//! Verification-query client.
//!
//! Updates are always TSIG-signed, so on a multi-view DNSVault/BIND they
//! route to the view that knows the key. Plain queries route by SOURCE
//! ADDRESS — from inside the network they land in the internal view, which
//! may not carry the challenge zone at all. Two knobs fix this:
//! `dns.sign_queries` signs verification queries with the same key so they
//! follow the update's view routing, and `dns.resolver` points queries at a
//! different server entirely (e.g. a public resolver).

use std::net::SocketAddr;

use anyhow::{anyhow, bail, Result};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType, TSigner};

pub struct Querier {
    addr: SocketAddr,
    signer: Option<TSigner>,
}

impl Querier {
    pub fn new(addr: SocketAddr, key: Option<(&str, Vec<u8>, &str)>) -> Result<Self> {
        let signer = match key {
            Some((name, secret, algorithm)) => Some(
                TSigner::new(
                    secret,
                    hickory_algorithm(algorithm)?,
                    Name::from_ascii(name).map_err(|e| anyhow!("bad key name: {e}"))?,
                    300,
                )
                .map_err(|e| anyhow!("cannot build query signer: {e}"))?,
            ),
            None => None,
        };
        Ok(Self { addr, signer })
    }


    /// TCP query; returns the answer RDATA for records matching `rtype` at `name`.
    pub async fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<RData>> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };
        let owner =
            Name::from_str_relaxed(&fqdn).map_err(|e| anyhow!("bad name {name}: {e}"))?;

        let (stream_future, sender) =
            TcpClientStream::new(self.addr, None, None, TokioRuntimeProvider::new());
        let stream = stream_future
            .await
            .map_err(|e| anyhow!("cannot connect to {}: {e}", self.addr))?;
        let mut multiplexer = DnsMultiplexer::new(stream, sender);
        if let Some(signer) = &self.signer {
            multiplexer = multiplexer.with_signer(signer.clone());
        }
        let (mut client, bg): (Client<TokioRuntimeProvider>, _) =
            Client::from_sender(multiplexer);
        tokio::spawn(bg);

        let response = client
            .query(owner.clone(), DNSClass::IN, rtype)
            .await
            .map_err(|e| anyhow!("query to {} failed: {e}", self.addr))?;
        if response.response_code != ResponseCode::NoError
            && response.response_code != ResponseCode::NXDomain
        {
            bail!("server {} answered {}", self.addr, response.response_code);
        }
        Ok(response
            .answers
            .iter()
            .filter(|r| r.record_type() == rtype && r.name == owner)
            .map(|r| r.data.clone())
            .collect())
    }
}

fn hickory_algorithm(s: &str) -> Result<TsigAlgorithm> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "hmac-sha1" => TsigAlgorithm::HmacSha1,
        "hmac-sha224" => TsigAlgorithm::HmacSha224,
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        other => bail!("unsupported tsig_algorithm '{other}'"),
    })
}
