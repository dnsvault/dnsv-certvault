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


    async fn connect(&self) -> Result<Client<TokioRuntimeProvider>> {
        let (stream_future, sender) =
            TcpClientStream::new(self.addr, None, None, TokioRuntimeProvider::new());
        let stream = stream_future
            .await
            .map_err(|e| anyhow!("cannot connect to {}: {e}", self.addr))?;
        let mut multiplexer = DnsMultiplexer::new(stream, sender);
        if let Some(signer) = &self.signer {
            multiplexer = multiplexer.with_signer(signer.clone());
        }
        let (client, bg): (Client<TokioRuntimeProvider>, _) = Client::from_sender(multiplexer);
        tokio::spawn(bg);
        Ok(client)
    }

    /// TCP query; returns the answer RDATA for records matching `rtype` at `name`.
    /// NOTE: plain queries are never TSIG-signed (hickory signs only
    /// UPDATE/NOTIFY/AXFR), so on a multi-view server this is routed by
    /// source address. Use `txt_exists` when the view must follow the key.
    pub async fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<RData>> {
        let owner = Name::from_str_relaxed(fqdn(name).as_str())
            .map_err(|e| anyhow!("bad name {name}: {e}"))?;
        let mut client = self.connect().await?;

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

impl Querier {
    /// Ask the server whether `value` exists in the TXT RRset at `name`,
    /// using an RFC 2136 prerequisite-only UPDATE (empty update section, so
    /// nothing is written).
    ///
    /// Why not a plain query: hickory signs UPDATE/NOTIFY/AXFR but never
    /// plain queries (`TSigner::should_sign_message`), and a multi-view
    /// server routes UNSIGNED queries by source address — from inside the
    /// network that is the wrong view. An UPDATE is signed by definition, so
    /// this read lands in the same view as the writes.
    ///
    /// NOERROR = present, NXRRSET = absent.
    pub async fn txt_exists(&self, zone: &str, name: &str, value: &str) -> Result<bool> {
        use hickory_proto::op::update_message::UpdateMessage;
        use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, OpCode, Query};
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{DNSClass, RData, Record, RecordType};

        if self.signer.is_none() {
            bail!("prerequisite check needs a TSIG key");
        }
        let zone_name = Name::from_str_relaxed(fqdn(zone).as_str())
            .map_err(|e| anyhow!("bad zone {zone}: {e}"))?;
        let owner = Name::from_str_relaxed(fqdn(name).as_str())
            .map_err(|e| anyhow!("bad name {name}: {e}"))?;

        let mut zq = Query::new();
        zq.set_name(zone_name)
            .set_query_class(DNSClass::IN)
            .set_query_type(RecordType::SOA);

        let mut message = Message::query();
        message.metadata.op_code = OpCode::Update;
        message.metadata.recursion_desired = false;
        message.add_zone(zq);
        // "RRset exists (value dependent)": class = zone class, ttl 0, rdata present.
        let mut prereq = Record::from_rdata(owner, 0, RData::TXT(TXT::new(vec![value.to_string()])));
        prereq.dns_class = DNSClass::IN;
        message.add_pre_requisite(prereq);

        let client = self.connect().await?;
        let response = {
            use futures_util::StreamExt;
            use hickory_net::xfer::DnsHandle;
            let mut stream = client.send(DnsRequest::new(message, DnsRequestOptions::default()));
            stream
                .next()
                .await
                .ok_or_else(|| anyhow!("no response from {}", self.addr))?
                .map_err(|e| anyhow!("prerequisite check to {} failed: {e}", self.addr))?
        };
        match response.response_code {
            ResponseCode::NoError => Ok(true),
            ResponseCode::NXRRSet | ResponseCode::NXDomain => Ok(false),
            other => bail!("server {} answered {} to the prerequisite check", self.addr, other),
        }
    }
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
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
