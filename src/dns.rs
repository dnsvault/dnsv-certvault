use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use dns_update::{DnsRecord, DnsRecordType, DnsUpdater, TsigAlgorithm};

use crate::config::DnsConfig;

/// TXT record name in the challenge zone for an ACME identifier.
/// The real zone carries `_acme-challenge.<base> CNAME <this name>`.
pub fn challenge_txt_name(identifier: &str, zone: &str) -> String {
    let base = identifier.strip_prefix("*.").unwrap_or(identifier);
    format!("{base}.{zone}")
}

pub struct ChallengeDns {
    updater: DnsUpdater,
    /// Always the update server: authoritative truth that a write landed.
    master: crate::query::Querier,
    /// What the world sees — the resolver when configured, else the master.
    verify: crate::query::Querier,
    verify_is_resolver: bool,
    pub zone: String,
    ttl: u32,
    pub propagation_wait_secs: u64,
    signed: bool,
}

impl ChallengeDns {
    pub fn new(cfg: &DnsConfig) -> Result<Self> {
        // Queries go out unsigned either way; without a secret we build the
        // updater with a dummy key and refuse writes, so read-only commands
        // (doctor's CNAME checks) work before any credential exists.
        let (key, signed) = match cfg.tsig_secret.as_deref() {
            Some(secret) => (
                base64::engine::general_purpose::STANDARD
                    .decode(secret.trim())
                    .context("dns.tsig_secret is not valid base64")?,
                true,
            ),
            None => (vec![0u8; 32], false),
        };
        let server_sock = resolve_addr(&cfg.server_addr())?;
        let updater = DnsUpdater::new_rfc2136_tsig(
            format!("tcp://{server_sock}").as_str(),
            &cfg.tsig_key,
            key.clone(),
            parse_algorithm(&cfg.tsig_algorithm)?,
        )
        .map_err(|e| anyhow!("cannot create DNS updater: {e}"))?;

        // Verification queries: same server by default, signed by default —
        // multi-view servers route signed queries like the signed updates.
        // A custom resolver flips the signing default off (a public resolver
        // doesn't know the key).
        let master_key = if signed {
            Some((cfg.tsig_key.as_str(), key.clone(), cfg.tsig_algorithm.as_str()))
        } else {
            None
        };
        let master = crate::query::Querier::new(server_sock, master_key)?;

        let verify_is_resolver = cfg.resolver.is_some();
        let verify = match &cfg.resolver {
            Some(r) => {
                let sock = resolve_addr(&normalize_addr(r))?;
                let sign = cfg.sign_queries.unwrap_or(false);
                let k = if sign && signed {
                    Some((cfg.tsig_key.as_str(), key, cfg.tsig_algorithm.as_str()))
                } else {
                    None
                };
                crate::query::Querier::new(sock, k)?
            }
            None => {
                let sign = cfg.sign_queries.unwrap_or(true);
                let k = if sign && signed {
                    Some((cfg.tsig_key.as_str(), key, cfg.tsig_algorithm.as_str()))
                } else {
                    None
                };
                crate::query::Querier::new(server_sock, k)?
            }
        };

        Ok(Self {
            updater,
            master,
            verify,
            verify_is_resolver,
            zone: cfg.challenge_zone.clone(),
            ttl: cfg.ttl,
            propagation_wait_secs: cfg.propagation_wait_secs,
            signed,
        })
    }

    pub fn can_write(&self) -> bool {
        self.signed
    }

    fn require_secret(&self) -> Result<()> {
        if !self.signed {
            bail!("no TSIG secret configured — set dns.tsig_secret or DNSVCERT_TSIG_SECRET");
        }
        Ok(())
    }

    pub async fn add_txt(&self, name: &str, value: &str) -> Result<()> {
        self.require_secret()?;
        self.updater
            .add_to_rrset(
                name,
                DnsRecordType::TXT,
                self.ttl,
                vec![DnsRecord::TXT(value.to_string())],
                self.zone.as_str(),
            )
            .await
            .map_err(|e| anyhow!("TSIG update failed adding TXT {name}: {e}"))
    }

    /// Delete the whole TXT RRSet at `name`.
    pub async fn clear_txt(&self, name: &str) -> Result<()> {
        self.require_secret()?;
        self.updater
            .set_rrset(name, DnsRecordType::TXT, 0, vec![], self.zone.as_str())
            .await
            .map_err(|e| anyhow!("TSIG update failed clearing TXT {name}: {e}"))
    }

    /// TXT values as the update server itself answers them.
    pub async fn txt_values(&self, name: &str) -> Result<Vec<String>> {
        self.txt_values_via(&self.master, name).await
    }

    async fn txt_values_via(
        &self,
        q: &crate::query::Querier,
        name: &str,
    ) -> Result<Vec<String>> {
        use hickory_proto::rr::{RData, RecordType};
        let records = q
            .query(name, RecordType::TXT)
            .await
            .map_err(|e| anyhow!("TXT query for {name} failed: {e}"))?;
        Ok(records
            .into_iter()
            .filter_map(|r| match r {
                RData::TXT(t) => Some(
                    t.txt_data
                        .iter()
                        .map(|c| String::from_utf8_lossy(c).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }

    /// Query the verification path for a CNAME target, if any.
    /// ponytail: this asks one server — if the real zone lives elsewhere and
    /// that server won't recurse, set dns.resolver to something that will.
    pub async fn cname_target(&self, name: &str) -> Result<Option<String>> {
        use hickory_proto::rr::{RData, RecordType};
        let records = self
            .verify
            .query(name, RecordType::CNAME)
            .await
            .map_err(|e| anyhow!("CNAME query for {name} failed: {e}"))?;
        Ok(records.into_iter().find_map(|r| match r {
            RData::CNAME(target) => Some(target.0.to_utf8()),
            _ => None,
        }))
    }

    /// Write a probe TXT record, confirm it, and clean it up — proves the
    /// TSIG key + server + zone combination end to end.
    pub async fn probe(&self) -> Result<()> {
        let name = format!("_dnsvcert-probe.{}", self.zone);
        let value = format!("dnsvcert-probe-{}", std::process::id());
        self.add_txt(&name, &value).await?;
        let result = self.confirm_txt(&name, &value).await;
        self.clear_txt(&name).await?;
        result
    }

    /// Confirm the update server itself serves `value` — proof the write landed.
    /// BIND applies updates synchronously; the retries cover slow paths only.
    pub async fn confirm_txt(&self, name: &str, value: &str) -> Result<()> {
        for _ in 0..10 {
            if self.txt_values(name).await?.iter().any(|v| v == value) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        bail!(
            "TXT {name} was accepted but the update server does not serve it — \
             check that this server is authoritative for {}",
            self.zone
        );
    }

    /// Poll the configured resolver until it sees `value`. Advisory: Let's
    /// Encrypt resolves from its own servers, so a resolver that hasn't caught
    /// up does not mean validation will fail. Returns false on timeout.
    /// Only meaningful when a separate resolver is configured.
    pub async fn await_public_txt(&self, name: &str, value: &str, budget_secs: u64) -> bool {
        if !self.verify_is_resolver {
            return true;
        }
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(budget_secs.max(30));
        loop {
            if let Ok(vals) = self.txt_values_via(&self.verify, name).await {
                if vals.iter().any(|v| v == value) {
                    return true;
                }
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// Bare "host" or "host:port" → "tcp://host:port" (the form server_addr emits).
fn normalize_addr(raw: &str) -> String {
    let s = raw.trim();
    let with_proto = if s.contains("://") {
        s.to_string()
    } else {
        format!("tcp://{s}")
    };
    let after = with_proto.splitn(2, "://").nth(1).unwrap_or("");
    if after.contains(':') {
        with_proto
    } else {
        format!("{with_proto}:53")
    }
}

/// "proto://host:port" → SocketAddr, resolving hostnames (people configure
/// names; dns-update's parser only takes IPs).
fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr> {
    let rest = addr.splitn(2, "://").nth(1).unwrap_or(addr);
    let (host, port) = rest.rsplit_once(':').unwrap_or((rest, "53"));
    let port: u16 = port.parse().with_context(|| format!("bad port in '{addr}'"))?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    use std::net::ToSocketAddrs;
    format!("{host}:{port}")
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve hostname '{host}'"))?
        .next()
        .ok_or_else(|| anyhow!("'{host}' resolved to no addresses"))
}

fn parse_algorithm(s: &str) -> Result<TsigAlgorithm> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "hmac-sha1" => TsigAlgorithm::HmacSha1,
        "hmac-sha224" => TsigAlgorithm::HmacSha224,
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        other => bail!("unsupported tsig_algorithm '{other}' (use hmac-sha256, hmac-sha512, ...)"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_identifiers_to_challenge_zone_names() {
        assert_eq!(
            challenge_txt_name("app.example.com", "acme.example.com"),
            "app.example.com.acme.example.com"
        );
        // wildcard and its base share the same TXT name
        assert_eq!(
            challenge_txt_name("*.app.example.com", "acme.example.com"),
            challenge_txt_name("app.example.com", "acme.example.com"),
        );
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(parse_algorithm("hmac-md5").is_err());
        assert!(parse_algorithm("hmac-sha256").is_ok());
    }
}
