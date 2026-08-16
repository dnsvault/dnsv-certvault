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
        let updater = DnsUpdater::new_rfc2136_tsig(
            cfg.server_addr().as_str(),
            &cfg.tsig_key,
            key,
            parse_algorithm(&cfg.tsig_algorithm)?,
        )
        .map_err(|e| anyhow!("cannot create DNS updater: {e}"))?;
        Ok(Self {
            updater,
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

    /// Query the configured master for the TXT values at `name`.
    pub async fn txt_values(&self, name: &str) -> Result<Vec<String>> {
        let records = self
            .updater
            .list_rrset(name, DnsRecordType::TXT, self.zone.as_str())
            .await
            .map_err(|e| anyhow!("TXT query for {name} failed: {e}"))?;
        Ok(records
            .into_iter()
            .filter_map(|r| match r {
                DnsRecord::TXT(v) => Some(v),
                _ => None,
            })
            .collect())
    }

    /// Query the configured master for a CNAME target, if any.
    /// ponytail: doctor asks the master only — if the real zone lives on
    /// other servers this reports "missing" even when the CNAME exists.
    pub async fn cname_target(&self, name: &str) -> Result<Option<String>> {
        let records = self
            .updater
            .list_rrset(name, DnsRecordType::CNAME, self.zone.as_str())
            .await
            .map_err(|e| anyhow!("CNAME query for {name} failed: {e}"))?;
        Ok(records.into_iter().find_map(|r| match r {
            DnsRecord::CNAME(target) => Some(target),
            _ => None,
        }))
    }

    /// Confirm the master serves `value` in TXT at `name` (update is applied
    /// synchronously by BIND; a few retries cover slow paths).
    pub async fn confirm_txt(&self, name: &str, value: &str) -> Result<()> {
        for _ in 0..10 {
            if self.txt_values(name).await?.iter().any(|v| v == value) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        bail!("TXT {name} not visible on master after update — check the challenge zone setup");
    }
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
