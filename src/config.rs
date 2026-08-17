use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub acme: AcmeConfig,
    pub dns: DnsConfig,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    #[serde(default)]
    pub certificates: Vec<CertConfig>,
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default = "default_directory")]
    pub directory: String,
    pub email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// DNS master that accepts the TSIG-signed updates.
    /// "203.0.113.10", "203.0.113.10:5353" or "tcp://203.0.113.10:53".
    pub server: String,
    /// The delegated challenge zone, e.g. "acme.example.com".
    pub challenge_zone: String,
    pub tsig_key: String,
    /// Base64 TSIG secret. May be omitted when DNSVCERT_TSIG_SECRET is set.
    #[serde(default)]
    pub tsig_secret: Option<String>,
    #[serde(default = "default_tsig_algorithm")]
    pub tsig_algorithm: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Seconds to wait after writing TXT records before telling the CA to
    /// validate — covers NOTIFY lag to the challenge zone's secondaries.
    #[serde(default = "default_propagation_wait_secs")]
    pub propagation_wait_secs: u64,
    /// Where verification queries (TXT confirm, doctor's CNAME checks) go.
    /// Defaults to `server`. Point it elsewhere when the update server's view
    /// routing would answer your queries from the wrong view.
    #[serde(default)]
    pub resolver: Option<String>,
    /// Sign verification queries with the TSIG key so multi-view servers
    /// route them like the updates. Default: true when `resolver` is unset,
    /// false when a custom resolver is configured.
    #[serde(default)]
    pub sign_queries: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertConfig {
    pub domains: Vec<String>,
    pub output_dir: String,
    #[serde(default)]
    pub reload_hook: Option<String>,
}

fn default_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".into()
}
fn default_state_dir() -> String {
    "/var/lib/dnsvcert".into()
}
fn default_tsig_algorithm() -> String {
    "hmac-sha256".into()
}
fn default_ttl() -> u32 {
    60
}
fn default_propagation_wait_secs() -> u64 {
    10
}
fn default_renew_before_days() -> i64 {
    30
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {path}"))?;
        let mut cfg: Config =
            serde_yaml::from_str(&raw).with_context(|| format!("invalid config in {path}"))?;
        if let Ok(secret) = std::env::var("DNSVCERT_TSIG_SECRET") {
            cfg.dns.tsig_secret = Some(secret);
        }
        if matches!(cfg.dns.tsig_secret.as_deref(), Some("") | Some("CHANGE_ME")) {
            cfg.dns.tsig_secret = None;
        }
        // A missing secret is allowed here: read-only commands (doctor's CNAME
        // checks) work unsigned. Writes fail with a pointed error instead.
        Ok(cfg)
    }
}

impl DnsConfig {
    /// Normalize `server` to the "proto://host:port" form dns-update expects.
    pub fn server_addr(&self) -> String {
        let s = self.server.trim();
        let with_proto = if s.contains("://") {
            s.to_string()
        } else {
            format!("tcp://{s}")
        };
        // has a port already? (count ':' after the scheme; bare IPv6 unsupported)
        let after_scheme = with_proto.splitn(2, "://").nth(1).unwrap_or("");
        if after_scheme.contains(':') {
            with_proto
        } else {
            format!("{with_proto}:53")
        }
    }
}

/// Render a config file. Used by `init` (placeholders) and `setup` (real values).
#[allow(clippy::too_many_arguments)]
pub fn render_template(
    email: &str,
    server: &str,
    zone: &str,
    key: &str,
    secret: Option<&str>,
    domains: &[String],
    output_dir: &str,
    state_dir: &str,
    reload_hook: Option<&str>,
    resolver: Option<&str>,
) -> String {
    let domains_line = if domains.is_empty() {
        r#""app.example.com", "*.app.example.com""#.to_string()
    } else {
        domains
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let hook_line = match reload_hook {
        Some(h) if !h.is_empty() => format!("    reload_hook: \"{h}\"\n"),
        _ => "    # reload_hook: \"systemctl reload nginx\"\n".to_string(),
    };
    let resolver_block = match resolver {
        Some(r) => format!(
            "  # Verification queries go here (what Let's Encrypt sees); query signing is off.\n  resolver: {r}"
        ),
        None => "  # Verification queries are TSIG-signed to the server above so multi-view\n  # servers route them like the updates. To verify via a resolver instead:\n  # resolver: 8.8.8.8\n  # sign_queries: false".to_string(),
    };
    format!(
        r#"acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  email: {email}

state_dir: {state_dir}

dns:
  # The three values below come with your DNSVault subscription.
  server: {server}
  challenge_zone: {zone}
  tsig_key: {key}
  # Base64 secret; alternatively set the DNSVCERT_TSIG_SECRET environment variable.
  tsig_secret: "{secret}"
{resolver_block}

renew_before_days: 30

certificates:
  - domains: [{domains_line}]
    output_dir: {output_dir}
{hook_line}"#,
        secret = secret.unwrap_or("CHANGE_ME"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config_with_defaults() {
        let cfg: Config = serde_yaml::from_str(
            r#"
acme:
  email: admin@example.com
dns:
  server: 203.0.113.10
  challenge_zone: acme.example.com
  tsig_key: acme-key
  tsig_secret: "c2VjcmV0"
certificates:
  - domains: ["app.example.com", "*.app.example.com"]
    output_dir: /tmp/certs
"#,
        )
        .unwrap();
        assert!(cfg.acme.directory.contains("letsencrypt.org"));
        assert_eq!(cfg.dns.server_addr(), "tcp://203.0.113.10:53");
        assert_eq!(cfg.dns.ttl, 60);
        assert_eq!(cfg.renew_before_days, 30);
        assert_eq!(cfg.certificates[0].domains.len(), 2);
    }

    #[test]
    fn server_addr_keeps_explicit_proto_and_port() {
        let mk = |s: &str| DnsConfig {
            server: s.into(),
            challenge_zone: "z".into(),
            tsig_key: "k".into(),
            tsig_secret: None,
            tsig_algorithm: default_tsig_algorithm(),
            ttl: 60,
            propagation_wait_secs: 1,
            resolver: None,
            sign_queries: None,
        };
        assert_eq!(mk("udp://1.2.3.4:5353").server_addr(), "udp://1.2.3.4:5353");
        assert_eq!(mk("1.2.3.4:5353").server_addr(), "tcp://1.2.3.4:5353");
        assert_eq!(mk("1.2.3.4").server_addr(), "tcp://1.2.3.4:53");
    }
}
