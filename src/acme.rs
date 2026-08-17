use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};

use crate::config::{CertConfig, Config};
use crate::dns::{challenge_txt_name, ChallengeDns};

pub async fn load_or_create_account(cfg: &Config) -> Result<Account> {
    let path = account_path(cfg);
    if path.exists() {
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let credentials: AccountCredentials =
            serde_json::from_str(&json).with_context(|| format!("bad {}", path.display()))?;
        return Account::builder()?
            .from_credentials(credentials)
            .await
            .context("cannot restore ACME account from stored credentials");
    }

    let contact = format!("mailto:{}", cfg.acme.email);
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            cfg.acme.directory.clone(),
            None,
        )
        .await
        .context("cannot create ACME account")?;

    std::fs::create_dir_all(&cfg.state_dir)
        .with_context(|| format!("cannot create state_dir {}", cfg.state_dir))?;
    write_file(&path, serde_json::to_string(&credentials)?.as_bytes(), 0o600)?;
    println!("created ACME account, credentials stored in {}", path.display());
    Ok(account)
}

fn account_path(cfg: &Config) -> PathBuf {
    let tag: String = cfg
        .acme
        .directory
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    Path::new(&cfg.state_dir).join(format!("account-{tag}.json"))
}

/// Days until the leaf certificate in `fullchain.pem` expires.
/// None when the file does not exist yet.
pub fn days_until_expiry(output_dir: &str) -> Result<Option<i64>> {
    let path = Path::new(output_dir).join("fullchain.pem");
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data)
        .map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", path.display()))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", path.display()))?;
    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    Ok(Some((not_after - now) / 86400))
}

/// Order, validate via DNS-01 through the challenge zone, and write
/// privkey.pem + fullchain.pem into the cert's output_dir.
pub async fn issue(account: &Account, cert: &CertConfig, dns: &ChallengeDns) -> Result<()> {
    let identifiers: Vec<Identifier> = cert
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("cannot create ACME order")?;

    let mut txt_names: Vec<String> = Vec::new();
    let result = run_order(&mut order, dns, &mut txt_names).await;

    // best-effort cleanup of every TXT we created, success or failure
    txt_names.sort();
    txt_names.dedup();
    for name in &txt_names {
        if let Err(e) = dns.clear_txt(name).await {
            eprintln!("warning: could not clean up TXT {name}: {e}");
        }
    }

    let (key_pem, chain_pem) = result?;
    let dir = Path::new(&cert.output_dir);
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create output_dir {}", cert.output_dir))?;
    write_file(&dir.join("privkey.pem"), key_pem.as_bytes(), 0o600)?;
    write_file(&dir.join("fullchain.pem"), chain_pem.as_bytes(), 0o644)?;
    println!(
        "issued certificate for [{}] into {}",
        cert.domains.join(", "),
        cert.output_dir
    );
    Ok(())
}

async fn run_order(
    order: &mut instant_acme::Order,
    dns: &ChallengeDns,
    txt_names: &mut Vec<String>,
) -> Result<(String, String)> {
    let mut pending: Vec<(String, String)> = Vec::new();
    // Pass 1: write every TXT record and confirm the master serves them.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => bail!("unexpected authorization status: {status:?}"),
            }
            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .context("server offered no dns-01 challenge")?;
            let name = challenge_txt_name(&challenge.identifier().to_string(), &dns.zone);
            let value = challenge.key_authorization().dns_value();
            dns.add_txt(&name, &value).await?;
            txt_names.push(name.clone());
            dns.confirm_txt(&name, &value).await?;
            println!("TXT {name} in place");
            pending.push((name, value));
        }
    }

    // One wait for the challenge zone's secondaries to catch up via NOTIFY.
    if !txt_names.is_empty() && dns.propagation_wait_secs > 0 {
        println!("waiting {}s for propagation", dns.propagation_wait_secs);
        tokio::time::sleep(std::time::Duration::from_secs(dns.propagation_wait_secs)).await;
    }

    // With a resolver configured, give it a chance to show the record too.
    // Advisory only: the CA resolves from its own servers, and a resolver that
    // cached "no such record" before the write will lag by its negative TTL.
    for (name, value) in &pending {
        if !dns
            .await_public_txt(name, value, dns.propagation_wait_secs.max(60))
            .await
        {
            println!(
                "note: {name} is not visible via your configured resolver yet \
                 (negative caching); proceeding — the CA queries the authoritative \
                 servers itself. Lower the challenge zone's SOA minimum (60s) if this \
                 keeps happening."
            );
        }
    }

    // Pass 2: tell the CA every challenge is ready.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if authz.status != AuthorizationStatus::Pending {
                continue;
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .context("server offered no dns-01 challenge")?;
            challenge.set_ready().await?;
        }
    }

    // Production Let's Encrypt validates from multiple network perspectives
    // and can take well over a minute; the default policy gives up too early.
    let patient = RetryPolicy::default()
        .initial_delay(std::time::Duration::from_secs(1))
        .backoff(1.5)
        .timeout(std::time::Duration::from_secs(300));
    let status = order.poll_ready(&patient).await?;
    if status != OrderStatus::Ready {
        bail!("order failed validation, status: {status:?}");
    }
    let key_pem = order.finalize().await.context("finalize failed")?;
    let chain_pem = order
        .poll_certificate(&patient)
        .await
        .context("certificate download failed")?;
    Ok((key_pem, chain_pem))
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("cannot write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode; // Windows: NTFS ACLs inherit from the directory; no chmod analogue
    std::fs::rename(&tmp, path).with_context(|| format!("cannot move into {}", path.display()))?;
    Ok(())
}
