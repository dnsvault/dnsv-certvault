mod acme;
mod config;
mod dns;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use config::Config;
use dns::{challenge_txt_name, ChallengeDns};

#[derive(Parser)]
#[command(
    name = "dnsvcert",
    version,
    about = "DNSVault ACME DNS-01 client — Let's Encrypt certificates through a delegated challenge zone"
)]
struct Cli {
    /// Path to the YAML config file
    #[arg(short, long, default_value = "/etc/dnsvcert/dnsvcert.yml")]
    config: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a starter config file, then print the DNS records to add
    Init(InitArgs),
    /// Issue (or re-issue) every certificate in the config
    Issue,
    /// Issue only certificates missing or expiring within renew_before_days
    Renew,
    /// Check CNAME delegation and TSIG write access, then exit
    Doctor,
    /// Certbot manual-hook mode (reads CERTBOT_DOMAIN / CERTBOT_VALIDATION)
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(clap::Args)]
struct InitArgs {
    /// Domain to request a certificate for (repeatable; add its wildcard too if wanted)
    #[arg(long = "domain")]
    domains: Vec<String>,
    /// Contact email for the ACME account
    #[arg(long)]
    email: Option<String>,
    /// DNS server that accepts the TSIG-signed updates (from DNSVault)
    #[arg(long)]
    server: Option<String>,
    /// Delegated challenge zone (from DNSVault)
    #[arg(long)]
    challenge_zone: Option<String>,
    /// TSIG key name (from DNSVault)
    #[arg(long)]
    tsig_key: Option<String>,
    /// Where certificate files are written
    #[arg(long)]
    output_dir: Option<String>,
}

#[derive(Subcommand)]
enum HookAction {
    /// --manual-auth-hook: add the validation TXT record
    Auth,
    /// --manual-cleanup-hook: remove the validation TXT record
    Cleanup,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Init(args) = &cli.command {
        return run_init(&cli.config, args);
    }
    let cfg = Config::load(&cli.config)?;
    match cli.command {
        Command::Init(_) => unreachable!(),
        Command::Issue => run_certs(&cfg, false).await,
        Command::Renew => run_certs(&cfg, true).await,
        Command::Doctor => run_doctor(&cfg).await,
        Command::Hook { action } => run_hook(&cfg, action).await,
    }
}

fn run_init(config_path: &str, args: &InitArgs) -> Result<()> {
    let path = std::path::Path::new(config_path);
    if path.exists() {
        bail!("{config_path} already exists — edit it directly or pass a different -c path");
    }
    let or = |v: &Option<String>, ph: &str| v.clone().unwrap_or_else(|| ph.to_string());
    let domains = if args.domains.is_empty() {
        r#""app.example.com", "*.app.example.com""#.to_string()
    } else {
        args.domains
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let contents = format!(
        r#"acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  email: {email}

state_dir: /var/lib/dnsvcert

dns:
  # The three values below come with your DNSVault subscription.
  server: {server}
  challenge_zone: {zone}
  tsig_key: {key}
  # Base64 secret; alternatively set the DNSVCERT_TSIG_SECRET environment variable.
  tsig_secret: "CHANGE_ME"

renew_before_days: 30

certificates:
  - domains: [{domains}]
    output_dir: {out}
    # reload_hook: "systemctl reload nginx"
"#,
        email = or(&args.email, "you@example.com"),
        server = or(&args.server, "ns1.example-dnsvault.net"),
        zone = or(&args.challenge_zone, "acme.example.com"),
        key = or(&args.tsig_key, "dnsvcert-key"),
        out = or(&args.output_dir, "/etc/ssl/dnsvcert"),
    );
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("cannot write {config_path}"))?;
    println!("wrote {config_path}");
    println!();
    println!("Next steps:");
    println!("  1. Fill in the CHANGE_ME / example values in {config_path}");
    if let Some(zone) = &args.challenge_zone {
        let mut bases: Vec<&str> = args
            .domains
            .iter()
            .map(|d| d.strip_prefix("*.").unwrap_or(d))
            .collect();
        bases.sort();
        bases.dedup();
        if bases.is_empty() {
            println!("  2. Add: _acme-challenge.<name>  CNAME  <name>.{zone}.");
        } else {
            println!("  2. Add in the DNS that hosts your domain(s):");
            for base in bases {
                println!("       _acme-challenge.{base}  CNAME  {base}.{zone}.");
            }
        }
    } else {
        println!("  2. Add: _acme-challenge.<name>  CNAME  <name>.<challenge_zone>.");
    }
    println!("  3. Run: dnsvcert -c {config_path} doctor");
    Ok(())
}

async fn run_certs(cfg: &Config, renew_only: bool) -> Result<()> {
    if cfg.certificates.is_empty() {
        bail!("no certificates configured");
    }
    let dns = ChallengeDns::new(&cfg.dns)?;
    if !dns.can_write() {
        bail!("no TSIG secret configured — set dns.tsig_secret or DNSVCERT_TSIG_SECRET");
    }
    let account = acme::load_or_create_account(cfg).await?;

    let mut failures = 0;
    for cert in &cfg.certificates {
        if renew_only {
            match acme::days_until_expiry(&cert.output_dir) {
                Ok(Some(days)) if days > cfg.renew_before_days => {
                    println!(
                        "skip [{}]: {days} days left (renews at {})",
                        cert.domains.join(", "),
                        cfg.renew_before_days
                    );
                    continue;
                }
                Ok(_) => {}
                Err(e) => eprintln!("warning: cannot read existing cert, re-issuing: {e}"),
            }
        }
        if let Err(e) = acme::issue(&account, cert, &dns).await {
            eprintln!("FAILED [{}]: {e:#}", cert.domains.join(", "));
            failures += 1;
            continue;
        }
        if let Some(hook) = &cert.reload_hook {
            #[cfg(unix)]
            let mut cmd = {
                let mut c = std::process::Command::new("sh");
                c.arg("-c").arg(hook);
                c
            };
            #[cfg(windows)]
            let mut cmd = {
                let mut c = std::process::Command::new("cmd");
                c.arg("/C").arg(hook);
                c
            };
            match cmd.status() {
                Ok(s) if s.success() => println!("reload hook ok: {hook}"),
                Ok(s) => {
                    eprintln!("reload hook exited {s}: {hook}");
                    failures += 1;
                }
                Err(e) => {
                    eprintln!("reload hook failed to start: {e}");
                    failures += 1;
                }
            }
        }
    }
    if failures > 0 {
        bail!("{failures} certificate(s) failed");
    }
    Ok(())
}

async fn run_doctor(cfg: &Config) -> Result<()> {
    let dns = ChallengeDns::new(&cfg.dns)?;
    let mut failed = false;

    // TSIG write probe inside the challenge zone
    if dns.can_write() {
        let probe_name = format!("_dnsvcert-probe.{}", dns.zone);
        let probe_value = format!("dnsvcert-probe-{}", std::process::id());
        match probe_tsig(&dns, &probe_name, &probe_value).await {
            Ok(()) => println!("PASS  TSIG write access to {}", dns.zone),
            Err(e) => {
                println!("FAIL  TSIG write access to {}: {e:#}", dns.zone);
                failed = true;
            }
        }
    } else {
        println!("SKIP  TSIG write probe — no tsig_secret set (CNAME checks still run)");
    }

    // CNAME delegation per unique base name (a wildcard shares its base's CNAME)
    let mut checked: Vec<String> = Vec::new();
    for cert in &cfg.certificates {
        for domain in &cert.domains {
            let base = domain.strip_prefix("*.").unwrap_or(domain);
            if checked.iter().any(|c| c == base) {
                continue;
            }
            checked.push(base.to_string());
            let expected = challenge_txt_name(domain, &dns.zone);
            let cname_name = format!("_acme-challenge.{base}");
            match dns.cname_target(&cname_name).await {
                Ok(Some(target)) if normalize(&target) == normalize(&expected) => {
                    println!("PASS  {cname_name} -> {expected}");
                }
                Ok(Some(target)) => {
                    println!("FAIL  {cname_name} points at {target}, expected {expected}");
                    failed = true;
                }
                Ok(None) => {
                    println!("FAIL  {cname_name} has no CNAME — add: {cname_name} CNAME {expected}.");
                    failed = true;
                }
                Err(e) => {
                    println!("FAIL  {cname_name}: {e:#}");
                    failed = true;
                }
            }
        }
    }

    if failed {
        bail!("doctor found problems");
    }
    println!("all checks passed");
    Ok(())
}

async fn probe_tsig(dns: &ChallengeDns, name: &str, value: &str) -> Result<()> {
    dns.add_txt(name, value).await?;
    let result = dns.confirm_txt(name, value).await;
    dns.clear_txt(name).await?;
    result
}

async fn run_hook(cfg: &Config, action: HookAction) -> Result<()> {
    let domain = std::env::var("CERTBOT_DOMAIN")
        .context("CERTBOT_DOMAIN not set — hook mode is for certbot --manual-auth-hook")?;
    let dns = ChallengeDns::new(&cfg.dns)?;
    let name = challenge_txt_name(&domain, &dns.zone);
    match action {
        HookAction::Auth => {
            let value = std::env::var("CERTBOT_VALIDATION").context("CERTBOT_VALIDATION not set")?;
            dns.add_txt(&name, &value).await?;
            dns.confirm_txt(&name, &value).await?;
            tokio::time::sleep(std::time::Duration::from_secs(dns.propagation_wait_secs)).await;
        }
        HookAction::Cleanup => dns.clear_txt(&name).await?,
    }
    Ok(())
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}
