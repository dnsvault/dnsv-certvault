//! `dnsvcert setup` — guided, interactive first-run: asks for every value,
//! writes the config, live-checks DNS in a fix-and-retry loop, then offers
//! to issue. For people without an AI agent (or a DNS background).

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::{render_template, Config};
use crate::dns::{challenge_txt_name, ChallengeDns};

pub async fn run(config_path: &str) -> Result<()> {
    println!("dnsvcert guided setup");
    println!("=====================");
    println!("Three steps: 1) your details  2) DNS checks  3) issue the certificate.");
    println!("Nothing is requested from Let's Encrypt until step 3.\n");

    let path = Path::new(config_path);
    if path.exists() {
        if confirm(&format!("Found {config_path} — use it as-is?"), true) {
            let cfg = Config::load(config_path)?;
            return check_and_issue(config_path, &cfg).await;
        }
        if !confirm("Overwrite it with new answers?", false) {
            println!("Keeping the existing file. Edit it directly, then run: dnsvcert doctor");
            return Ok(());
        }
    }

    // ---- Step 1: collect values -------------------------------------------
    println!("Step 1/3 — your details");
    println!("(press Enter to accept a [default])\n");

    let email = ask_validated("Contact email for Let's Encrypt", None, |v| {
        v.contains('@') && v.contains('.')
    });

    println!("\nThe next three values come from DNSVault (your subscription or your admin):");
    let server = ask("DNS server that accepts the updates (name or IP)", None);
    let zone = ask("Challenge zone (e.g. acme.example.com)", None);
    let key = ask("TSIG key name", Some("dnsvcert"));
    let secret = ask_secret(
        "TSIG secret (input hidden; Enter to skip for now — DNS checks still run)",
    );
    if secret.is_none() {
        println!("  no secret yet — you can add it to the config later as dns.tsig_secret");
    }

    println!();
    let mut domains: Vec<String> = Vec::new();
    loop {
        let d = ask(
            if domains.is_empty() {
                "Domain to get a certificate for (e.g. app.example.com)"
            } else {
                "Another domain (Enter to stop)"
            },
            if domains.is_empty() { None } else { Some("") },
        );
        if d.is_empty() {
            break;
        }
        let base = d.strip_prefix("*.").unwrap_or(&d).to_string();
        if !domains.contains(&base) {
            domains.push(base.clone());
        }
        let wild = format!("*.{base}");
        if !domains.contains(&wild) && confirm(&format!("Include the wildcard {wild} too?"), true) {
            domains.push(wild);
        }
        if !confirm("Add another domain?", false) {
            break;
        }
    }

    println!();
    println!("How should dnsvcert verify its DNS records?");
    println!("  1. Ask the DNSVault server directly (signed) — works everywhere,");
    println!("     including locked-down networks where DNS must go through DNSVault");
    println!("  2. Ask a resolver — checks exactly what Let's Encrypt will see");
    let resolver = loop {
        match ask("Choose 1 or 2", Some("1")).as_str() {
            "1" => break None,
            "2" => {
                let r = ask("Resolver address", Some("8.8.8.8"));
                if confirm(
                    "Is your DNS split-horizon / multi-view (internal answers differ from public)?",
                    false,
                ) {
                    let internal_ip = r.starts_with("10.")
                        || r.starts_with("192.168.")
                        || r.starts_with("172.");
                    if internal_ip {
                        println!("  NOTE: {r} looks like an internal resolver — on a split-horizon");
                        println!("  network it may answer from the internal view, which is not what");
                        println!("  Let's Encrypt sees. A public resolver (8.8.8.8) or option 1 is safer.");
                        if !confirm(&format!("Keep {r} anyway?"), false) {
                            continue;
                        }
                    }
                    println!("  tip: keep the challenge zone's TTLs and SOA minimum low (60s)");
                    println!("  so resolver caches don't stall verification.");
                }
                break Some(r);
            }
            _ => println!("  1 or 2, please"),
        }
    };

    let first_base = domains
        .first()
        .map(|d| d.strip_prefix("*.").unwrap_or(d).to_string())
        .unwrap_or_else(|| "certs".into());
    let output_dir = ask("Directory for the certificate files", Some(&format!("./certs/{first_base}")));
    let hook = ask(
        "Command to run after issue/renew (e.g. systemctl reload nginx; Enter for none)",
        Some(""),
    );

    // ---- write config ------------------------------------------------------
    let contents = render_template(
        &email,
        &server,
        &zone,
        &key,
        secret.as_deref(),
        &domains,
        &output_dir,
        &default_state_dir(),
        Some(hook.as_str()).filter(|h| !h.is_empty()),
        resolver.as_deref(),
    );
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("cannot write {config_path}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("\nwrote {config_path} (owner-only permissions)");

    let cfg = Config::load(config_path)?;
    check_and_issue(config_path, &cfg).await
}

async fn check_and_issue(config_path: &str, cfg: &Config) -> Result<()> {
    // ---- Step 2: live DNS checks, fix-and-retry ---------------------------
    println!("\nStep 2/3 — checking your DNS setup");
    let dns = ChallengeDns::new(&cfg.dns)?;

    if dns.can_write() {
        loop {
            match dns.probe().await {
                Ok(()) => {
                    println!("PASS  write access to {} confirmed", dns.zone);
                    break;
                }
                Err(e) => {
                    println!("FAIL  cannot write to {}: {e:#}", dns.zone);
                    println!("      check dns.server / tsig_key / tsig_secret in {config_path}");
                    if !confirm("Fixed something? Check again?", true) {
                        println!("Stopping here. Re-run `dnsvcert setup` when ready.");
                        return Ok(());
                    }
                }
            }
        }
    } else {
        println!("SKIP  write check — no TSIG secret set yet");
    }

    let mut bases: Vec<String> = cfg
        .certificates
        .iter()
        .flat_map(|c| c.domains.iter())
        .map(|d| d.strip_prefix("*.").unwrap_or(d).to_string())
        .collect();
    bases.sort();
    bases.dedup();

    for base in &bases {
        let expected = challenge_txt_name(base, &dns.zone);
        let cname = format!("_acme-challenge.{base}");
        loop {
            match dns.cname_target(&cname).await {
                Ok(Some(t)) if normalize(&t) == normalize(&expected) => {
                    println!("PASS  {cname} -> {expected}");
                    break;
                }
                other => {
                    match other {
                        Ok(Some(t)) => println!("FAIL  {cname} points at {t}, expected {expected}"),
                        _ => println!("MISSING  {cname} has no CNAME yet"),
                    }
                    println!("      Add this record in the DNS that hosts {base}:");
                    println!("        {cname}  CNAME  {expected}.");
                    if !confirm("Added it? Check again? (DNS changes can take a minute)", true) {
                        println!("Stopping here. Re-run `dnsvcert setup` once the record exists.");
                        return Ok(());
                    }
                }
            }
        }
    }

    if !dns.can_write() {
        println!("\nDNS records are in place. Add your TSIG secret to {config_path}");
        println!("(dns.tsig_secret), then run `dnsvcert setup` again to issue.");
        return Ok(());
    }

    // ---- Step 3: issue ----------------------------------------------------
    println!("\nStep 3/3 — issue the certificate");
    if !confirm("Request the certificate from Let's Encrypt now?", true) {
        println!("Setup complete. Issue any time with: dnsvcert -c {config_path} issue");
        return Ok(());
    }
    match crate::run_certs(cfg, false).await {
        Ok(()) => {
            println!("\nDone. Renewal is automatic once you schedule it, e.g. cron:");
            println!("  17 3 * * *  root  dnsvcert -c {config_path} renew");
            Ok(())
        }
        Err(e) => {
            println!("\nIssuance failed: {e:#}");
            println!("Fix the cause and run: dnsvcert -c {config_path} issue");
            Ok(())
        }
    }
}

fn default_state_dir() -> String {
    #[cfg(unix)]
    let home = std::env::var("HOME").unwrap_or_else(|_| "/var/lib".into());
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\ProgramData".into());
    format!("{home}/.local/state/dnsvcert")
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

// ---- tiny prompt helpers (stdlib only; non-TTY reads plain lines so the
// wizard stays scriptable) --------------------------------------------------

fn ask(prompt: &str, default: Option<&str>) -> String {
    loop {
        match default {
            Some("") => print!("{prompt}: "),
            Some(d) => print!("{prompt} [{d}]: "),
            None => print!("{prompt}: "),
        }
        let _ = io::stdout().flush();
        let mut s = String::new();
        if io::stdin().read_line(&mut s).is_err() {
            return default.unwrap_or("").to_string();
        }
        let s = s.trim().to_string();
        if s.is_empty() {
            match default {
                Some(d) => return d.to_string(),
                None => {
                    println!("  (required)");
                    continue;
                }
            }
        }
        return s;
    }
}

fn ask_validated(prompt: &str, default: Option<&str>, ok: impl Fn(&str) -> bool) -> String {
    loop {
        let v = ask(prompt, default);
        if ok(&v) {
            return v;
        }
        println!("  that doesn't look right — try again");
    }
}

fn ask_secret(prompt: &str) -> Option<String> {
    let value = if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{prompt}: ")).unwrap_or_default()
    } else {
        ask(prompt, Some(""))
    };
    let value = value.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn confirm(prompt: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    let v = ask(&format!("{prompt} {hint}"), Some(""));
    match v.to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" | "ya" => true,
        _ => false,
    }
}
