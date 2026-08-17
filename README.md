# dnsv-certvault

`dnsvcert` — ACME DNS-01 client for DNSVault. Gets Let's Encrypt (or any
RFC 8555 CA) certificates for machines that cannot use HTTP-01: internal
servers and wildcard certs.

Instead of granting update access to your real zones, dnsvcert writes the
`_acme-challenge` TXT records into a **dedicated challenge zone** via
RFC 2136 + TSIG. Your real zones only carry one static CNAME per name.
A leaked TSIG key can write TXT records in a throwaway zone — nothing else.

Works with DNSVault hybrid (v1) and Neo alike: both serve BIND, and BIND is
the whole server-side requirement.

## One-time server setup

1. Generate a TSIG key on the DNSVault master:

   ```
   tsig-keygen dnsvcert-key
   ```

2. Create the challenge zone (say `acme.example.com`) and allow that key to
   write TXT records only:

   ```
   key "dnsvcert-key" {
       algorithm hmac-sha256;
       secret "…";
   };

   zone "acme.example.com" {
       type master;
       file "acme.example.com.db";
       update-policy { grant dnsvcert-key zonesub TXT; };
   };
   ```

   The zone needs an ordinary SOA/NS skeleton and must be publicly
   resolvable (delegated like any other zone).

3. For every name you want certificates for, add one static CNAME in the
   real zone (through the DNSVault console, like any record):

   ```
   _acme-challenge.app.example.com.  CNAME  app.example.com.acme.example.com.
   ```

   One CNAME covers both `app.example.com` and `*.app.example.com`.

## Install

Grab a prebuilt binary from [Releases](https://github.com/dnsvault/dnsv-certvault/releases)
(Linux x86_64/ARM64, macOS, Windows, FreeBSD), extract, and put `dnsvcert`
on your PATH. No runtime, no dependencies.

## Client usage

New to this? The guided walkthrough asks for everything, live-checks your
DNS with fix-and-retry loops, and issues when everything passes:

```
dnsvcert setup
```

Prefer flags? The non-interactive path:

```
dnsvcert init --domain app.example.com --domain '*.app.example.com' \
  --email ops@example.com --challenge-zone acme.example.com   # writes starter config
dnsvcert doctor    # verify CNAME delegation + TSIG write access
dnsvcert issue     # issue everything in the config
dnsvcert renew     # cron/systemd-timer friendly, renews when < 30 days left
```

`doctor`'s CNAME checks run even before you have a TSIG secret, and every
failure prints the exact record to add.

The internal machine only needs outbound DNS to the DNSVault master and
outbound HTTPS to the CA. Nothing inbound.

### As a certbot hook

Already on certbot? Keep it, use dnsvcert only for the DNS part:

```
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook    "dnsvcert hook auth" \
  --manual-cleanup-hook "dnsvcert hook cleanup" \
  -d app.example.com -d '*.app.example.com'
```

## Build

```
cargo build --release   # target/release/dnsvcert, single static-ish binary
```

## Multi-view DNS (internal networks)

DNSVault-style servers answer different views to different clients, routed
by source address — or by TSIG key. dnsvcert signs its verification
queries (TXT confirm, `doctor` checks) with your key by default, so they
land in the same view as the signed updates and running from inside the
network just works. To send verification queries elsewhere instead, set
`dns.resolver: 8.8.8.8` (signing then defaults off); `dns.sign_queries`
overrides either behaviour explicitly.

## License

Source-available, all rights reserved. You may read the code and run the
release binaries for your own certificate automation. Copying, forking,
redistribution, and offering this software as part of any service require
written permission from DNSVault — see [LICENSE](LICENSE).
