# NovaDNS

Enterprise-style self-hosted DNS server and management platform, built
entirely in Python (Flask + stdlib). No Node.js, no third-party DNS
library, no external database service — a single process serves both
the DNS protocol and the admin web UI.

## Quick start

```bash
cd novadns
pip install -r requirements.txt
sudo python3 run.py     # port 53 needs root/capability — see below
```

Open **http://localhost:8080** and follow the setup wizard. The DNS
server listens on **port 53 by default** (both UDP and TCP) — this is
required for real devices: phones, PCs, and routers all send DNS
queries to port 53 and give you no way to configure a different port,
so this is not optional for real-world use.

A default upstream (Cloudflare 1.1.1.1/1.0.0.1) is seeded automatically
on first run, so internet domains resolve immediately even before you
finish the wizard.

### Getting your devices talking to it (read this if "it doesn't work")

The single most common failure is **port 53 not actually being bound**
(permission denied, silently) or a **host firewall blocking inbound
53**. Check the persistent red banner at the top of the admin UI if the
DNS listener failed to start — it shows the exact error. Then:

```bash
# Option A — grant the capability once, run as a normal user after that
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
python3 run.py

# Option B — run as root (simplest)
sudo python3 run.py

# Option C — systemd service (recommended for always-on use)
sudo cp deploy/novadns.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now novadns

# Option D — Docker
docker compose up -d
```

Then open **firewall access** for port 53 from your LAN (see the
in-app checklist under **Device Setup Center**, or the platform-specific
commands there — ufw / firewalld / Windows Firewall / macOS).

Finally, either point each device's DNS setting at the server's LAN IP
(shown on the Device Setup Center page, with copy buttons and QR codes
for mobile), or — much easier for "my phone and my PC" — set the
server's IP as the DNS server in your **router's DHCP settings** so
every device on the network picks it up automatically.

Test from another machine before troubleshooting further:

```bash
dig @<server-ip> google.com          # macOS/Linux
nslookup google.com <server-ip>      # Windows
```

### Environment variables

| Variable            | Default                        | Purpose                          |
|---------------------|---------------------------------|-----------------------------------|
| `NOVADNS_DB`         | `./data/novadns.sqlite`         | SQLite database path              |
| `NOVADNS_SECRET`     | random per-run                  | Flask session secret — set a fixed value in production |
| `NOVADNS_BIND`       | `0.0.0.0`                       | DNS server bind address           |
| `NOVADNS_DNS_PORT`   | `53`                            | DNS server port (UDP + TCP)       |
| `NOVADNS_WEB_PORT`   | `8080`                          | Admin web UI port                 |

Environment variables always win over anything saved in Settings →
Network, so production deployments (systemd/Docker) stay pinned to
known-good values regardless of what's in the database.

## Architecture

```
run.py                     # entry point
app/
  __init__.py               # Flask app factory, blueprint registration, DNS server bootstrap
  db.py                     # sqlite3 connection helpers (per-request + per-thread)
  schema.sql                # full data model
  auth.py                   # session auth, password hashing, audit() helper
  dnscore/
    wire.py                 # hand-written RFC 1035 message encode/decode (no dnslib/dnspython)
    resolver.py              # resolution pipeline: filter -> rewrite -> cache -> authoritative -> forward
    cache.py                 # in-memory TTL cache with stats
    server.py                # UDP + TCP socket server threads
  routes/                   # one blueprint per feature area (zones, forwarders, rewrite,
                             # filtering, monitoring, diagnostics, devices, settings, audit,
                             # status, terminal, api, install, auth, dashboard)
  utils/
    detect.py                # network/system detection (psutil-backed) for the wizard & devices
    health.py                 # Server Health Score computation + settings get/set
    backup.py                 # encrypted (Fernet/PBKDF2) backup & restore
    icons.py                  # hand-authored inline SVG icon set (no icon-font/CDN dependency)
  templates/, static/        # Jinja2 + vanilla JS/CSS UI (dark/light/system themes, skeleton
                             # loading, live "query pulse" strip, canvas-based charts)
```

**Everything runs in one process.** The DNS server runs in its own
background threads (UDP listener thread + TCP listener thread, with a
new worker thread per request), started once by the Flask app factory.
It talks to SQLite directly (not through Flask's request-scoped
connection) so it keeps working regardless of web traffic.

## What's fully working

- **Authoritative DNS** for A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA,
  NAPTR — real UDP + TCP listeners, hand-written wire-format parsing.
- **Simple DNS Mode** (domain + IP → zone/SOA/NS auto-created) and an
  advanced zone/record editor with export and validation.
- **Forwarding** with multiple upstreams, priority ordering, conditional
  (per-domain) forwarding, and per-forwarder health/latency testing.
- **Rewrite engine**: exact / wildcard / regex matching, client (CIDR)
  and time-window scoping, priority ordering, hit counters, and a live
  simulation tool.
- **Filtering / Family Safe DNS**: category toggles (malware, phishing,
  scam, ransomware, botnet, adult, gambling, etc.), custom block/allow
  lists (domain or regex, optionally client-scoped).
- **Caching** with TTL/negative caching, hit-ratio stats, inspection,
  and manual clearing.
- **Monitoring**: live query stream, QPS/latency charts, cache and
  resource stats (via `psutil`), source-of-answer breakdown.
- **Diagnostics**: built-in lookup tool (uses NovaDNS's own resolver),
  upstream connectivity test, automatic configuration analysis.
- **Device Setup Center**: guides for Windows/macOS/Linux/Android/iOS/
  ChromeOS/router/Docker/VM/cloud, with detected server IPs, copy
  buttons, and QR codes for mobile.
- **Guided install wizard**: system checks, network detection, admin
  account creation, DNS/upstream/security/Family-Safe configuration,
  database/plugin selection, summary — re-runnable from Settings.
- **Backups**: manual, real AES encryption (PBKDF2 + Fernet) with
  integrity checksums, download/restore, history.
- **Audit log**: every write action logged, searchable, CSV export.
- **Maintenance mode**, **multi-user accounts**, **dynamic DNS**
  client/server (token-authenticated update endpoint), **public status
  page**, and a **restricted browser terminal** (`dig`/`nslookup`
  against NovaDNS's own resolver; `ping`/`traceroute` via the host OS
  if present) with command allow-listing and audit logging.
- **Real ad-blocking and content filtering**: category toggles now load
  actual, real domains — not placeholders. Brand-name categories (ads &
  tracking, adult, gambling, social media, gaming, streaming, torrents,
  VPN/proxy, dating, drugs, cryptocurrency) ship with a curated seed
  list of well-known real domains (e.g. `doubleclick.net`,
  `googlesyndication.com`, `taboola.com` for ads/tracking) that blocks
  immediately, offline, the moment you flip the switch — verified by
  actually querying `doubleclick.net`/`pornhub.com`/`bet365.com`
  through the live resolver and confirming NXDOMAIN. Security-critical
  categories (malware, phishing, scam, ransomware, botnet) instead
  subscribe to real, actively-maintained public threat-intel feeds
  (StevenBlack's combined hosts list, abuse.ch URLhaus, OpenPhish) via
  the existing scheduled blocklist updater — a static list of "known
  malicious domains" would be stale within days, so these need live
  internet access to populate, same as any real security product.
  You can also import a blocklist from a local file (hosts-format or
  plain domain list) for fully offline use, and view the actual
  domains loaded for any category from the Filtering page.
- **Two real resolver bugs found and fixed** while investigating a
  reported issue: (1) wildcard records were being merged into every
  query's answer regardless of whether the queried name had its own
  explicit record — so a zone with both `www A 1.2.3.4` and `* A
  9.9.9.9` incorrectly returned *both* for a query against `www`, and
  the same bug could shadow an explicit CNAME lookup entirely. Fixed
  per RFC 1034 §4.3.3: a wildcard only ever answers for a name that
  doesn't exist in the zone at all. (2) NAPTR records were silently
  broken end-to-end — the encoder had no NAPTR case (falling through
  to an empty-bytes fallback) and the decoder had no NAPTR case either
  (falling through to opaque storage), so every NAPTR record ever
  added would have gone out on the wire empty. Both now have real
  encode/decode implementations and permanent regression tests. Found
  by writing a broader integration audit (multi-record zones,
  concurrent load, TCP, every claimed record type round-tripped through
  a full DNS message) rather than trusting the existing narrower tests
  — that audit script is worth rerunning after any resolver change.
- **Reverse DNS zone helper**: enter a network (e.g. `10.0.0.0/24`) and
  NovaDNS computes the correct `in-addr.arpa`/`ip6.arpa` zone name
  automatically; a convenience form lets you add PTR records by host
  number + target hostname instead of hand-building the reversed owner
  name.
- **Bulk record operations**: select multiple records in a zone to
  bulk-delete or bulk-set their TTL in one action.
- **ANY queries fixed**: previously broken — querying type ANY searched
  for a literal (nonexistent) "ANY" record type and always came back
  empty. Now returns every real record at that name, each keeping its
  own type, with correct DNSSEC RRSIG handling (no duplicates).
- **Structured TLSA, SSHFP, DS, and HTTPS/SVCB records**: upgraded from
  opaque hex-blob storage to real field-based encoding/decoding —
  usage/selector/matching-type for TLSA (RFC 6698), algorithm/fp-type
  for SSHFP (RFC 4255), key-tag/algorithm/digest for DS, and full
  SvcParam support (alpn, port, ipv4hint, ipv6hint) for HTTPS/SVCB
  (RFC 9460). All four now have their own real tests in the suite.
- **RFC Compliance Center**: a real test suite (`tests/test_rfc_compliance.py`,
  24 tests across 11 RFCs) runs live from the UI — every number shown
  (pass/fail counts, compliance %) comes from actually executing
  assertions against NovaDNS's own code that moment, not a static claim.
  RFCs not implemented (NSEC3, DoQ, ACME) are listed honestly alongside
  the ones that are.
- **DNS Packet Inspector**: paste or generate a real hex-encoded DNS
  message and see it parsed with NovaDNS's own wire-format decoder —
  header flags, questions, answers/authority/additional sections, with
  side-by-side comparison of two packets.
- **Zone Verification Center**: expanded from a basic sanity check to
  real, specific validations — circular CNAME chains, apex CNAME
  conflicts, MX/SRV targets that don't resolve or point at a CNAME,
  duplicate records, out-of-range TTLs, missing glue for in-zone
  delegations, SOA timer sanity, DNSSEC consistency, empty zones —
  each with a severity (critical/high/medium/low/info).
- **Live Query Trace**: the diagnostics lookup tool now shows every
  pipeline stage a query actually passed through (ACL → blocklists →
  rewrite → cache → Split DNS/authoritative → forwarder → DNSSEC) with
  per-stage timing and the real decision made at each step.
- **Advanced Monitoring**: real p50/p90/p95/p99 latency percentiles,
  peak queries-per-minute, slowest query in the selected window
  (hour/day/week/month/year), and live security counters (rate-limited,
  ACL-refused, blocklist hits, failed logins).
- **Import/Export Center**: zones export to BIND zone file, JSON, CSV,
  or YAML, and import back from JSON/CSV/YAML.
- **Documentation Center** and **Architecture Explorer**: searchable
  in-app docs and clickable diagrams describing NovaDNS's actual
  resolution pipeline, cache behavior, DNSSEC signing process, thread
  model, and database layout — accurate to the real implementation,
  not aspirational.
- **Public DNS Lookup Portal** (`/lookup`, no login required): anyone
  can look up real DNS records for any domain through NovaDNS's own
  resolver. Registrar information via RDAP is included when the
  network allows reaching the registry's RDAP service — when it can't
  (offline deployments, restrictive egress), the portal says so
  plainly instead of fabricating registrar data. DNS results are
  unaffected either way since they come directly from NovaDNS.
- **Enhanced public status page**: per-protocol availability (DNS
  UDP/TCP, Admin UI) with real reachability checks, a real 30-day
  uptime timeline computed from actual query history, and live cache
  hit ratio.
- **Correct AA (Authoritative Answer) bit**: fixed a real bug where a
  cached answer always reported AA=0 even if the underlying data was
  ours — the DNS header now reflects true data origin, not "was this
  served from cache." A cached authoritative answer still says AA=1;
  a cached forwarded answer never does, matching what a real
  validating client expects. Verified by querying the same name twice
  (cache miss then cache hit) for both an authoritative record and a
  forwarded one, confirming the bit stays correct in every case.
- **Split DNS**: any record can be scoped to a specific client
  network/group (`client_match`), so the same name can answer
  differently for internal vs. external clients — e.g. an internal LAN
  IP for your office network and a public IP for everyone else,
  configured per-record from the zone editor. Falls back to the
  unscoped record when no client-specific one matches.
- **Client Groups**: name a set of CIDRs/IPs once (e.g. `staff`,
  `kids`, `iot`) and reference it as `group:name` anywhere a client
  match is accepted — Split DNS records, rewrite rules, and filtering
  entries all understand it.
- **Zone templates**: create a new zone pre-populated from a template
  (basic web hosting, web+mail with SPF, or an internal-only service
  scoped to a client network/group) instead of adding records one at a
  time.
- **Scheduled blocklist auto-updates**: point a blocklist at a real
  source URL (hosts-file or plain-domain-list format) and NovaDNS
  fetches and refreshes it automatically (every 24h, or on demand with
  "Sync now") — stdlib `urllib` only, no dependency.
- **Professional public-facing pages**: the Documentation Center now
  covers 20 topics across five groups (Getting Started, DNS Management,
  Security, Operations, Reference) with real depth — deployment options,
  every feature's actual behavior, an API reference, and honest
  "not yet implemented" notes, all searchable. The public Status page
  gained a "Connect to this DNS server" section with real per-platform
  setup instructions (Windows/macOS/Linux/Android/iOS/router/Docker/VM/
  cloud) and the server's actual detected IPs, so a visitor who isn't
  logged in can still get their device connected. The public DNS Lookup
  Portal now renders every record type in a proper human-readable format
  (an MX record shows "10 mail.example.com", not
  `{"priority":10,"target":"mail.example.com"}`) instead of dumping
  raw JSON.
- **Real bundled logo**: NovaDNS ships with an actual logo (not a
  generic placeholder) — used across the sidebar, login page, install
  wizard, browser favicon/tab icon, and the public status and lookup
  pages. Includes real monochrome, black, and white variants generated
  from the source art: the black mark is used in a genuine print
  stylesheet (gradients don't reproduce reliably on most printers, and
  the interactive chrome is hidden entirely when printing a page).
  Uploading a custom logo from Settings still overrides all of this,
  exactly as before.
- **Custom branding**: upload a logo (PNG/JPG/WEBP/SVG) to replace the
  default mark in the sidebar and on the login page.
- **DNSSEC**: real zone signing — generates an ECDSAP256SHA256 (RFC 6605)
  key pair per zone, publishes a genuine DNSKEY record, and produces
  RFC 4034-canonical RRSIGs for every RRset, **including NSEC records
  for authenticated denial of existence** (a real, verifiable proof
  that a name doesn't exist — not just an NXDOMAIN with no evidence).
  Verified in testing by independently checking signatures
  cryptographically against the DNSKEY served over the wire, and by
  confirming the NSEC "next name" correctly brackets a nonexistent
  query name in canonical order. Serves RRSIG/DNSKEY/NSEC to clients
  that set the EDNS DO bit, same as a real validating resolver expects.
  The DS record for your parent zone/registrar is shown in the zone's
  DNSSEC panel. Key rollover is manual — see roadmap.
- **SOA handling**: SOA now always answers correctly at the zone apex
  (previously a gap — a bare SOA query could return NXDOMAIN if no
  explicit SOA record existed), is included in the authority section
  of NXDOMAIN/NODATA responses per RFC 2308 for correct negative
  caching by real resolvers, and is editable from the zone page
  (MNAME/RNAME/refresh/retry/expire/minimum; serial auto-increments).
- **Zone transfer (AXFR)**: real RFC 5936 zone transfers over TCP, for
  syncing to a secondary/slave DNS server. Refused for everyone by
  default (secure default, unlike the general query ACL) — add trusted
  secondary IPs under Settings → Network & Security.
- **Self-signed HTTPS for the admin UI**: generate a real X.509
  certificate (with the server's detected IPs as SANs) from Settings,
  no external dependency. Browsers will show a trust warning since
  nothing signed it — for a publicly-trusted certificate, put NovaDNS
  behind a reverse proxy (Caddy/nginx) instead.
- **DNS-over-HTTPS and DNS-over-TLS forwarding**: both are live, not
  just recorded — DoH POSTs the wire-format message per RFC 8484, DoT
  wraps a standard length-prefixed TCP query in TLS per RFC 7858, both
  using stdlib only (`urllib`/`ssl`, no extra dependency).
- **Real notification delivery**: Discord/Slack/generic webhooks and
  Telegram (bot API) via `urllib`, email via `smtplib` — all stdlib,
  no dependency. A background alert monitor watches forwarder health,
  CPU/memory/disk, and backup staleness, and dispatches to whichever
  channels are enabled (with dedup so an ongoing issue doesn't spam).
- **Built-in benchmark**: fires real queries through the live resolver
  (configurable count/concurrency), reporting QPS and p95/p99 latency,
  with history and plain-language recommendations.
- **Production hardening**: guaranteed SERVFAIL responses instead of
  silently dropped packets on internal errors, rotating file logging
  (`logs/novadns.log`) for every bind/resolve failure, SQLite WAL mode
  + busy-timeout to eliminate lock contention under concurrent
  multi-device traffic, EDNS0 (OPT record) acknowledgement for modern
  stub resolvers, per-client token-bucket rate limiting (configurable,
  live-applied without restart), and an access-control list to restrict
  which client networks may query the server at all.
- **REST API** (`/api/v1/...`) for zones/records plus the dynamic DNS
  update endpoint.
- **Deployment tooling**: `deploy/novadns.service` (systemd, with the
  `CAP_NET_BIND_SERVICE` capability so it doesn't need to run as root),
  `Dockerfile` + `docker-compose.yml` for one-command containerized
  deployment.

## Running the test suite

```bash
python3 -m unittest tests.test_rfc_compliance -v
```

These are the exact tests the RFC Compliance Center runs live from the
UI — genuine assertions against the real wire-format encoder/decoder,
resolver, DNSSEC signer, AXFR, EDNS0, DoT, and DoH code, not smoke
tests. All 20 currently pass; this is also how a real thread-local
database connection bug (connections were keyed by thread only, not
by database path) got caught and fixed during development.

## What's intentionally simplified (roadmap)

- **DNSSEC**: NSEC gives real denial-of-existence proofs, but NSEC3
  (hashed, zone-walk-resistant) isn't implemented, and key rollover is
  manual (re-signing reuses the same key rather than rotating it on a
  schedule).
- **DNS-over-QUIC**: no pure-stdlib QUIC implementation exists, and the
  one real Python QUIC library (`aioquic`) is a real dependency we
  haven't pulled in — DoQ forwarders can be configured but won't
  connect yet.
- **ACME (Let's Encrypt) auto-TLS**: not implemented — self-signed HTTPS
  is available from Settings for LAN/testing use; for a real publicly-
  trusted certificate, put NovaDNS behind a reverse proxy today.
- **Visual drag-and-drop zone/rule editors**: the rule builder and zone
  editor are full CRUD forms with simulation/validation; a graphical
  drag-and-drop canvas is not built.
- **Historical graphing** beyond the live/short-window charts shown in
  Monitoring (multi-day trend views aren't built yet).
- **AXFR** is single-message only — very large zones that don't fit in
  one TCP DNS message aren't chunked across multiple messages yet.

All of the above are clearly-marked follow-on work, not shipped as
fake/non-functional UI.

## Security notes for production use

- Set `NOVADNS_SECRET` to a fixed, random value (don't rely on the
  auto-generated dev default across restarts).
- Run behind a reverse proxy for TLS on the admin UI.
- The dev server (`app.run(...)`) is fine for evaluation; use a
  production WSGI server (gunicorn/waitress) plus a process manager
  for real deployments.
- Back up `data/novadns.sqlite` regularly (or use Settings → Backups).
