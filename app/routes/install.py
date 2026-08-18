import json
from flask import Blueprint, render_template, request, redirect, url_for, session

from .. import db as dbmod
from ..auth import hash_password, audit
from ..utils import detect
from ..utils.health import get_setting, set_setting

bp = Blueprint("install", __name__, url_prefix="/install")

STEPS = ["welcome", "network", "account", "dns", "upstream", "security", "family", "database", "plugins", "summary"]

UPSTREAM_PRESETS = {
    "cloudflare": [("1.1.1.1", 53), ("1.0.0.1", 53)],
    "google": [("8.8.8.8", 53), ("8.8.4.4", 53)],
    "quad9": [("9.9.9.9", 53), ("149.112.112.112", 53)],
    "opendns": [("208.67.222.222", 53), ("208.67.220.220", 53)],
}

PLUGIN_CATALOG = [
    {"id": "geoip", "name": "GeoIP Insights", "desc": "Tag clients and query logs with approximate geographic origin."},
    {"id": "prometheus", "name": "Prometheus Exporter", "desc": "Expose DNS metrics for external monitoring stacks."},
    {"id": "ldap", "name": "LDAP / Active Directory", "desc": "Authenticate admin users against a directory service."},
    {"id": "letsencrypt", "name": "ACME Auto-TLS", "desc": "Automatic certificate issuance for the admin web UI."},
]


def _is_installed(db):
    return get_setting(db, "install_complete") == "1"


@bp.route("/", methods=["GET"])
def wizard():
    db = dbmod.get_db()
    if _is_installed(db) and not session.get("allow_reinstall"):
        return redirect(url_for("auth.login"))
    step = request.args.get("step", "welcome")
    if step not in STEPS:
        step = "welcome"
    ctx = {"step": step, "steps": STEPS, "step_index": STEPS.index(step)}

    if step == "welcome":
        ctx["checks"] = {
            "python": True,
            "write_access": True,
            "dns_port_free": detect.port_is_free(5353),
            "disk_free_gb": detect.disk_free_gb(),
            "os": detect.get_os_summary(),
        }
    elif step == "network":
        ctx["ips"] = detect.get_local_ips()
        hostname, fqdn = detect.get_hostname_fqdn()
        ctx["hostname"] = hostname
        ctx["fqdn"] = fqdn
        ctx["interfaces"] = detect.get_network_interfaces()
    elif step == "upstream":
        ctx["presets"] = UPSTREAM_PRESETS
    elif step == "plugins":
        ctx["catalog"] = PLUGIN_CATALOG
    elif step == "summary":
        ctx["wizard_data"] = session.get("wizard", {})

    return render_template(f"install/{step}.html", **ctx)


@bp.route("/save/<step>", methods=["POST"])
def save_step(step):
    wiz = session.get("wizard", {})
    form = request.form

    if step == "network":
        wiz["bind_addr"] = form.get("bind_addr", "0.0.0.0")
        wiz["dns_port"] = form.get("dns_port", "53")
    elif step == "account":
        wiz["username"] = form.get("username", "admin").strip()
        wiz["password"] = form.get("password", "")
    elif step == "dns":
        wiz["primary_domain"] = form.get("primary_domain", "").strip()
        wiz["default_ttl"] = form.get("default_ttl", "3600")
        wiz["enable_recursive"] = form.get("enable_recursive") == "on"
    elif step == "upstream":
        wiz["upstream_preset"] = form.get("upstream_preset", "cloudflare")
        wiz["custom_upstream"] = form.get("custom_upstream", "").strip()
    elif step == "security":
        wiz["enable_dnssec"] = form.get("enable_dnssec") == "on"
        wiz["enable_https_admin"] = form.get("enable_https_admin") == "on"
        wiz["session_timeout"] = form.get("session_timeout", "60")
    elif step == "family":
        wiz["family_categories"] = request.form.getlist("categories")
        wiz["safesearch"] = form.get("safesearch") == "on"
    elif step == "database":
        wiz["db_engine"] = "sqlite"
    elif step == "plugins":
        wiz["plugins"] = request.form.getlist("plugins")

    session["wizard"] = wiz
    idx = STEPS.index(step)
    nxt = STEPS[idx + 1] if idx + 1 < len(STEPS) else "summary"
    return redirect(url_for("install.wizard", step=nxt))


@bp.route("/finish", methods=["POST"])
def finish():
    db = dbmod.get_db()
    wiz = session.get("wizard", {})

    existing = dbmod.query(db, "SELECT id FROM users WHERE username=?", (wiz.get("username", "admin"),), one=True)
    if not existing and wiz.get("username") and wiz.get("password"):
        dbmod.execute(db, "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                      (wiz["username"], hash_password(wiz["password"]), "admin"))

    domain = wiz.get("primary_domain")
    if domain:
        exists = dbmod.query(db, "SELECT id FROM zones WHERE name=?", (domain,), one=True)
        if not exists:
            dbmod.execute(db, """INSERT INTO zones (name, default_ttl, soa_mname, soa_rname)
                                  VALUES (?,?,?,?)""",
                          (domain, int(wiz.get("default_ttl", 3600)),
                           f"ns1.{domain}.", f"admin.{domain}."))

    preset = wiz.get("upstream_preset", "cloudflare")
    servers = UPSTREAM_PRESETS.get(preset, [])
    dbmod.execute(db, "DELETE FROM forwarders")
    for i, (addr, port) in enumerate(servers):
        dbmod.execute(db, """INSERT INTO forwarders (address, port, protocol, label, priority)
                              VALUES (?,?,?,?,?)""", (addr, port, "udp", preset, i))
    custom = wiz.get("custom_upstream")
    if custom:
        parts = custom.split(":")
        addr = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 53
        dbmod.execute(db, """INSERT INTO forwarders (address, port, protocol, label, priority)
                              VALUES (?,?,?,?,?)""", (addr, port, "udp", "custom", 100))

    if wiz.get("family_categories"):
        from ..utils.blocklist_seeds import SEED_LISTS, SECURITY_FEED_URLS, CATEGORY_LABELS
        from ..utils import blocklist_updater
        for cat in wiz["family_categories"]:
            label = CATEGORY_LABELS.get(cat, f"Family Safe: {cat}")
            if cat in SEED_LISTS:
                bid = dbmod.execute(db, """INSERT INTO blocklists (name, category, enabled, entry_count, last_updated)
                                            VALUES (?,?,1,?,datetime('now'))""",
                                     (label, cat, len(SEED_LISTS[cat])))
                for domain in SEED_LISTS[cat]:
                    dbmod.execute(db, "INSERT INTO block_entries (blocklist_id, domain, list_type) VALUES (?,?,'block')", (bid, domain))
            elif cat in SECURITY_FEED_URLS:
                url = SECURITY_FEED_URLS[cat]
                bid = dbmod.execute(db, "INSERT INTO blocklists (name, category, source_url, enabled) VALUES (?,?,?,1)",
                                     (label, cat, url))
                try:
                    blocklist_updater.fetch_and_sync(db, bid, url)
                except Exception:
                    pass  # scheduled updater or a manual "Sync now" picks it up once internet is reachable
            else:
                dbmod.execute(db, "INSERT INTO blocklists (name, category, enabled) VALUES (?,?,1)", (label, cat))

    set_setting(db, "install_complete", "1")
    set_setting(db, "site_name", "NovaDNS")
    set_setting(db, "accent_color", "#4C8CFF")
    set_setting(db, "safesearch_enabled", "1" if wiz.get("safesearch") else "0")
    set_setting(db, "dnssec_enabled", "1" if wiz.get("enable_dnssec") else "0")
    set_setting(db, "session_timeout_min", wiz.get("session_timeout", "60"))
    for p in wiz.get("plugins", []):
        set_setting(db, f"plugin_{p}_enabled", "1")

    db.commit()
    audit("Installation wizard completed", "system")
    session.pop("wizard", None)
    session.pop("allow_reinstall", None)
    return redirect(url_for("auth.login"))


@bp.route("/rerun")
def rerun():
    session["allow_reinstall"] = True
    return redirect(url_for("install.wizard", step="welcome"))
