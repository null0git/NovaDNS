import os
import secrets
from flask import Flask, g, session

from . import db as dbmod
from .dnscore.server import DNSServer
from .utils.alertmonitor import AlertMonitor
from .utils.blocklist_updater import BlocklistUpdater

_dns_server_instance = None
_alert_monitor_instance = None
_blocklist_updater_instance = None


def get_dns_server():
    return _dns_server_instance


def create_app(test_config=None):
    global _dns_server_instance, _alert_monitor_instance, _blocklist_updater_instance
    app = Flask(__name__, instance_relative_config=False)

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app.config.update(
        DATABASE_PATH=os.environ.get("NOVADNS_DB", os.path.join(base_dir, "data", "novadns.sqlite")),
        SECRET_KEY=os.environ.get("NOVADNS_SECRET", "dev-secret-change-me-" + secrets.token_hex(8)),
        DNS_BIND_ADDR=os.environ.get("NOVADNS_BIND", "0.0.0.0"),
        DNS_PORT=int(os.environ.get("NOVADNS_DNS_PORT", "53")),
        BACKUP_DIR=os.path.join(base_dir, "backups"),
        BASE_DIR=base_dir,
    )
    if test_config:
        app.config.update(test_config)

    first_time = dbmod.init_db(app)

    # Let a value saved from Settings -> Network override the default on the
    # NEXT boot, but never override an explicit environment variable (env
    # vars are how systemd/Docker/production deployments pin this down).
    conn = __import__("sqlite3").connect(app.config["DATABASE_PATH"])
    conn.row_factory = __import__("sqlite3").Row
    saved = {r["key"]: r["value"] for r in conn.execute(
        "SELECT key, value FROM settings WHERE key IN ('dns_port','dns_bind_addr','ratelimit_capacity','ratelimit_refill')")}
    if "NOVADNS_DNS_PORT" not in os.environ and saved.get("dns_port"):
        app.config["DNS_PORT"] = int(saved["dns_port"])
    if "NOVADNS_BIND" not in os.environ and saved.get("dns_bind_addr"):
        app.config["DNS_BIND_ADDR"] = saved["dns_bind_addr"]

    # Out-of-the-box internet resolution: if no forwarders exist yet at all
    # (e.g. the wizard was skipped or interrupted), seed a sane default so
    # "google.com won't resolve" isn't the first thing a new install hits.
    fw_count = conn.execute("SELECT COUNT(*) FROM forwarders").fetchone()[0]
    if fw_count == 0:
        conn.execute("INSERT INTO forwarders (address, port, protocol, label, priority) VALUES (?,?,?,?,?)",
                     ("1.1.1.1", 53, "udp", "cloudflare (auto)", 0))
        conn.execute("INSERT INTO forwarders (address, port, protocol, label, priority) VALUES (?,?,?,?,?)",
                     ("1.0.0.1", 53, "udp", "cloudflare (auto)", 1))
        conn.commit()
    conn.close()

    if _dns_server_instance is None:
        _dns_server_instance = DNSServer(app.config["DATABASE_PATH"], app.config["DNS_BIND_ADDR"],
                                          app.config["DNS_PORT"], base_dir=base_dir)
        rl_capacity = saved.get("ratelimit_capacity")
        rl_refill = saved.get("ratelimit_refill")
        if rl_capacity or rl_refill:
            _dns_server_instance.rate_limiter.configure(
                int(rl_capacity) if rl_capacity else 200,
                int(rl_refill) if rl_refill else 100)
        _dns_server_instance.start()

    if _alert_monitor_instance is None:
        _alert_monitor_instance = AlertMonitor(app.config["DATABASE_PATH"], get_dns_server, base_dir)
        _alert_monitor_instance.start()

    if _blocklist_updater_instance is None:
        _blocklist_updater_instance = BlocklistUpdater(app.config["DATABASE_PATH"], base_dir)
        _blocklist_updater_instance.start()

    from .routes import auth as auth_bp
    from .routes import install as install_bp
    from .routes import dashboard as dashboard_bp
    from .routes import zones as zones_bp
    from .routes import forwarders as forwarders_bp
    from .routes import rewrite as rewrite_bp
    from .routes import filtering as filtering_bp
    from .routes import monitoring as monitoring_bp
    from .routes import diagnostics as diagnostics_bp
    from .routes import devices as devices_bp
    from .routes import settings as settings_bp
    from .routes import audit as audit_bp
    from .routes import status as status_bp
    from .routes import terminal as terminal_bp
    from .routes import api as api_bp
    from .routes import benchmark as benchmark_bp
    from .routes import groups as groups_bp
    from .routes import compliance as compliance_bp
    from .routes import inspector as inspector_bp
    from .routes import lookup_portal as lookup_portal_bp
    from .routes import docs as docs_bp
    from .routes import architecture as architecture_bp

    app.register_blueprint(auth_bp.bp)
    app.register_blueprint(install_bp.bp)
    app.register_blueprint(dashboard_bp.bp)
    app.register_blueprint(zones_bp.bp)
    app.register_blueprint(forwarders_bp.bp)
    app.register_blueprint(rewrite_bp.bp)
    app.register_blueprint(filtering_bp.bp)
    app.register_blueprint(monitoring_bp.bp)
    app.register_blueprint(diagnostics_bp.bp)
    app.register_blueprint(devices_bp.bp)
    app.register_blueprint(settings_bp.bp)
    app.register_blueprint(audit_bp.bp)
    app.register_blueprint(status_bp.bp)
    app.register_blueprint(terminal_bp.bp)
    app.register_blueprint(api_bp.bp)
    app.register_blueprint(benchmark_bp.bp)
    app.register_blueprint(groups_bp.bp)
    app.register_blueprint(compliance_bp.bp)
    app.register_blueprint(inspector_bp.bp)
    app.register_blueprint(lookup_portal_bp.bp)
    app.register_blueprint(docs_bp.bp)
    app.register_blueprint(architecture_bp.bp)

    @app.context_processor
    def inject_globals():
        from .utils.health import get_setting
        db = dbmod.get_db()
        site_name = get_setting(db, "site_name", "NovaDNS")
        accent = get_setting(db, "accent_color", "#4C8CFF")
        logo_ext = get_setting(db, "logo_ext", "")
        from .auth import current_user
        srv = _dns_server_instance
        return {
            "site_name": site_name,
            "accent_color": accent,
            "logo_ext": logo_ext,
            "current_user": current_user(),
            "dns_running": srv.is_running() if srv else False,
            "dns_bind_error": srv.bind_error if srv else None,
            "dns_port_global": srv.port if srv else None,
            "dns_bind_addr_global": srv.bind_addr if srv else None,
        }

    from markupsafe import Markup
    from .utils.icons import icon as _icon_fn
    app.jinja_env.globals["icon"] = lambda name, cls="": Markup(_icon_fn(name, cls))

    @app.template_filter("dtfmt")
    def dtfmt(value, fmt="%b %d, %H:%M"):
        if not value:
            return "—"
        try:
            import datetime
            if isinstance(value, str):
                value = datetime.datetime.fromisoformat(value.replace("Z", ""))
            return value.strftime(fmt)
        except Exception:
            return str(value)

    return app
