import time
from flask import Blueprint, render_template
from .. import db as dbmod
from ..auth import login_required
from ..utils.health import compute_health_score
from .. import get_dns_server

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def home():
    db = dbmod.get_db()
    srv = get_dns_server()

    zone_count = dbmod.query(db, "SELECT COUNT(*) c FROM zones", one=True)["c"]
    record_count = dbmod.query(db, "SELECT COUNT(*) c FROM records", one=True)["c"]
    client_count = dbmod.query(db, "SELECT COUNT(*) c FROM clients", one=True)["c"]
    queries_today = dbmod.query(db, "SELECT COUNT(*) c FROM query_log WHERE ts >= datetime('now','-1 day')", one=True)["c"]

    top_domains = dbmod.query(db, """
        SELECT qname, COUNT(*) c FROM query_log WHERE ts >= datetime('now','-1 day')
        GROUP BY qname ORDER BY c DESC LIMIT 6""")
    top_clients = dbmod.query(db, """
        SELECT client_ip, COUNT(*) c FROM query_log WHERE ts >= datetime('now','-1 day')
        GROUP BY client_ip ORDER BY c DESC LIMIT 6""")
    recent_alerts = dbmod.query(db, "SELECT * FROM alerts WHERE resolved=0 ORDER BY ts DESC LIMIT 5")
    recent_audit = dbmod.query(db, "SELECT * FROM audit_log ORDER BY ts DESC LIMIT 6")

    cache_stats = srv.resolver.cache.stats() if srv else {"entries": 0, "hits": 0, "misses": 0, "hit_ratio": 0}
    health = compute_health_score(db, srv.is_running() if srv else False)

    uptime_seconds = int(time.time() - srv.started_at) if srv and srv.started_at else 0

    qps_rows = dbmod.query(db, """
        SELECT strftime('%H:%M', ts) bucket, COUNT(*) c FROM query_log
        WHERE ts >= datetime('now','-1 hour') GROUP BY (strftime('%s',ts) / 60) ORDER BY ts""")
    qps_series = [r["c"] for r in qps_rows] or [0]

    return render_template(
        "dashboard.html",
        zone_count=zone_count, record_count=record_count, client_count=client_count,
        queries_today=queries_today, top_domains=top_domains, top_clients=top_clients,
        recent_alerts=recent_alerts, recent_audit=recent_audit, cache_stats=cache_stats,
        health=health, uptime_seconds=uptime_seconds, qps_series=qps_series,
        dns_running=srv.is_running() if srv else False,
        bind_error=srv.bind_error if srv else None,
        dns_port=srv.port if srv else None,
    )
