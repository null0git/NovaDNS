from flask import Blueprint, render_template, jsonify, request
from .. import db as dbmod
from ..auth import login_required
from .. import get_dns_server
from ..utils import detect

bp = Blueprint("monitoring", __name__, url_prefix="/monitoring")


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    forwarders = dbmod.query(db, "SELECT * FROM forwarders ORDER BY priority")
    return render_template("monitoring.html", forwarders=forwarders)


@bp.route("/api/percentiles")
@login_required
def api_percentiles():
    db = dbmod.get_db()
    window = request.args.get("window", "hour")
    interval_map = {"hour": "-1 hour", "day": "-1 day", "week": "-7 days", "month": "-30 days", "year": "-365 days"}
    since = interval_map.get(window, "-1 hour")
    rows = dbmod.query(db, f"SELECT latency_ms FROM query_log WHERE ts >= datetime('now','{since}') AND latency_ms IS NOT NULL ORDER BY latency_ms")
    latencies = [r["latency_ms"] for r in rows]
    n = len(latencies)

    def pct(p):
        if not n:
            return 0
        idx = min(n - 1, max(0, int(n * p) - 1))
        return round(latencies[idx], 2)

    slowest = dbmod.query(db, f"""SELECT qname, qtype, latency_ms, ts FROM query_log
                                   WHERE ts >= datetime('now','{since}') ORDER BY latency_ms DESC LIMIT 1""", one=True)
    peak_qps_row = dbmod.query(db, f"""SELECT MAX(c) m FROM (SELECT COUNT(*) c FROM query_log
                                        WHERE ts >= datetime('now','{since}') GROUP BY strftime('%s',ts)/60)""", one=True)
    return jsonify({
        "count": n, "p50": pct(0.50), "p90": pct(0.90), "p95": pct(0.95), "p99": pct(0.99),
        "avg": round(sum(latencies) / n, 2) if n else 0,
        "peak_qps_per_min": peak_qps_row["m"] if peak_qps_row and peak_qps_row["m"] else 0,
        "slowest_query": {"qname": slowest["qname"], "qtype": slowest["qtype"], "latency_ms": round(slowest["latency_ms"], 2),
                           "ts": slowest["ts"]} if slowest else None,
    })


@bp.route("/api/security")
@login_required
def api_security():
    db = dbmod.get_db()
    srv = get_dns_server()
    blocklist_hits = dbmod.query(db, "SELECT COUNT(*) c FROM query_log WHERE source='blocked' AND ts >= datetime('now','-1 day')", one=True)["c"]
    failed_logins = dbmod.query(db, "SELECT COUNT(*) c FROM audit_log WHERE action LIKE 'Failed login%' AND ts >= datetime('now','-1 day')", one=True)["c"]
    return jsonify({
        "rate_limited": srv.stats.get("rate_limited", 0) if srv else 0,
        "acl_refused": srv.stats.get("refused_acl", 0) if srv else 0,
        "blocklist_hits_24h": blocklist_hits,
        "failed_logins_24h": failed_logins,
    })


@bp.route("/api/recent")
@login_required
def api_recent():
    db = dbmod.get_db()
    limit = int(request.args.get("limit", 20))
    rows = dbmod.query(db, "SELECT * FROM query_log ORDER BY id DESC LIMIT ?", (limit,))
    entries = [{"qname": r["qname"], "qtype": r["qtype"], "source": r["source"],
                "rcode": r["rcode"], "latency_ms": round(r["latency_ms"] or 0, 1), "ts": r["ts"]}
               for r in reversed(rows)]
    return jsonify({"entries": entries})


@bp.route("/api/series")
@login_required
def api_series():
    db = dbmod.get_db()
    rows = dbmod.query(db, """
        SELECT strftime('%Y-%m-%d %H:%M', ts) bucket, COUNT(*) c,
               AVG(latency_ms) avg_latency,
               SUM(CASE WHEN source='cache' THEN 1 ELSE 0 END) cache_hits
        FROM query_log WHERE ts >= datetime('now','-30 minutes')
        GROUP BY bucket ORDER BY bucket""")
    return jsonify({
        "qps": [r["c"] for r in rows] or [0],
        "latency": [round(r["avg_latency"] or 0, 1) for r in rows] or [0],
        "cache_hits": [r["cache_hits"] for r in rows] or [0],
    })


@bp.route("/api/resources")
@login_required
def api_resources():
    res = detect.get_system_resources()
    srv = get_dns_server()
    cache_stats = srv.resolver.cache.stats() if srv else {}
    return jsonify({"resources": res, "cache": cache_stats,
                     "dns_running": srv.is_running() if srv else False,
                     "server_stats": srv.stats if srv else {}})


@bp.route("/api/source-breakdown")
@login_required
def api_source_breakdown():
    db = dbmod.get_db()
    rows = dbmod.query(db, """
        SELECT source, COUNT(*) c FROM query_log WHERE ts >= datetime('now','-1 day')
        GROUP BY source""")
    return jsonify({"breakdown": [{"source": r["source"], "count": r["c"]} for r in rows]})


@bp.route("/cache/clear", methods=["POST"])
@login_required
def clear_cache():
    srv = get_dns_server()
    if srv:
        srv.resolver.cache.clear()
    return jsonify({"ok": True})


@bp.route("/cache/inspect")
@login_required
def inspect_cache():
    srv = get_dns_server()
    rows = srv.resolver.cache.inspect() if srv else []
    return jsonify({"entries": rows})
