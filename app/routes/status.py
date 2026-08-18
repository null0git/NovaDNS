import socket
import time
from flask import Blueprint, render_template, jsonify
from .. import db as dbmod
from .. import get_dns_server
from ..dnscore import wire
from ..utils import detect
from ..utils.device_platforms import PLATFORMS

bp = Blueprint("status", __name__, url_prefix="/status")


def _check_dns(protocol):
    srv = get_dns_server()
    if not srv or not srv.is_running():
        return {"online": False, "latency_ms": None}
    m = wire.Message()
    m.id = wire.new_query_id()
    m.rd = 1
    m.questions.append(wire.Question("example.com.", "A"))
    payload = m.to_wire()
    start = time.time()
    try:
        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(payload, ("127.0.0.1", srv.port))
            sock.recvfrom(4096)
        else:
            sock = socket.create_connection(("127.0.0.1", srv.port), timeout=2)
            sock.sendall(len(payload).to_bytes(2, "big") + payload)
            rlen = int.from_bytes(sock.recv(2), "big")
            data = b""
            while len(data) < rlen:
                data += sock.recv(rlen - len(data))
            sock.close()
        return {"online": True, "latency_ms": round((time.time() - start) * 1000, 2)}
    except Exception:
        return {"online": False, "latency_ms": None}


@bp.route("/")
def public_status():
    db = dbmod.get_db()
    srv = get_dns_server()
    running = srv.is_running() if srv else False
    uptime_seconds = int(time.time() - srv.started_at) if srv and srv.started_at else 0

    incidents = dbmod.query(db, "SELECT * FROM alerts WHERE severity IN ('warning','critical') ORDER BY ts DESC LIMIT 10")
    maintenance = dbmod.query(db, "SELECT * FROM maintenance WHERE id=1", one=True)

    total = dbmod.query(db, "SELECT COUNT(*) c FROM query_log WHERE ts >= datetime('now','-1 day')", one=True)["c"]
    failed = dbmod.query(db, """SELECT COUNT(*) c FROM query_log
                                 WHERE ts >= datetime('now','-1 day') AND rcode NOT IN (0,3)""", one=True)["c"]
    uptime_pct = round(100 * (1 - (failed / total)), 2) if total else 100.0

    avg_latency = dbmod.query(db, """SELECT AVG(latency_ms) a FROM query_log
                                      WHERE ts >= datetime('now','-1 hour')""", one=True)["a"] or 0
    cache_stats = srv.resolver.cache.stats() if srv else {"hit_ratio": 0}

    services = {
        "dns_udp": _check_dns("udp"),
        "dns_tcp": _check_dns("tcp"),
        "admin_ui": {"online": True, "latency_ms": 0},  # if this handler ran, the admin UI is up
    }

    # Real 30-day uptime timeline from query_log: each day's success ratio (rcode not SERVFAIL)
    daily = dbmod.query(db, """
        SELECT date(ts) d, COUNT(*) total, SUM(CASE WHEN rcode=2 THEN 1 ELSE 0 END) fails
        FROM query_log WHERE ts >= datetime('now','-30 days') GROUP BY date(ts) ORDER BY d""")
    timeline = [{"date": r["d"], "pct": round(100 * (1 - r["fails"] / r["total"]), 1) if r["total"] else 100.0} for r in daily]

    ips = detect.get_local_ips()
    hostname, fqdn = detect.get_hostname_fqdn()

    return render_template("status.html", running=running, uptime_seconds=uptime_seconds,
                           incidents=incidents, maintenance=maintenance, uptime_pct=uptime_pct,
                           avg_latency=round(avg_latency, 1), services=services, timeline=timeline,
                           cache_hit_ratio=cache_stats.get("hit_ratio", 0),
                           ips=ips, port=srv.port if srv else 53, hostname=hostname,
                           platforms=PLATFORMS)


@bp.route("/api")
def public_status_api():
    db = dbmod.get_db()
    srv = get_dns_server()
    return jsonify({
        "dns_running": srv.is_running() if srv else False,
        "uptime_seconds": int(time.time() - srv.started_at) if srv and srv.started_at else 0,
    })
