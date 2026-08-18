import socket
import time
from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required
from .. import get_dns_server
from ..dnscore import wire
from ..utils import detect

bp = Blueprint("diagnostics", __name__, url_prefix="/diagnostics")


@bp.route("/")
@login_required
def index():
    return render_template("diagnostics.html")


@bp.route("/lookup", methods=["POST"])
@login_required
def lookup():
    body = request.get_json(force=True)
    qname = body.get("qname", "").strip()
    qtype = body.get("qtype", "A").strip().upper()
    if not qname:
        return jsonify({"error": "Enter a domain name."}), 400
    srv = get_dns_server()
    start = time.time()
    answers, rcode, source, authority, is_authoritative, trace_steps = srv.resolver.resolve(
        qname, qtype, "127.0.0.1", dnssec_ok=True, trace=True)
    elapsed = round((time.time() - start) * 1000, 2)
    return jsonify({
        "qname": qname, "qtype": qtype, "rcode": rcode, "source": source, "elapsed_ms": elapsed,
        "is_authoritative": is_authoritative, "trace": trace_steps,
        "answers": [{"rtype": a.rtype, "ttl": a.ttl, "value": a.value} for a in answers],
        "authority": [{"rtype": a.rtype, "ttl": a.ttl, "value": a.value} for a in authority],
    })


@bp.route("/connectivity", methods=["POST"])
@login_required
def connectivity():
    results = []
    for host, port, label in [("1.1.1.1", 53, "Cloudflare DNS"), ("8.8.8.8", 53, "Google DNS")]:
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            req = wire.Message()
            req.id = wire.new_query_id()
            req.rd = 1
            req.questions.append(wire.Question("example.com.", "A"))
            s.sendto(req.to_wire(), (host, port))
            s.recvfrom(4096)
            latency = round((time.time() - start) * 1000, 1)
            results.append({"label": label, "host": host, "ok": True, "latency_ms": latency})
        except Exception as e:
            results.append({"label": label, "host": host, "ok": False, "error": str(e)})
    return jsonify({"results": results})


@bp.route("/config-analysis")
@login_required
def config_analysis():
    db = dbmod.get_db()
    suggestions = []
    zones = dbmod.query(db, "SELECT COUNT(*) c FROM zones", one=True)["c"]
    if zones == 0:
        suggestions.append({"level": "info", "message": "No zones yet — try Simple DNS Mode to create your first one."})
    forwarders = dbmod.query(db, "SELECT COUNT(*) c FROM forwarders WHERE enabled=1", one=True)["c"]
    if forwarders == 0:
        suggestions.append({"level": "warning", "message": "No upstream forwarders configured — public domains won't resolve."})
    unhealthy = dbmod.query(db, "SELECT COUNT(*) c FROM forwarders WHERE enabled=1 AND healthy=0", one=True)["c"]
    if unhealthy:
        suggestions.append({"level": "error", "message": f"{unhealthy} forwarder(s) are currently unhealthy."})
    port_free = detect.port_is_free(5353)
    srv = get_dns_server()
    if srv and not srv.is_running():
        suggestions.append({"level": "error", "message": f"DNS listener failed to bind: {srv.bind_error}"})
    if not suggestions:
        suggestions.append({"level": "ok", "message": "Configuration looks healthy."})
    return jsonify({"suggestions": suggestions})
