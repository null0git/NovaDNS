import socket
import time
from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required, audit
from .. import get_dns_server
from ..dnscore import wire

bp = Blueprint("forwarders", __name__, url_prefix="/forwarders")


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    forwarders = dbmod.query(db, "SELECT * FROM forwarders ORDER BY condition_domain IS NULL DESC, priority ASC")
    return render_template("forwarders.html", forwarders=forwarders)


@bp.route("/add", methods=["POST"])
@login_required
def add():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    fid = dbmod.execute(db, """INSERT INTO forwarders (address, port, protocol, label, priority, condition_domain)
                                VALUES (?,?,?,?,?,?)""",
                         (body["address"], int(body.get("port", 53)), body.get("protocol", "udp"),
                          body.get("label", ""), int(body.get("priority", 100)),
                          body.get("condition_domain") or None))
    audit(f"Added forwarder {body['address']}:{body.get('port', 53)}", "dns")
    return jsonify({"ok": True, "id": fid})


@bp.route("/<int:fid>", methods=["DELETE"])
@login_required
def remove(fid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM forwarders WHERE id=?", (fid,))
    audit(f"Removed forwarder #{fid}", "dns")
    return jsonify({"ok": True})


@bp.route("/<int:fid>/toggle", methods=["POST"])
@login_required
def toggle(fid):
    db = dbmod.get_db()
    row = dbmod.query(db, "SELECT enabled FROM forwarders WHERE id=?", (fid,), one=True)
    dbmod.execute(db, "UPDATE forwarders SET enabled=? WHERE id=?", (0 if row["enabled"] else 1, fid))
    return jsonify({"ok": True})


@bp.route("/<int:fid>/test", methods=["POST"])
@login_required
def test(fid):
    db = dbmod.get_db()
    fw = dbmod.query(db, "SELECT * FROM forwarders WHERE id=?", (fid,), one=True)
    if not fw:
        return jsonify({"error": "not found"}), 404
    req = wire.Message()
    req.id = wire.new_query_id()
    req.rd = 1
    req.questions.append(wire.Question("example.com.", "A"))
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.5)
        sock.sendto(req.to_wire(), (fw["address"], fw["port"]))
        data, _ = sock.recvfrom(4096)
        sock.close()
        latency = round((time.time() - start) * 1000, 1)
        resp = wire.Message.from_wire(data)
        dbmod.execute(db, "UPDATE forwarders SET last_latency_ms=?, last_check=datetime('now'), healthy=1 WHERE id=?",
                      (latency, fid))
        return jsonify({"ok": True, "latency_ms": latency, "rcode": resp.rcode, "answers": len(resp.answers)})
    except Exception as e:
        dbmod.execute(db, "UPDATE forwarders SET healthy=0, last_check=datetime('now') WHERE id=?", (fid,))
        return jsonify({"ok": False, "error": str(e)})
