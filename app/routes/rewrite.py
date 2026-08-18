import json
from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required, audit
from .. import get_dns_server
from ..dnscore.resolver import Resolver

bp = Blueprint("rewrite", __name__, url_prefix="/rewrite")


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    rules = dbmod.query(db, "SELECT * FROM rewrite_rules ORDER BY priority ASC")
    return render_template("rewrite.html", rules=rules)


@bp.route("/add", methods=["POST"])
@login_required
def add():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    rtype = body.get("rtype", "A")
    value = {"ttl": int(body.get("ttl", 300))}
    if rtype in ("A", "AAAA"):
        value["address"] = body.get("value")
    elif rtype == "CNAME":
        value["target"] = body.get("value")
    elif rtype == "TXT":
        value["text"] = body.get("value")
    else:
        value["address"] = body.get("value")

    rid = dbmod.execute(db, """INSERT INTO rewrite_rules
        (name, match_type, pattern, rtype, rewrite_value, client_match, time_start, time_end, priority)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (body.get("name", body.get("pattern")), body.get("match_type", "exact"), body.get("pattern"),
         rtype, json.dumps(value), body.get("client_match") or None,
         body.get("time_start") or None, body.get("time_end") or None, int(body.get("priority", 100))))
    audit(f"Added rewrite rule for '{body.get('pattern')}'", "dns")
    return jsonify({"ok": True, "id": rid})


@bp.route("/<int:rid>", methods=["DELETE"])
@login_required
def remove(rid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM rewrite_rules WHERE id=?", (rid,))
    audit(f"Removed rewrite rule #{rid}", "dns")
    return jsonify({"ok": True})


@bp.route("/<int:rid>/toggle", methods=["POST"])
@login_required
def toggle(rid):
    db = dbmod.get_db()
    row = dbmod.query(db, "SELECT enabled FROM rewrite_rules WHERE id=?", (rid,), one=True)
    dbmod.execute(db, "UPDATE rewrite_rules SET enabled=? WHERE id=?", (0 if row["enabled"] else 1, rid))
    return jsonify({"ok": True})


@bp.route("/simulate", methods=["POST"])
@login_required
def simulate():
    body = request.get_json(force=True)
    qname = body.get("qname", "")
    qtype = body.get("qtype", "A")
    client_ip = body.get("client_ip", "127.0.0.1")
    srv = get_dns_server()
    result = srv.resolver._apply_rewrite(qname, qtype, client_ip) if srv else None
    if result:
        return jsonify({"matched": True, "value": result.value, "ttl": result.ttl})
    return jsonify({"matched": False})
