import json
from flask import Blueprint, jsonify, request
from .. import db as dbmod
from ..auth import login_required
from .. import get_dns_server

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.route("/zones")
@login_required
def api_zones():
    db = dbmod.get_db()
    zones = dbmod.query(db, "SELECT * FROM zones")
    return jsonify([dict(z) for z in zones])


@bp.route("/zones/<int:zone_id>/records")
@login_required
def api_zone_records(zone_id):
    db = dbmod.get_db()
    rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=?", (zone_id,))
    out = []
    for r in rows:
        d = dict(r)
        d["data"] = json.loads(d.pop("data_json"))
        out.append(d)
    return jsonify(out)


@bp.route("/dyndns/update")
def dyndns_update():
    """Public (token-auth) dynamic DNS update endpoint, matching the
    Dynamic DNS Client feature: GET /api/v1/dyndns/update?hostname=&token=&ip=&ipv6="""
    hostname = request.args.get("hostname")
    token = request.args.get("token")
    ip = request.args.get("ip")
    ipv6 = request.args.get("ipv6")
    if not hostname or not token:
        return jsonify({"error": "hostname and token are required"}), 400

    db = dbmod.get_db()
    host = dbmod.query(db, "SELECT * FROM dyndns_hosts WHERE hostname=? AND token=?", (hostname, token), one=True)
    if not host:
        return jsonify({"error": "unauthorized"}), 401
    if not ip and not ipv6:
        ip = request.remote_addr

    dbmod.execute(db, "UPDATE dyndns_hosts SET last_ip=?, last_ipv6=?, last_update=datetime('now') WHERE id=?",
                  (ip, ipv6, host["id"]))

    if host["zone_id"]:
        zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (host["zone_id"],), one=True)
        if zone:
            relative = "@" if hostname.rstrip(".").lower() == zone["name"].rstrip(".").lower() else \
                hostname.rstrip(".").lower().replace("." + zone["name"].rstrip(".").lower(), "")
            if ip:
                existing = dbmod.query(db, "SELECT id FROM records WHERE zone_id=? AND name=? AND rtype='A'",
                                       (zone["id"], relative), one=True)
                if existing:
                    dbmod.execute(db, "UPDATE records SET data_json=? WHERE id=?",
                                  (json.dumps({"address": ip}), existing["id"]))
                else:
                    dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                                  (zone["id"], relative, "A", 60, json.dumps({"address": ip})))
    srv = get_dns_server()
    if srv:
        srv.resolver.cache.clear()
    return jsonify({"ok": True, "hostname": hostname, "ip": ip, "ipv6": ipv6})


@bp.route("/docs")
def docs():
    return jsonify({
        "info": "NovaDNS REST API — reference",
        "endpoints": {
            "GET /api/v1/zones": "List all zones (session auth required)",
            "GET /api/v1/zones/<id>/records": "List records for a zone (session auth required)",
            "GET /api/v1/dyndns/update": "Dynamic DNS update: ?hostname=&token=&ip=&ipv6= (token auth)",
        },
    })
