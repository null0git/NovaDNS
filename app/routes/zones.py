import json
import time
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from .. import db as dbmod
from ..auth import login_required, audit
from .. import get_dns_server
from ..dnscore import zonesigning

bp = Blueprint("zones", __name__, url_prefix="/zones")

RTYPE_FIELDS = {
    "A": ["address"], "AAAA": ["address"], "CNAME": ["target"], "NS": ["target"], "PTR": ["target"],
    "MX": ["priority", "target"], "TXT": ["text"],
    "SRV": ["priority", "weight", "port", "target"], "CAA": ["flags", "tag", "value"],
    "NAPTR": ["order", "preference", "flags", "service", "regexp", "replacement"],
    "TLSA": ["usage", "selector", "matching_type", "cert_data"],
    "SSHFP": ["algorithm", "fp_type", "fingerprint"],
    "DS": ["key_tag", "algorithm", "digest_type", "digest"],
    "HTTPS": ["priority", "target", "alpn", "port", "ipv4hint", "ipv6hint"],
}
# Fields that are optional even though listed above (HTTPS's SvcParams are all optional).
OPTIONAL_FIELDS = {"HTTPS": {"alpn", "port", "ipv4hint", "ipv6hint"}}


ZONE_TEMPLATES = {
    "blank": {"label": "Blank (NS only)", "records": []},
    "basic_web": {"label": "Basic web hosting", "records": [
        {"name": "@", "rtype": "A", "fields": {"address": "{IP}"}},
        {"name": "www", "rtype": "A", "fields": {"address": "{IP}"}},
    ]},
    "web_and_mail": {"label": "Web + mail", "records": [
        {"name": "@", "rtype": "A", "fields": {"address": "{IP}"}},
        {"name": "www", "rtype": "A", "fields": {"address": "{IP}"}},
        {"name": "mail", "rtype": "A", "fields": {"address": "{IP}"}},
        {"name": "@", "rtype": "MX", "fields": {"priority": 10, "target": "mail.{ZONE}."}},
        {"name": "@", "rtype": "TXT", "fields": {"text": "v=spf1 mx ~all"}},
    ]},
    "internal_service": {"label": "Internal-only service (no public record)", "records": [
        {"name": "@", "rtype": "A", "fields": {"address": "{IP}"}, "client_match": "{ACL}"},
    ]},
}


def _bust_cache():
    srv = get_dns_server()
    if srv:
        srv.resolver.cache.clear()


def _resign_if_enabled(db, zone_id):
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if zone and zone["dnssec_enabled"]:
        zonesigning.sign_zone(db, zone)


@bp.route("/<int:zone_id>/dnssec/sign", methods=["POST"])
@login_required
def dnssec_sign(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    result = zonesigning.sign_zone(db, zone)
    audit(f"Signed zone '{zone['name']}' with DNSSEC (key tag {result['key_tag']})", "dns")
    _bust_cache()
    return jsonify({"ok": True, **result})


@bp.route("/<int:zone_id>/dnssec/status")
@login_required
def dnssec_status(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    key = dbmod.query(db, "SELECT * FROM dnssec_keys WHERE zone_id=?", (zone_id,), one=True)
    if not key:
        return jsonify({"signed": False})
    rrsig_count = dbmod.query(db, "SELECT COUNT(*) c FROM records WHERE zone_id=? AND rtype='RRSIG'",
                               (zone_id,), one=True)["c"]
    return jsonify({
        "signed": bool(zone["dnssec_enabled"]),
        "key_tag": key["key_tag"], "algorithm": key["algorithm"], "flags": key["flags"],
        "ds_digest_sha256": key["ds_digest_sha256"], "rrsig_count": rrsig_count,
        "ds_record_text": f"{zone['name'].rstrip('.')} IN DS {key['key_tag']} {key['algorithm']} 2 {key['ds_digest_sha256']}",
    })


@bp.route("/")
@login_required
def list_zones():
    db = dbmod.get_db()
    zones = dbmod.query(db, """
        SELECT z.*, (SELECT COUNT(*) FROM records r WHERE r.zone_id = z.id) AS record_count
        FROM zones z ORDER BY z.name""")
    return render_template("zones/list.html", zones=zones)


@bp.route("/simple", methods=["GET", "POST"])
@login_required
def simple_mode():
    db = dbmod.get_db()
    if request.method == "POST":
        domain = request.form.get("domain", "").strip().rstrip(".")
        ip = request.form.get("ip", "").strip()
        ttl = int(request.form.get("ttl", 3600))
        rtype = "AAAA" if ":" in ip else "A"
        if dbmod.query(db, "SELECT id FROM zones WHERE name=?", (domain,), one=True):
            return render_template("zones/simple.html", error="A zone for this domain already exists.")
        zone_id = dbmod.execute(db, """INSERT INTO zones (name, default_ttl, soa_mname, soa_rname)
                                        VALUES (?,?,?,?)""",
                                 (domain, ttl, f"ns1.{domain}.", f"admin.{domain}."))
        dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                      (zone_id, "@", rtype, ttl, json.dumps({"address": ip})))
        dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                      (zone_id, "www", rtype, ttl, json.dumps({"address": ip})))
        audit(f"Created zone '{domain}' via Simple DNS Mode", "dns", f"ip={ip}")
        _bust_cache()
        return redirect(url_for("zones.detail", zone_id=zone_id))
    return render_template("zones/simple.html")


@bp.route("/reverse/new", methods=["GET", "POST"])
@login_required
def new_reverse_zone():
    import ipaddress
    db = dbmod.get_db()
    if request.method == "POST":
        network = request.form.get("network", "").strip()
        ttl = int(request.form.get("default_ttl", 3600))
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return render_template("zones/reverse_new.html", error=f"'{network}' isn't a valid network (e.g. 10.0.0.0/24).")
        zone_name = _reverse_zone_name(net)
        if not zone_name:
            return render_template("zones/reverse_new.html",
                                   error="Only networks that align to a /8, /16, or /24 (IPv4) or a nibble boundary (IPv6) are supported for automatic reverse-zone naming.")
        if dbmod.query(db, "SELECT id FROM zones WHERE name=?", (zone_name,), one=True):
            return render_template("zones/reverse_new.html", error=f"A reverse zone for this network ('{zone_name}') already exists.")
        zone_id = dbmod.execute(db, """INSERT INTO zones (name, default_ttl, soa_mname, soa_rname)
                                        VALUES (?,?,?,?)""",
                                 (zone_name, ttl, f"ns1.{zone_name}.", f"admin.{zone_name}."))
        dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                      (zone_id, "@", "NS", ttl, json.dumps({"target": f"ns1.{zone_name}."})))
        audit(f"Created reverse DNS zone '{zone_name}' for {network}", "dns")
        _bust_cache()
        return redirect(url_for("zones.detail", zone_id=zone_id))
    return render_template("zones/reverse_new.html")


def _reverse_zone_name(net):
    """Computes the conventional in-addr.arpa / ip6.arpa zone name for a
    network aligned to a standard boundary. Returns None for prefixes we
    can't name unambiguously (e.g. a /27 doesn't map to a whole
    in-addr.arpa zone -- that needs classless delegation, out of scope)."""
    import ipaddress
    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen == 24:
            octets = str(net.network_address).split(".")
            return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        if net.prefixlen == 16:
            octets = str(net.network_address).split(".")
            return f"{octets[1]}.{octets[0]}.in-addr.arpa"
        if net.prefixlen == 8:
            octets = str(net.network_address).split(".")
            return f"{octets[0]}.in-addr.arpa"
        return None
    if isinstance(net, ipaddress.IPv6Network):
        if net.prefixlen % 4 != 0:
            return None
        nibbles = net.network_address.exploded.replace(":", "")
        keep = net.prefixlen // 4
        return ".".join(reversed(nibbles[:keep])) + ".ip6.arpa"
    return None


@bp.route("/<int:zone_id>/reverse/add-ptr", methods=["POST"])
@login_required
def add_ptr_convenience(zone_id):
    """Convenience form for reverse zones: enter a host number (last
    octet, or last nibble-group for IPv6) and a target hostname instead
    of hand-building the PTR owner name."""
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    body = request.get_json(force=True)
    host_part = str(body.get("host_part", "")).strip()
    target = body.get("target", "").strip().rstrip(".") + "."
    ttl = body.get("ttl")
    if not host_part or not target:
        return jsonify({"error": "Both the host number and target hostname are required"}), 400
    rec_id = dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                            (zone_id, host_part, "PTR", int(ttl) if ttl else None, json.dumps({"target": target})))
    dbmod.execute(db, "UPDATE zones SET updated_at=datetime('now'), soa_serial=soa_serial+1 WHERE id=?", (zone_id,))
    audit(f"Added PTR record '{host_part}' -> '{target}' in zone '{zone['name']}'", "dns")
    _resign_if_enabled(db, zone_id)
    _bust_cache()
    return jsonify({"ok": True, "id": rec_id})


@bp.route("/<int:zone_id>/records/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_records(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    body = request.get_json(force=True)
    ids = [int(i) for i in body.get("ids", [])]
    if not ids:
        return jsonify({"error": "No records selected"}), 400
    placeholders = ",".join("?" * len(ids))
    dbmod.execute(db, f"DELETE FROM records WHERE zone_id=? AND id IN ({placeholders})", (zone_id, *ids))
    dbmod.execute(db, "UPDATE zones SET updated_at=datetime('now'), soa_serial=soa_serial+1 WHERE id=?", (zone_id,))
    audit(f"Bulk-deleted {len(ids)} record(s) from zone '{zone['name']}'", "dns")
    _resign_if_enabled(db, zone_id)
    _bust_cache()
    return jsonify({"ok": True, "deleted": len(ids)})


@bp.route("/<int:zone_id>/records/bulk-ttl", methods=["POST"])
@login_required
def bulk_set_ttl(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    body = request.get_json(force=True)
    ids = [int(i) for i in body.get("ids", [])]
    ttl = body.get("ttl")
    if not ids or ttl in (None, ""):
        return jsonify({"error": "Select records and provide a TTL"}), 400
    placeholders = ",".join("?" * len(ids))
    dbmod.execute(db, f"UPDATE records SET ttl=? WHERE zone_id=? AND id IN ({placeholders})", (int(ttl), zone_id, *ids))
    dbmod.execute(db, "UPDATE zones SET updated_at=datetime('now'), soa_serial=soa_serial+1 WHERE id=?", (zone_id,))
    audit(f"Bulk-set TTL to {ttl} for {len(ids)} record(s) in zone '{zone['name']}'", "dns")
    _resign_if_enabled(db, zone_id)
    _bust_cache()
    return jsonify({"ok": True, "updated": len(ids)})


@bp.route("/templates")
@login_required
def list_templates():
    return jsonify({k: v["label"] for k, v in ZONE_TEMPLATES.items()})


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new_zone():
    db = dbmod.get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip().rstrip(".")
        ttl = int(request.form.get("default_ttl", 3600))
        template_id = request.form.get("template", "blank")
        ip = request.form.get("template_ip", "").strip()
        acl = request.form.get("template_acl", "").strip()
        zone_id = dbmod.execute(db, """INSERT INTO zones (name, default_ttl, soa_mname, soa_rname)
                                        VALUES (?,?,?,?)""",
                                 (name, ttl, f"ns1.{name}.", f"admin.{name}."))
        dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                      (zone_id, "@", "NS", ttl, json.dumps({"target": f"ns1.{name}."})))
        template = ZONE_TEMPLATES.get(template_id, ZONE_TEMPLATES["blank"])
        for rec in template["records"]:
            fields = {}
            for k, v in rec["fields"].items():
                fields[k] = v.replace("{IP}", ip).replace("{ZONE}", name) if isinstance(v, str) else v
            client_match = rec.get("client_match", "").replace("{ACL}", acl) or None
            client_match = client_match if client_match and client_match != "" else None
            dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json, client_match) VALUES (?,?,?,?,?,?)",
                          (zone_id, rec["name"], rec["rtype"], ttl, json.dumps(fields), client_match))
        audit(f"Created zone '{name}' from template '{template_id}'", "dns")
        _bust_cache()
        return redirect(url_for("zones.detail", zone_id=zone_id))
    return render_template("zones/new.html", templates=ZONE_TEMPLATES)


@bp.route("/<int:zone_id>")
@login_required
def detail(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return redirect(url_for("zones.list_zones"))
    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? ORDER BY name, rtype", (zone_id,))
    records = [dict(r, data=json.loads(r["data_json"])) for r in records]
    return render_template("zones/detail.html", zone=zone, records=records, rtype_fields=RTYPE_FIELDS)


@bp.route("/<int:zone_id>/soa", methods=["POST"])
@login_required
def update_soa(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    body = request.get_json(force=True)
    dbmod.execute(db, """UPDATE zones SET soa_mname=?, soa_rname=?, soa_refresh=?, soa_retry=?,
                          soa_expire=?, soa_minimum=?, soa_serial=soa_serial+1, updated_at=datetime('now')
                          WHERE id=?""",
                  (body.get("mname", zone["soa_mname"]), body.get("rname", zone["soa_rname"]),
                   int(body.get("refresh", zone["soa_refresh"])), int(body.get("retry", zone["soa_retry"])),
                   int(body.get("expire", zone["soa_expire"])), int(body.get("minimum", zone["soa_minimum"])),
                   zone_id))
    audit(f"Updated SOA for zone '{zone['name']}'", "dns")
    _resign_if_enabled(db, zone_id)
    _bust_cache()
    return jsonify({"ok": True})


@bp.route("/<int:zone_id>/delete", methods=["POST"])
@login_required
def delete_zone(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    dbmod.execute(db, "DELETE FROM zones WHERE id=?", (zone_id,))
    if zone:
        audit(f"Deleted zone '{zone['name']}'", "dns")
    _bust_cache()
    return jsonify({"ok": True})


@bp.route("/<int:zone_id>/records", methods=["POST"])
@login_required
def add_record(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    body = request.get_json(force=True)
    rtype = body.get("rtype")
    name = body.get("name", "@").strip() or "@"
    ttl = body.get("ttl")
    client_match = body.get("client_match", "").strip() or None
    fields = RTYPE_FIELDS.get(rtype)
    if not fields:
        return jsonify({"error": f"Unsupported record type: {rtype}"}), 400
    data = {f: body.get(f) for f in fields if body.get(f) not in (None, "")}
    optional = OPTIONAL_FIELDS.get(rtype, set()) | {"raw_hex"}
    missing = [f for f in fields if f not in data and f not in optional]
    if missing:
        return jsonify({"error": f"Missing required field(s): {', '.join(missing)}"}), 400
    rec_id = dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json, client_match) VALUES (?,?,?,?,?,?)",
                            (zone_id, name, rtype, int(ttl) if ttl else None, json.dumps(data), client_match))
    dbmod.execute(db, "UPDATE zones SET updated_at=datetime('now'), soa_serial=soa_serial+1 WHERE id=?", (zone_id,))
    audit(f"Added {rtype} record '{name}' to zone '{zone['name']}'", "dns", json.dumps(data))
    _resign_if_enabled(db, zone_id)
    _bust_cache()
    return jsonify({"ok": True, "id": rec_id})


@bp.route("/records/<int:record_id>", methods=["DELETE"])
@login_required
def delete_record(record_id):
    db = dbmod.get_db()
    rec = dbmod.query(db, "SELECT * FROM records WHERE id=?", (record_id,), one=True)
    if rec:
        dbmod.execute(db, "DELETE FROM records WHERE id=?", (record_id,))
        dbmod.execute(db, "UPDATE zones SET updated_at=datetime('now'), soa_serial=soa_serial+1 WHERE id=?", (rec["zone_id"],))
        audit(f"Deleted {rec['rtype']} record '{rec['name']}'", "dns")
        _resign_if_enabled(db, rec["zone_id"])
    _bust_cache()
    return jsonify({"ok": True})


@bp.route("/<int:zone_id>/export.json")
@login_required
def export_json(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=?", (zone_id,))
    payload = {
        "zone": {k: zone[k] for k in zone.keys()},
        "records": [{"name": r["name"], "rtype": r["rtype"], "ttl": r["ttl"],
                     "data": json.loads(r["data_json"]), "client_match": r["client_match"]} for r in records],
    }
    from flask import Response
    return Response(json.dumps(payload, indent=2), mimetype="application/json",
                     headers={"Content-Disposition": f"attachment; filename={zone['name']}.json"})


@bp.route("/<int:zone_id>/export.csv")
@login_required
def export_csv(zone_id):
    import csv, io
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=?", (zone_id,))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "rtype", "ttl", "data_json", "client_match"])
    for r in records:
        writer.writerow([r["name"], r["rtype"], r["ttl"] or "", r["data_json"], r["client_match"] or ""])
    from flask import Response
    return Response(buf.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": f"attachment; filename={zone['name']}.csv"})


@bp.route("/<int:zone_id>/export.yaml")
@login_required
def export_yaml(zone_id):
    import yaml
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=?", (zone_id,))
    payload = {
        "zone": zone["name"], "default_ttl": zone["default_ttl"],
        "records": [{"name": r["name"], "rtype": r["rtype"], "ttl": r["ttl"],
                     "data": json.loads(r["data_json"]), "client_match": r["client_match"]} for r in records],
    }
    from flask import Response
    return Response(yaml.dump(payload, sort_keys=False), mimetype="text/yaml",
                     headers={"Content-Disposition": f"attachment; filename={zone['name']}.yaml"})


@bp.route("/<int:zone_id>/import", methods=["POST"])
@login_required
def import_records(zone_id):
    import csv, io
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400
    filename = file.filename.lower()
    text = file.read().decode("utf-8", errors="ignore")
    imported = 0
    try:
        if filename.endswith(".json"):
            payload = json.loads(text)
            rows = payload.get("records", payload if isinstance(payload, list) else [])
        elif filename.endswith(".csv"):
            rows = []
            for row in csv.DictReader(io.StringIO(text)):
                rows.append({"name": row["name"], "rtype": row["rtype"],
                              "ttl": int(row["ttl"]) if row.get("ttl") else None,
                              "data": json.loads(row["data_json"]), "client_match": row.get("client_match") or None})
        elif filename.endswith((".yaml", ".yml")):
            import yaml
            payload = yaml.safe_load(text)
            rows = payload.get("records", [])
        else:
            return jsonify({"error": "Use .json, .csv, or .yaml"}), 400

        for row in rows:
            dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json, client_match) VALUES (?,?,?,?,?,?)",
                          (zone_id, row["name"], row["rtype"], row.get("ttl"),
                           json.dumps(row["data"]), row.get("client_match")))
            imported += 1
        dbmod.execute(db, "UPDATE zones SET soa_serial=soa_serial+1, updated_at=datetime('now') WHERE id=?", (zone_id,))
        audit(f"Imported {imported} record(s) into zone '{zone['name']}' from {filename}", "dns")
        _resign_if_enabled(db, zone_id)
        _bust_cache()
        return jsonify({"ok": True, "imported": imported})
    except Exception as e:
        return jsonify({"error": f"Import failed: {e}"}), 400


@bp.route("/<int:zone_id>/export")
@login_required
def export_zone(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=?", (zone_id,))
    lines = [f"$ORIGIN {zone['name']}.", f"$TTL {zone['default_ttl']}",
             f"@ IN SOA {zone['soa_mname']} {zone['soa_rname']} ({zone['soa_serial']} {zone['soa_refresh']} "
             f"{zone['soa_retry']} {zone['soa_expire']} {zone['soa_minimum']})"]
    for r in records:
        data = json.loads(r["data_json"])
        rdata = " ".join(str(v) for v in data.values())
        lines.append(f"{r['name']} {r['ttl'] or zone['default_ttl']} IN {r['rtype']} {rdata}")
    text = "\n".join(lines) + "\n"
    from flask import Response
    return Response(text, mimetype="text/plain",
                     headers={"Content-Disposition": f"attachment; filename={zone['name']}.zone"})


@bp.route("/<int:zone_id>/validate")
@login_required
def validate_zone(zone_id):
    db = dbmod.get_db()
    zone = dbmod.query(db, "SELECT * FROM zones WHERE id=?", (zone_id,), one=True)
    if not zone:
        return jsonify({"error": "Zone not found"}), 404
    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=?", (zone_id,))
    parsed = [dict(r, data=json.loads(r["data_json"])) for r in records]
    issues = []

    def add(level, message, severity=None):
        issues.append({"level": level, "message": message})

    # --- Empty zone
    if not parsed:
        add("high", "Zone has no records at all besides the implicit SOA.")

    # --- NS at apex
    apex_ns = [r for r in parsed if r["name"] == "@" and r["rtype"] == "NS"]
    if not apex_ns:
        add("high", "Zone has no NS records at the apex — resolvers won't know who's authoritative.")

    # --- Duplicate records (same name+rtype+data+client_match)
    seen = {}
    for r in parsed:
        key = (r["name"], r["rtype"], r["data_json"], r["client_match"])
        seen.setdefault(key, []).append(r)
    for key, rows in seen.items():
        if len(rows) > 1:
            add("low", f"Duplicate {key[1]} record for '{key[0]}' appears {len(rows)} times.")

    # --- Apex CNAME conflict (RFC 1034: CNAME can't coexist with other records at the same name)
    by_name = {}
    for r in parsed:
        by_name.setdefault(r["name"], []).append(r)
    for name, rows in by_name.items():
        types_here = {r["rtype"] for r in rows}
        if "CNAME" in types_here and len(types_here) > 1:
            add("critical", f"'{name}' has a CNAME alongside other record types ({', '.join(types_here - {'CNAME'})}) — not allowed per RFC 1034/2181.")

    # --- Circular CNAME chains
    cname_map = {r["name"]: r["data"].get("target", "").rstrip(".").lower() for r in parsed if r["rtype"] == "CNAME"}
    zone_suffix = zone["name"].rstrip(".").lower()
    for start in cname_map:
        seen_chain, cur = set(), start
        while True:
            if cur in seen_chain:
                add("critical", f"Circular CNAME chain detected starting at '{start}'.")
                break
            seen_chain.add(cur)
            target = cname_map.get(cur)
            if not target:
                break
            # only chase within this zone; a target that leaves the zone is fine (external CNAME)
            if target == zone_suffix:
                rel = "@"
            elif target.endswith("." + zone_suffix):
                rel = target[: -(len(zone_suffix) + 1)]
            else:
                break
            cur = rel
            if len(seen_chain) > 20:
                break

    # --- MX target must not itself be a CNAME (RFC 2181 §10.3)
    cname_names = {r["name"] for r in parsed if r["rtype"] == "CNAME"}
    for r in parsed:
        if r["rtype"] == "MX":
            target = r["data"].get("target", "").rstrip(".").lower()
            target_rel = target[: -(len(zone_suffix) + 1)] if target.endswith("." + zone_suffix) else None
            if target_rel and target_rel in cname_names:
                add("high", f"MX record for '{r['name']}' points to '{target}', which is a CNAME — not allowed.")
            if not r["data"].get("target"):
                add("critical", f"MX record for '{r['name']}' has no target.")

    # --- SRV must have a target
    for r in parsed:
        if r["rtype"] == "SRV" and not r["data"].get("target"):
            add("critical", f"SRV record for '{r['name']}' has no target.")

    # --- Invalid TTLs
    for r in parsed:
        if r["ttl"] is not None and (r["ttl"] < 0 or r["ttl"] > 2147483647):
            add("medium", f"Record '{r['name']}' ({r['rtype']}) has an out-of-range TTL: {r['ttl']}.")
        if r["ttl"] == 0:
            add("low", f"Record '{r['name']}' ({r['rtype']}) has TTL=0 — every resolver will re-query on every lookup.")

    # --- A/AAAA address validity
    import ipaddress
    for r in parsed:
        if r["rtype"] == "A" and "address" in r["data"]:
            try:
                ipaddress.IPv4Address(r["data"]["address"])
            except ValueError:
                add("critical", f"Invalid IPv4 address for '{r['name']}': {r['data']['address']}")
        if r["rtype"] == "AAAA" and "address" in r["data"]:
            try:
                ipaddress.IPv6Address(r["data"]["address"])
            except ValueError:
                add("critical", f"Invalid IPv6 address for '{r['name']}': {r['data']['address']}")

    # --- Missing glue: NS delegation to a name inside this zone with no A/AAAA record
    for r in parsed:
        if r["rtype"] == "NS" and r["name"] != "@":
            target = r["data"].get("target", "").rstrip(".").lower()
            if target.endswith("." + zone_suffix) or target == zone_suffix:
                target_rel = "@" if target == zone_suffix else target[: -(len(zone_suffix) + 1)]
                has_glue = any(x["name"] == target_rel and x["rtype"] in ("A", "AAAA") for x in parsed)
                if not has_glue:
                    add("high", f"Delegation NS for '{r['name']}' points to in-zone name '{target}' with no glue A/AAAA record.")

    # --- SOA timer sanity (RFC 1035 §3.3.13 conventional relationship: retry < refresh < expire)
    if zone["soa_retry"] >= zone["soa_refresh"]:
        add("medium", f"SOA retry ({zone['soa_retry']}) should be smaller than refresh ({zone['soa_refresh']}).")
    if zone["soa_refresh"] >= zone["soa_expire"]:
        add("medium", f"SOA refresh ({zone['soa_refresh']}) should be smaller than expire ({zone['soa_expire']}).")
    if zone["soa_minimum"] > 86400:
        add("low", f"SOA minimum/negative-TTL ({zone['soa_minimum']}s) is unusually high.")

    # --- DNSSEC consistency
    if zone["dnssec_enabled"]:
        key = dbmod.query(db, "SELECT * FROM dnssec_keys WHERE zone_id=?", (zone_id,), one=True)
        rrsig_count = dbmod.query(db, "SELECT COUNT(*) c FROM records WHERE zone_id=? AND rtype='RRSIG'", (zone_id,), one=True)["c"]
        if not key:
            add("critical", "Zone is marked DNSSEC-enabled but has no signing key.")
        if rrsig_count == 0:
            add("high", "Zone is DNSSEC-enabled but has no RRSIGs — re-sign the zone.")

    # --- wildcard note (informational, not necessarily a problem)
    if any(r["name"] == "*" for r in parsed):
        add("info", "Zone uses a wildcard record — remember wildcards don't match names that already have their own records, or names one label below an existing delegation.")

    if not issues:
        issues = [{"level": "ok", "message": "No issues found."}]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}
    issues.sort(key=lambda i: severity_order.get(i["level"], 9))
    counts = {}
    for i in issues:
        counts[i["level"]] = counts.get(i["level"], 0) + 1
    return jsonify({"issues": issues, "counts": counts})
