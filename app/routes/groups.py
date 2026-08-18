from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required, audit

bp = Blueprint("groups", __name__, url_prefix="/groups")


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    groups = dbmod.query(db, "SELECT * FROM client_groups ORDER BY name")
    result = []
    for g in groups:
        entries = dbmod.query(db, "SELECT * FROM client_group_entries WHERE group_id=?", (g["id"],))
        result.append({"group": g, "entries": entries})
    return render_template("groups.html", groups=result)


@bp.route("/add", methods=["POST"])
@login_required
def add():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    name = body.get("name", "").strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400
    if dbmod.query(db, "SELECT id FROM client_groups WHERE name=?", (name,), one=True):
        return jsonify({"error": "A group with this name already exists"}), 400
    gid = dbmod.execute(db, "INSERT INTO client_groups (name, description) VALUES (?,?)",
                         (name, body.get("description", "")))
    audit(f"Created client group '{name}'", "groups")
    return jsonify({"ok": True, "id": gid})


@bp.route("/<int:gid>/delete", methods=["POST"])
@login_required
def delete(gid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM client_groups WHERE id=?", (gid,))
    audit(f"Deleted client group #{gid}", "groups")
    return jsonify({"ok": True})


@bp.route("/<int:gid>/entries/add", methods=["POST"])
@login_required
def add_entry(gid):
    db = dbmod.get_db()
    body = request.get_json(force=True)
    cidr = body.get("cidr_or_ip", "").strip()
    if not cidr:
        return jsonify({"error": "CIDR or IP is required"}), 400
    eid = dbmod.execute(db, "INSERT INTO client_group_entries (group_id, cidr_or_ip) VALUES (?,?)", (gid, cidr))
    audit(f"Added {cidr} to client group #{gid}", "groups")
    return jsonify({"ok": True, "id": eid})


@bp.route("/entries/<int:eid>/delete", methods=["POST"])
@login_required
def delete_entry(eid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM client_group_entries WHERE id=?", (eid,))
    return jsonify({"ok": True})
