import os
import json
import secrets
from flask import Blueprint, render_template, request, jsonify, send_from_directory, current_app
from .. import db as dbmod
from ..auth import login_required, audit, hash_password
from ..utils.health import get_setting, set_setting
from ..utils import backup as backup_mod
from ..utils import notify as notify_mod
from .. import get_dns_server

bp = Blueprint("settings", __name__, url_prefix="/settings")

CHANNELS = ["email", "discord", "slack", "telegram", "webhook"]


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    settings_rows = {r["key"]: r["value"] for r in dbmod.query(db, "SELECT * FROM settings")}
    backups = dbmod.query(db, "SELECT * FROM backups ORDER BY created_at DESC")
    maintenance = dbmod.query(db, "SELECT * FROM maintenance WHERE id=1", one=True)
    notif = {r["channel"]: r for r in dbmod.query(db, "SELECT * FROM notification_channels")}
    users = dbmod.query(db, "SELECT id, username, role, created_at, last_login FROM users")
    dyndns = dbmod.query(db, "SELECT * FROM dyndns_hosts")
    zones = dbmod.query(db, "SELECT id, name FROM zones")
    return render_template("settings/index.html", s=settings_rows, backups=backups, maintenance=maintenance,
                           notif=notif, channels=CHANNELS, users=users, dyndns=dyndns, zones=zones)


@bp.route("/network", methods=["POST"])
@login_required
def network():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    set_setting(db, "dns_bind_addr", body.get("bind_addr", "0.0.0.0"))
    set_setting(db, "dns_port", body.get("dns_port", "53"))
    set_setting(db, "acl_networks", body.get("acl_networks", ""))
    set_setting(db, "axfr_allowed_clients", body.get("axfr_allowed_clients", ""))
    audit("Updated network/ACL settings (takes effect after restart)", "settings")
    return jsonify({"ok": True})


@bp.route("/ratelimit", methods=["POST"])
@login_required
def ratelimit():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    capacity = int(body.get("capacity", 200))
    refill = int(body.get("refill_per_sec", 100))
    set_setting(db, "ratelimit_capacity", capacity)
    set_setting(db, "ratelimit_refill", refill)
    srv = get_dns_server()
    if srv:
        srv.rate_limiter.configure(capacity, refill)
    audit(f"Updated rate limit to {refill} qps (burst {capacity})", "settings")
    return jsonify({"ok": True})


@bp.route("/branding/logo", methods=["POST"])
@login_required
def upload_logo():
    db = dbmod.get_db()
    file = request.files.get("logo")
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("png", "jpg", "jpeg", "svg", "webp"):
        return jsonify({"error": "Use PNG, JPG, WEBP, or SVG"}), 400
    brand_dir = os.path.join(current_app.config["BASE_DIR"], "data", "branding")
    os.makedirs(brand_dir, exist_ok=True)
    # remove any previous logo (any extension) before saving the new one
    for f in os.listdir(brand_dir):
        if f.startswith("logo."):
            os.remove(os.path.join(brand_dir, f))
    path = os.path.join(brand_dir, f"logo.{ext}")
    file.save(path)
    set_setting(db, "logo_ext", ext)
    audit("Uploaded a custom logo", "settings")
    return jsonify({"ok": True})


@bp.route("/branding/logo/remove", methods=["POST"])
@login_required
def remove_logo():
    db = dbmod.get_db()
    ext = get_setting(db, "logo_ext")
    if ext:
        path = os.path.join(current_app.config["BASE_DIR"], "data", "branding", f"logo.{ext}")
        if os.path.exists(path):
            os.remove(path)
    set_setting(db, "logo_ext", "")
    audit("Removed custom logo", "settings")
    return jsonify({"ok": True})


@bp.route("/general", methods=["POST"])
@login_required
def general():
    db = dbmod.get_db()
    body = request.form
    set_setting(db, "site_name", body.get("site_name", "NovaDNS"))
    set_setting(db, "accent_color", body.get("accent_color", "#4C8CFF"))
    set_setting(db, "default_theme", body.get("default_theme", "system"))
    audit("Updated general/branding settings", "settings")
    return jsonify({"ok": True})


@bp.route("/tls/generate", methods=["POST"])
@login_required
def tls_generate():
    from ..utils import tls as tls_mod
    from ..utils import detect
    db = dbmod.get_db()
    body = request.get_json(force=True) or {}
    cert_dir = os.path.join(current_app.config["BASE_DIR"], "data", "tls")
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")
    common_name = body.get("common_name") or "novadns.local"
    result = tls_mod.generate_self_signed_cert(cert_path, key_path, common_name, extra_names=detect.get_local_ips())
    set_setting(db, "https_enabled", "1")
    set_setting(db, "tls_cert_path", cert_path)
    set_setting(db, "tls_key_path", key_path)
    audit("Generated self-signed TLS certificate for the admin UI", "settings")
    return jsonify({"ok": True, **result})


@bp.route("/tls/status")
@login_required
def tls_status():
    from ..utils import tls as tls_mod
    db = dbmod.get_db()
    cert_path = get_setting(db, "tls_cert_path")
    enabled = get_setting(db, "https_enabled") == "1"
    days = tls_mod.cert_expiry_days(cert_path) if cert_path else None
    return jsonify({"enabled": enabled, "cert_exists": bool(cert_path and os.path.exists(cert_path)),
                     "expiry_days": days})


@bp.route("/tls/disable", methods=["POST"])
@login_required
def tls_disable():
    db = dbmod.get_db()
    set_setting(db, "https_enabled", "0")
    audit("Disabled HTTPS for the admin UI (restart required)", "settings")
    return jsonify({"ok": True})


@bp.route("/backups/create", methods=["POST"])
@login_required
def backup_create():
    db = dbmod.get_db()
    body = request.get_json(force=True) or {}
    password = body.get("password") or None
    result = backup_mod.create_backup(current_app.config["DATABASE_PATH"], current_app.config["BACKUP_DIR"],
                                       btype=body.get("btype", "manual"), password=password)
    dbmod.execute(db, "INSERT INTO backups (filename, btype, size_bytes, encrypted) VALUES (?,?,?,?)",
                  (result["filename"], body.get("btype", "manual"), result["size_bytes"], int(result["encrypted"])))
    audit(f"Created {'encrypted ' if result['encrypted'] else ''}backup {result['filename']}", "backup")
    return jsonify({"ok": True, **result})


@bp.route("/backups/<path:filename>/download")
@login_required
def backup_download(filename):
    return send_from_directory(current_app.config["BACKUP_DIR"], filename, as_attachment=True)


@bp.route("/backups/<path:filename>/delete", methods=["POST"])
@login_required
def backup_delete(filename):
    db = dbmod.get_db()
    path = os.path.join(current_app.config["BACKUP_DIR"], filename)
    if os.path.exists(path):
        os.remove(path)
    dbmod.execute(db, "DELETE FROM backups WHERE filename=?", (filename,))
    audit(f"Deleted backup {filename}", "backup")
    return jsonify({"ok": True})


@bp.route("/maintenance", methods=["POST"])
@login_required
def maintenance():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    exists = dbmod.query(db, "SELECT id FROM maintenance WHERE id=1", one=True)
    if exists:
        dbmod.execute(db, "UPDATE maintenance SET enabled=?, message=?, starts_at=?, ends_at=? WHERE id=1",
                      (int(body.get("enabled", False)), body.get("message", ""),
                       body.get("starts_at") or None, body.get("ends_at") or None))
    else:
        dbmod.execute(db, "INSERT INTO maintenance (id, enabled, message, starts_at, ends_at) VALUES (1,?,?,?,?)",
                      (int(body.get("enabled", False)), body.get("message", ""),
                       body.get("starts_at") or None, body.get("ends_at") or None))
    audit(f"Maintenance mode set to {'ON' if body.get('enabled') else 'OFF'}", "settings")
    get_dns_server().resolver.cache.clear()
    return jsonify({"ok": True})


@bp.route("/notifications/<channel>", methods=["POST"])
@login_required
def notifications(channel):
    if channel not in CHANNELS:
        return jsonify({"error": "unknown channel"}), 400
    db = dbmod.get_db()
    body = request.get_json(force=True)
    config_json = json.dumps(body.get("config", {}))
    exists = dbmod.query(db, "SELECT channel FROM notification_channels WHERE channel=?", (channel,), one=True)
    if exists:
        dbmod.execute(db, "UPDATE notification_channels SET config_json=?, enabled=? WHERE channel=?",
                      (config_json, int(body.get("enabled", False)), channel))
    else:
        dbmod.execute(db, "INSERT INTO notification_channels (channel, config_json, enabled) VALUES (?,?,?)",
                      (channel, config_json, int(body.get("enabled", False))))
    audit(f"Updated {channel} notification settings", "settings")
    return jsonify({"ok": True})


@bp.route("/notifications/<channel>/test", methods=["POST"])
@login_required
def notifications_test(channel):
    if channel not in CHANNELS:
        return jsonify({"error": "unknown channel"}), 400
    db = dbmod.get_db()
    row = dbmod.query(db, "SELECT * FROM notification_channels WHERE channel=?", (channel,), one=True)
    if not row:
        return jsonify({"ok": False, "error": "Save the channel's settings first"}), 400
    config = json.loads(row["config_json"])
    ok, err = notify_mod.dispatch(channel, config, "This is a test notification from NovaDNS.", subject="NovaDNS test")
    return jsonify({"ok": ok, "error": err})


@bp.route("/users/add", methods=["POST"])
@login_required
def add_user():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    if dbmod.query(db, "SELECT id FROM users WHERE username=?", (body["username"],), one=True):
        return jsonify({"error": "Username already exists"}), 400
    dbmod.execute(db, "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                  (body["username"], hash_password(body["password"]), body.get("role", "admin")))
    audit(f"Created user '{body['username']}'", "users")
    return jsonify({"ok": True})


@bp.route("/users/<int:uid>/delete", methods=["POST"])
@login_required
def delete_user(uid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM users WHERE id=?", (uid,))
    audit(f"Deleted user #{uid}", "users")
    return jsonify({"ok": True})


@bp.route("/dyndns/add", methods=["POST"])
@login_required
def dyndns_add():
    db = dbmod.get_db()
    body = request.get_json(force=True)
    token = secrets.token_urlsafe(24)
    hid = dbmod.execute(db, "INSERT INTO dyndns_hosts (hostname, zone_id, token) VALUES (?,?,?)",
                         (body["hostname"], body.get("zone_id") or None, token))
    audit(f"Registered dynamic DNS host '{body['hostname']}'", "dyndns")
    return jsonify({"ok": True, "id": hid, "token": token,
                     "update_url": f"/api/v1/dyndns/update?hostname={body['hostname']}&token={token}&ip=<your-ip>"})


@bp.route("/dyndns/<int:hid>/delete", methods=["POST"])
@login_required
def dyndns_delete(hid):
    db = dbmod.get_db()
    dbmod.execute(db, "DELETE FROM dyndns_hosts WHERE id=?", (hid,))
    return jsonify({"ok": True})
