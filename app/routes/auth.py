from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_from_directory, current_app
import os
from .. import db as dbmod
from ..auth import verify_password, audit
from ..utils.health import get_setting

bp = Blueprint("auth", __name__)


@bp.route("/branding/logo-file")
def logo_file():
    db = dbmod.get_db()
    ext = get_setting(db, "logo_ext")
    if not ext:
        return "", 404
    brand_dir = os.path.join(current_app.config["BASE_DIR"], "data", "branding")
    path = os.path.join(brand_dir, f"logo.{ext}")
    if not os.path.exists(path):
        return "", 404
    return send_from_directory(brand_dir, f"logo.{ext}")


@bp.route("/login", methods=["GET", "POST"])
def login():
    db = dbmod.get_db()
    installed = get_setting(db, "install_complete")
    if installed != "1":
        return redirect(url_for("install.wizard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = dbmod.query(db, "SELECT * FROM users WHERE username=?", (username,), one=True)
        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            dbmod.execute(db, "UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
            audit("Logged in", "security")
            nxt = request.args.get("next") or url_for("dashboard.home")
            return redirect(nxt)
        error = "Incorrect username or password."
        audit(f"Failed login attempt for '{username}'", "security")
    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    audit("Logged out", "security")
    session.clear()
    return redirect(url_for("auth.login"))
