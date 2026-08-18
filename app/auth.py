import functools
from flask import session, redirect, url_for, request, g
from werkzeug.security import generate_password_hash, check_password_hash
from . import db as dbmod


def hash_password(pw):
    return generate_password_hash(pw)


def verify_password(pw, pw_hash):
    return check_password_hash(pw_hash, pw)


def current_user():
    if "user_id" not in session:
        return None
    if not hasattr(g, "_current_user"):
        db = dbmod.get_db()
        g._current_user = dbmod.query(db, "SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)
    return g._current_user


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        db = dbmod.get_db()
        installed = dbmod.query(db, "SELECT value FROM settings WHERE key='install_complete'", one=True)
        if not installed or installed["value"] != "1":
            return redirect(url_for("install.wizard"))
        if current_user() is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def audit(action, category="general", details=""):
    db = dbmod.get_db()
    user = current_user()
    dbmod.execute(db, "INSERT INTO audit_log (username, action, category, details, ip) VALUES (?,?,?,?,?)",
                  (user["username"] if user else "system", action, category, details,
                   request.remote_addr if request else None))
