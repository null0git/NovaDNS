import csv
import io
from flask import Blueprint, render_template, request, Response, jsonify
from .. import db as dbmod
from ..auth import login_required

bp = Blueprint("audit", __name__, url_prefix="/audit")


def _filtered(db):
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    sql = "SELECT * FROM audit_log WHERE 1=1"
    args = []
    if q:
        sql += " AND (action LIKE ? OR details LIKE ? OR username LIKE ?)"
        args += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if category:
        sql += " AND category=?"
        args.append(category)
    sql += " ORDER BY ts DESC LIMIT 500"
    return dbmod.query(db, sql, args)


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    rows = _filtered(db)
    categories = [r["category"] for r in dbmod.query(db, "SELECT DISTINCT category FROM audit_log")]
    return render_template("audit.html", rows=rows, categories=categories,
                           q=request.args.get("q", ""), category=request.args.get("category", ""))


@bp.route("/export.csv")
@login_required
def export_csv():
    db = dbmod.get_db()
    rows = _filtered(db)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "username", "category", "action", "details", "ip"])
    for r in rows:
        writer.writerow([r["ts"], r["username"], r["category"], r["action"], r["details"], r["ip"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": "attachment; filename=novadns-audit-log.csv"})
