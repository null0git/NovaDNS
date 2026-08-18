from flask import Blueprint, render_template
from ..auth import login_required

bp = Blueprint("docs", __name__, url_prefix="/docs")


@bp.route("/")
@login_required
def index():
    return render_template("docs.html")
