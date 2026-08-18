from flask import Blueprint, render_template
from ..auth import login_required

bp = Blueprint("architecture", __name__, url_prefix="/architecture")


@bp.route("/")
@login_required
def index():
    return render_template("architecture.html")
