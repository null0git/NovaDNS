from flask import Blueprint, render_template, jsonify
from ..auth import login_required
from ..utils import detect
from ..utils.device_platforms import PLATFORMS
from .. import get_dns_server

bp = Blueprint("devices", __name__, url_prefix="/devices")


@bp.route("/")
@login_required
def index():
    ips = detect.get_local_ips()
    srv = get_dns_server()
    port = srv.port if srv else 53
    return render_template("devices.html", platforms=PLATFORMS, ips=ips, port=port)


@bp.route("/verify/<ip>")
@login_required
def verify(ip):
    # A lightweight reachability signal: confirm our own resolver answers on that bind IP.
    srv = get_dns_server()
    ok = srv.is_running() if srv else False
    return jsonify({"ok": ok, "ip": ip, "port": srv.port if srv else None})
