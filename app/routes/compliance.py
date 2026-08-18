from flask import Blueprint, render_template, jsonify
import traceback
from ..auth import login_required
from ..utils.testrunner import run_compliance_tests
from ..utils.logsetup import get_logger

bp = Blueprint("compliance", __name__, url_prefix="/compliance")


@bp.route("/")
@login_required
def index():
    return render_template("compliance.html")


@bp.route("/run")
@login_required
def run():
    try:
        result = run_compliance_tests()
        return jsonify(result)
    except Exception as e:
        # Whatever goes wrong here, the frontend must get JSON back --
        # an HTML error page here is what makes the UI hang forever on
        # "Running..." with no visible error.
        import os
        logger = get_logger(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
        logger.error(f"compliance test run failed: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Test run failed: {e}", "rfcs": [], "not_implemented": [],
                        "total_passed": 0, "total_failed": 0, "total_run": 0, "elapsed_sec": 0}), 500
