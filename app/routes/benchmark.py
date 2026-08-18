from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required, audit
from .. import get_dns_server
from ..utils import benchmark as bench_mod

bp = Blueprint("benchmark", __name__, url_prefix="/benchmark")


@bp.route("/")
@login_required
def index():
    db = dbmod.get_db()
    runs = dbmod.query(db, "SELECT * FROM benchmarks ORDER BY run_at DESC LIMIT 25")
    return render_template("benchmark.html", runs=runs)


@bp.route("/run", methods=["POST"])
@login_required
def run():
    db = dbmod.get_db()
    body = request.get_json(force=True) or {}
    target = body.get("target", "example.com.")
    qtype = body.get("qtype", "A")
    total = int(body.get("total", 500))
    concurrency = int(body.get("concurrency", 20))

    srv = get_dns_server()
    if not srv:
        return jsonify({"error": "DNS server not available"}), 500

    result = bench_mod.run_benchmark(srv.resolver, target, qtype, total, concurrency)
    tips = bench_mod.recommendations(result)

    dbmod.execute(db, """INSERT INTO benchmarks
        (queries, duration_sec, qps, avg_latency_ms, p95_latency_ms, p99_latency_ms, cache_hit_ratio, notes)
        VALUES (?,?,?,?,?,?,?,?)""",
        (result["queries"], result["duration_sec"], result["qps"], result["avg_latency_ms"],
         result["p95_latency_ms"], result["p99_latency_ms"], result["cache_hit_ratio"], "; ".join(tips)))
    audit(f"Ran benchmark: {result['qps']} qps, {result['avg_latency_ms']}ms avg", "benchmark")
    return jsonify({"ok": True, **result, "recommendations": tips})
