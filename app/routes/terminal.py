import re
import shutil
import subprocess
from flask import Blueprint, render_template, request, jsonify
from .. import db as dbmod
from ..auth import login_required, audit, current_user
from .. import get_dns_server

bp = Blueprint("terminal", __name__, url_prefix="/terminal")

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,253})[A-Za-z0-9]$|^[A-Za-z0-9]$")
ALLOWED_COMMANDS = {"dig", "nslookup", "ping", "traceroute", "help", "clear"}


def _valid_target(target):
    if len(target) > 255:
        return False
    return bool(HOSTNAME_RE.match(target)) or re.match(r"^[0-9a-fA-F:\.]+$", target)


@bp.route("/")
@login_required
def index():
    return render_template("terminal.html")


@bp.route("/exec", methods=["POST"])
@login_required
def exec_cmd():
    body = request.get_json(force=True)
    line = body.get("command", "").strip()
    if not line:
        return jsonify({"output": ""})
    parts = line.split()
    cmd = parts[0].lower()
    args = parts[1:]

    audit(f"Terminal command: {line}", "terminal")

    if cmd not in ALLOWED_COMMANDS:
        return jsonify({"output": f"novadns-term: '{cmd}' is not permitted. "
                                   f"Allowed: {', '.join(sorted(ALLOWED_COMMANDS))}"})

    if cmd == "help":
        return jsonify({"output": (
            "Available commands:\n"
            "  dig <name> [type]         resolve a name using NovaDNS's own resolver\n"
            "  nslookup <name>           simple lookup, A + AAAA\n"
            "  ping <host>               ICMP reachability test (if supported by the host OS)\n"
            "  traceroute <host>         path trace (if supported by the host OS)\n"
            "  clear                     clear the screen"
        )})

    if cmd == "clear":
        return jsonify({"output": "__CLEAR__"})

    if cmd in ("dig", "nslookup"):
        if not args:
            return jsonify({"output": f"usage: {cmd} <name> [type]"})
        name = args[0]
        qtype = args[1].upper() if len(args) > 1 else "A"
        if not _valid_target(name.rstrip(".")):
            return jsonify({"output": "invalid hostname"})
        srv = get_dns_server()
        answers, rcode, source, authority, is_authoritative, _trace = srv.resolver.resolve(
            name, qtype, "127.0.0.1", dnssec_ok=True)
        aa_flag = "aa " if is_authoritative else ""
        lines = [f"; NovaDNS internal resolver — {cmd} {name} {qtype}",
                 f";; source: {source}  rcode: {rcode}  flags: {aa_flag}rd ra", ""]
        if not answers:
            lines.append(";; no answer")
        for a in answers:
            lines.append(f"{name:<30} {a.ttl:<6} IN {a.rtype:<6} {a.value}")
        if authority:
            lines.append(";; AUTHORITY SECTION:")
            for a in authority:
                lines.append(f"  {a.ttl:<6} IN {a.rtype:<6} {a.value}")
        return jsonify({"output": "\n".join(lines)})

    if cmd in ("ping", "traceroute"):
        if not args or not _valid_target(args[0]):
            return jsonify({"output": "invalid or missing host"})
        binary = shutil.which(cmd)
        if not binary:
            return jsonify({"output": f"'{cmd}' is not available on this host system."})
        host = args[0]
        try:
            count_flag = ["-c", "3"] if cmd == "ping" else []
            result = subprocess.run([binary, *count_flag, host], capture_output=True, text=True, timeout=8)
            return jsonify({"output": (result.stdout or result.stderr or "(no output)")[-4000:]})
        except subprocess.TimeoutExpired:
            return jsonify({"output": f"{cmd}: timed out"})
        except Exception as e:
            return jsonify({"output": f"{cmd}: error — {e}"})

    return jsonify({"output": "unrecognized command"})
