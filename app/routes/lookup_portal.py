import json
import time
import urllib.request
import urllib.error

from flask import Blueprint, render_template, request, jsonify
from .. import get_dns_server

bp = Blueprint("lookup_portal", __name__, url_prefix="/lookup")

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA", "SRV"]
RDAP_TIMEOUT = 5


@bp.route("/")
def index():
    return render_template("lookup_portal.html")


def _rdap_lookup(domain):
    """Best-effort RDAP (RFC 7482/7483) lookup via rdap.org's bootstrap
    redirector. This is genuine external registry data, not something a
    DNS server can know on its own -- if the network can't reach it
    (blocked egress, offline deployment), we say so plainly rather than
    fabricating registrar details."""
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}",
                                      headers={"Accept": "application/rdap+json", "User-Agent": "NovaDNS/4.0"})
        with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        registrar = field[3]
        return {"available": True, "registrar": registrar,
                "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
                "status": data.get("status", [])}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return {"available": False, "error": str(e)}


@bp.route("/search", methods=["POST"])
def search():
    body = request.get_json(force=True)
    domain = body.get("domain", "").strip().rstrip(".").lower()
    if not domain or " " in domain:
        return jsonify({"error": "Enter a valid domain name"}), 400

    srv = get_dns_server()
    records = {}
    total_start = time.time()
    for rtype in RECORD_TYPES:
        start = time.time()
        answers, rcode, source, authority, is_auth, _trace = srv.resolver.resolve(domain + ".", rtype, "127.0.0.1")
        records[rtype] = {
            "rcode": rcode, "source": source, "elapsed_ms": round((time.time() - start) * 1000, 2),
            "values": [{"value": a.value, "ttl": a.ttl} for a in answers],
        }
    total_elapsed = round((time.time() - total_start) * 1000, 2)

    exists = any(r["rcode"] == 0 and r["values"] for r in records.values())
    rdap = _rdap_lookup(domain)

    return jsonify({"domain": domain, "exists": exists, "total_elapsed_ms": total_elapsed,
                     "records": records, "rdap": rdap})
