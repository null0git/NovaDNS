from flask import Blueprint, render_template, request, jsonify
from ..auth import login_required
from ..dnscore import wire

bp = Blueprint("inspector", __name__, url_prefix="/inspector")


@bp.route("/")
@login_required
def index():
    return render_template("inspector.html")


def _parse_hex(hex_str):
    hex_str = "".join(hex_str.split())
    data = bytes.fromhex(hex_str)
    msg = wire.Message.from_wire(data)

    def rr_dict(rr):
        return {"name": rr.name, "rtype": rr.rtype, "class": rr.rclass, "ttl": rr.ttl, "value": rr.value}

    return {
        "hex": data.hex(),
        "hex_grouped": " ".join(data.hex()[i:i + 2] for i in range(0, len(data.hex()), 2)),
        "binary": " ".join(format(b, "08b") for b in data[:64]) + (" …" if len(data) > 64 else ""),
        "length_bytes": len(data),
        "header": {
            "id": msg.id, "qr": msg.qr, "opcode": msg.opcode, "aa": msg.aa, "tc": msg.tc,
            "rd": msg.rd, "ra": msg.ra, "rcode": msg.rcode,
            "qdcount": len(msg.questions), "ancount": len(msg.answers),
            "nscount": len(msg.authorities), "arcount": len(msg.additionals),
        },
        "questions": [{"name": q.name, "qtype": q.qtype, "qclass": q.qclass} for q in msg.questions],
        "answers": [rr_dict(rr) for rr in msg.answers],
        "authority": [rr_dict(rr) for rr in msg.authorities],
        "additional": [rr_dict(rr) for rr in msg.additionals],
    }


@bp.route("/parse", methods=["POST"])
@login_required
def parse():
    body = request.get_json(force=True)
    try:
        return jsonify({"ok": True, "packet": _parse_hex(body.get("hex", ""))})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.route("/sample/<kind>")
@login_required
def sample(kind):
    """Generates a real sample packet (built with our own encoder) so
    the inspector has something to show without needing a pcap file."""
    m = wire.Message()
    m.id = 0xABCD
    m.rd = 1
    if kind == "query":
        m.questions.append(wire.Question("example.com.", "A"))
    elif kind == "response":
        m.qr = 1
        m.aa = 1
        m.ra = 1
        m.questions.append(wire.Question("example.com.", "A"))
        m.answers.append(wire.ResourceRecord("example.com.", "A", 300, {"address": "93.184.216.34"}))
    elif kind == "dnssec":
        m.qr = 1
        m.aa = 1
        m.questions.append(wire.Question("secure.example.", "A"))
        m.answers.append(wire.ResourceRecord("secure.example.", "A", 300, {"address": "10.0.0.5"}))
        m.additionals.append(wire.ResourceRecord(".", "OPT", 0x00008000, {"raw_hex": ""}, rclass=4096))
    else:
        m.questions.append(wire.Question("example.com.", "MX"))
    return jsonify({"hex": m.to_wire().hex()})
