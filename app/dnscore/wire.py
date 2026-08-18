"""
NovaDNS wire protocol layer.

Pure-Python (stdlib-only) implementation of RFC 1035 message
encoding/decoding, plus the common modern record types used by
NovaDNS. No third-party DNS library is used anywhere in this
project - this module IS the DNS engine.
"""
import struct
import ipaddress
import random

# ---------------------------------------------------------------- constants

QTYPE = {
    "A": 1, "NS": 2, "MD": 3, "MF": 4, "CNAME": 5, "SOA": 6, "MB": 7, "MG": 8, "MR": 9,
    "NULL": 10, "WKS": 11, "PTR": 12, "HINFO": 13, "MINFO": 14, "MX": 15, "TXT": 16,
    "RP": 17, "AFSDB": 18, "X25": 19, "ISDN": 20, "RT": 21, "SIG": 24, "KEY": 25,
    "PX": 26, "GPOS": 27, "AAAA": 28, "LOC": 29, "NXT": 30, "SRV": 33, "NAPTR": 35,
    "KX": 36, "CERT": 37, "DNAME": 39, "OPT": 41, "APL": 42, "DS": 43, "SSHFP": 44,
    "IPSECKEY": 45, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "DHCID": 49, "NSEC3": 50,
    "NSEC3PARAM": 51, "TLSA": 52, "SMIMEA": 53, "HIP": 55, "CDS": 59, "CDNSKEY": 60,
    "OPENPGPKEY": 61, "SVCB": 64, "HTTPS": 65, "SPF": 99, "TKEY": 249, "TSIG": 250,
    "IXFR": 251, "AXFR": 252, "MAILB": 253, "MAILA": 254, "ANY": 255, "URI": 256,
    "CAA": 257, "TA": 32768, "DLV": 32769,
}
QTYPE_BY_NUM = {v: k for k, v in QTYPE.items()}


def type_to_num(rtype) -> int:
    """Converts a type name (or already-numeric type, for the many real
    types we don't have a name mapping for) back to its wire number.
    This MUST be symmetric with how decode_name/from_wire represent an
    unrecognized type (as the digit string of its number) -- otherwise
    a query for any less-common type gets its echoed question section
    silently corrupted to ANY (255) in the response, which is exactly
    the kind of mismatch that makes a strict client like nslookup show
    garbled/placeholder output instead of a real answer."""
    if rtype in QTYPE:
        return QTYPE[rtype]
    if isinstance(rtype, str) and rtype.isdigit():
        return int(rtype)
    return 255  # genuinely unrecognized non-numeric type name -- ANY is the only sane fallback

QCLASS_IN = 1

RCODE = {
    "NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3,
    "NOTIMP": 4, "REFUSED": 5,
}


class DNSError(Exception):
    pass


# ------------------------------------------------------------- name codec

def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if name == "":
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        try:
            b = label.encode("idna") if not label.isascii() else label.encode("ascii")
        except UnicodeError:
            b = label.encode("utf-8", errors="ignore")[:63]
        if len(b) > 63:
            raise DNSError(f"label too long: {label}")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def decode_name(msg: bytes, offset: int):
    """Returns (name, new_offset). Follows compression pointers."""
    labels = []
    jumped = False
    start_offset = offset
    seen_pointers = 0
    while True:
        if offset >= len(msg):
            raise DNSError("truncated name")
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                raise DNSError("truncated pointer")
            seen_pointers += 1
            if seen_pointers > 128:
                raise DNSError("compression loop")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                start_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(msg[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    name = ".".join(labels) + "." if labels else "."
    return name, (start_offset if jumped else offset)


# -------------------------------------------------------------- rdata codec

def encode_rdata(rtype: str, value: dict) -> bytes:
    if rtype in ("A",):
        return ipaddress.IPv4Address(value["address"]).packed
    if rtype == "AAAA":
        return ipaddress.IPv6Address(value["address"]).packed
    if rtype in ("CNAME", "NS", "PTR"):
        return encode_name(value["target"])
    if rtype == "MX":
        return struct.pack("!H", int(value["priority"])) + encode_name(value["target"])
    if rtype == "TXT":
        text = value.get("text", "")
        chunks = [text[i:i + 255] for i in range(0, len(text), 255)] or [""]
        out = bytearray()
        for c in chunks:
            b = c.encode("utf-8")
            out.append(len(b))
            out.extend(b)
        return bytes(out)
    if rtype == "SOA":
        return (
            encode_name(value["mname"]) + encode_name(value["rname"]) +
            struct.pack("!IIIII", int(value["serial"]), int(value["refresh"]),
                        int(value["retry"]), int(value["expire"]), int(value["minimum"]))
        )
    if rtype == "SRV":
        return struct.pack("!HHH", int(value["priority"]), int(value["weight"]),
                            int(value["port"])) + encode_name(value["target"])
    if rtype == "CAA":
        tag = value["tag"].encode("ascii")
        return struct.pack("!BB", int(value.get("flags", 0)), len(tag)) + tag + value["value"].encode("ascii")
    if rtype == "NAPTR":
        def s(x): return bytes([len(x)]) + x.encode("ascii")
        return (struct.pack("!HH", int(value.get("order", 0)), int(value.get("preference", 0))) +
                s(value.get("flags", "")) + s(value.get("service", "")) +
                s(value.get("regexp", "")) + encode_name(value.get("replacement", ".")))
    if rtype == "TLSA":
        # RFC 6698 §2.1
        cert_data = bytes.fromhex(value.get("cert_data", ""))
        return struct.pack("!BBB", int(value.get("usage", 3)), int(value.get("selector", 1)),
                            int(value.get("matching_type", 1))) + cert_data
    if rtype == "SSHFP":
        # RFC 4255 §3.1
        fingerprint = bytes.fromhex(value.get("fingerprint", ""))
        return struct.pack("!BB", int(value.get("algorithm", 4)), int(value.get("fp_type", 2))) + fingerprint
    if rtype == "DS":
        # RFC 4034 §5.1
        digest = bytes.fromhex(value.get("digest", ""))
        return struct.pack("!HBB", int(value["key_tag"]), int(value.get("algorithm", 13)),
                            int(value.get("digest_type", 2))) + digest
    if rtype == "HTTPS":
        # RFC 9460 §2 (SVCB-compatible wire format)
        out = struct.pack("!H", int(value.get("priority", 1))) + encode_name(value.get("target", "."))
        params = []
        if value.get("alpn"):
            alpns = [a.strip() for a in value["alpn"].split(",") if a.strip()]
            pval = b"".join(bytes([len(a)]) + a.encode("ascii") for a in alpns)
            params.append((1, pval))
        if value.get("port") not in (None, ""):
            params.append((3, struct.pack("!H", int(value["port"]))))
        if value.get("ipv4hint"):
            ips = [ipaddress.IPv4Address(i.strip()).packed for i in value["ipv4hint"].split(",") if i.strip()]
            params.append((4, b"".join(ips)))
        if value.get("ipv6hint"):
            ips = [ipaddress.IPv6Address(i.strip()).packed for i in value["ipv6hint"].split(",") if i.strip()]
            params.append((6, b"".join(ips)))
        for key, pval in sorted(params):  # SvcParams must be in ascending key order (RFC 9460 §2.2)
            out += struct.pack("!HH", key, len(pval)) + pval
        return out
    # Types we don't fully re-derive cryptographically ourselves and instead
    # build/store pre-computed wire bytes directly (DNSKEY/RRSIG/NSEC are
    # assembled by dnssec.py/zonesigning.py; OPT is a pseudo-record), PLUS
    # the generic case: decode_rdata's fallback for any type we don't have
    # a structured encoder for is {"raw_hex": ...} -- that must always be
    # re-encodable symmetrically, or re-serializing a forwarded answer of
    # any less-common type (HINFO, LOC, CERT, SVCB, URI, NSEC3, ...) would
    # raise here instead of just passing the bytes through unchanged.
    if "raw_hex" in value:
        raw = value.get("raw_hex", "")
        return bytes.fromhex(raw) if raw else b""
    raise DNSError(f"unsupported rtype for encode: {rtype}")


def decode_rdata(rtype: str, msg: bytes, rdata_offset: int, rdlength: int):
    end = rdata_offset + rdlength
    if rtype == "A":
        return {"address": str(ipaddress.IPv4Address(msg[rdata_offset:end]))}
    if rtype == "AAAA":
        return {"address": str(ipaddress.IPv6Address(msg[rdata_offset:end]))}
    if rtype in ("CNAME", "NS", "PTR"):
        name, _ = decode_name(msg, rdata_offset)
        return {"target": name}
    if rtype == "MX":
        pr = struct.unpack("!H", msg[rdata_offset:rdata_offset + 2])[0]
        name, _ = decode_name(msg, rdata_offset + 2)
        return {"priority": pr, "target": name}
    if rtype == "TXT":
        out = []
        p = rdata_offset
        while p < end:
            ln = msg[p]
            p += 1
            out.append(msg[p:p + ln].decode("utf-8", errors="replace"))
            p += ln
        return {"text": "".join(out)}
    if rtype == "SOA":
        mname, p = decode_name(msg, rdata_offset)
        rname, p = decode_name(msg, p)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[p:p + 20])
        return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum}
    if rtype == "SRV":
        pr, w, port = struct.unpack("!HHH", msg[rdata_offset:rdata_offset + 6])
        target, _ = decode_name(msg, rdata_offset + 6)
        return {"priority": pr, "weight": w, "port": port, "target": target}
    if rtype == "CAA":
        flags = msg[rdata_offset]
        tag_len = msg[rdata_offset + 1]
        tag = msg[rdata_offset + 2:rdata_offset + 2 + tag_len].decode("ascii")
        value = msg[rdata_offset + 2 + tag_len:end].decode("ascii")
        return {"flags": flags, "tag": tag, "value": value}
    if rtype == "NAPTR":
        order, preference = struct.unpack("!HH", msg[rdata_offset:rdata_offset + 4])
        p = rdata_offset + 4

        def read_str(p):
            ln = msg[p]
            return msg[p + 1:p + 1 + ln].decode("ascii", errors="replace"), p + 1 + ln

        flags, p = read_str(p)
        service, p = read_str(p)
        regexp, p = read_str(p)
        replacement, _ = decode_name(msg, p)
        return {"order": order, "preference": preference, "flags": flags,
                "service": service, "regexp": regexp, "replacement": replacement}
    if rtype == "TLSA":
        usage, selector, matching_type = msg[rdata_offset], msg[rdata_offset + 1], msg[rdata_offset + 2]
        return {"usage": usage, "selector": selector, "matching_type": matching_type,
                "cert_data": msg[rdata_offset + 3:end].hex()}
    if rtype == "SSHFP":
        algorithm, fp_type = msg[rdata_offset], msg[rdata_offset + 1]
        return {"algorithm": algorithm, "fp_type": fp_type, "fingerprint": msg[rdata_offset + 2:end].hex()}
    if rtype == "DS":
        key_tag, algorithm, digest_type = struct.unpack("!HBB", msg[rdata_offset:rdata_offset + 4])
        return {"key_tag": key_tag, "algorithm": algorithm, "digest_type": digest_type,
                "digest": msg[rdata_offset + 4:end].hex()}
    if rtype == "HTTPS":
        priority = struct.unpack("!H", msg[rdata_offset:rdata_offset + 2])[0]
        target, p = decode_name(msg, rdata_offset + 2)
        result = {"priority": priority, "target": target}
        while p < end:
            key, plen = struct.unpack("!HH", msg[p:p + 4])
            pval = msg[p + 4:p + 4 + plen]
            if key == 1:  # alpn
                names, q = [], 0
                while q < len(pval):
                    ln = pval[q]
                    names.append(pval[q + 1:q + 1 + ln].decode("ascii", errors="replace"))
                    q += 1 + ln
                result["alpn"] = ",".join(names)
            elif key == 3:  # port
                result["port"] = struct.unpack("!H", pval)[0]
            elif key == 4:  # ipv4hint
                result["ipv4hint"] = ",".join(str(ipaddress.IPv4Address(pval[i:i + 4])) for i in range(0, len(pval), 4))
            elif key == 6:  # ipv6hint
                result["ipv6hint"] = ",".join(str(ipaddress.IPv6Address(pval[i:i + 16])) for i in range(0, len(pval), 16))
            p += 4 + plen
        return result
    # opaque fallback
    return {"raw_hex": msg[rdata_offset:end].hex()}


# ------------------------------------------------------------------ message

class Question:
    __slots__ = ("name", "qtype", "qclass")

    def __init__(self, name, qtype="A", qclass=QCLASS_IN):
        self.name = name
        self.qtype = qtype
        self.qclass = qclass


class ResourceRecord:
    __slots__ = ("name", "rtype", "rclass", "ttl", "value")

    def __init__(self, name, rtype, ttl, value, rclass=QCLASS_IN):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.value = value


class Message:
    def __init__(self):
        self.id = 0
        self.qr = 0          # 0=query 1=response
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 1
        self.ra = 0
        self.rcode = 0
        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    # ---------------------------------------------------------- decoding

    @classmethod
    def from_wire(cls, data: bytes):
        if len(data) < 12:
            raise DNSError("message too short")
        (mid, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])
        m = cls()
        m.id = mid
        m.qr = (flags >> 15) & 1
        m.opcode = (flags >> 11) & 0xF
        m.aa = (flags >> 10) & 1
        m.tc = (flags >> 9) & 1
        m.rd = (flags >> 8) & 1
        m.ra = (flags >> 7) & 1
        m.rcode = flags & 0xF

        offset = 12
        for _ in range(qdcount):
            name, offset = decode_name(data, offset)
            qtype_num, qclass = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            m.questions.append(Question(name, QTYPE_BY_NUM.get(qtype_num, str(qtype_num)), qclass))

        def read_rr_section(count, offset):
            section = []
            for _ in range(count):
                name, offset = decode_name(data, offset)
                rtype_num, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                rtype = QTYPE_BY_NUM.get(rtype_num, str(rtype_num))
                try:
                    value = decode_rdata(rtype, data, offset, rdlength)
                except Exception:
                    value = {"raw_hex": data[offset:offset + rdlength].hex()}
                section.append(ResourceRecord(name, rtype, ttl, value, rclass))
                offset += rdlength
            return section, offset

        m.answers, offset = read_rr_section(ancount, offset)
        m.authorities, offset = read_rr_section(nscount, offset)
        m.additionals, offset = read_rr_section(arcount, offset)
        return m

    # ---------------------------------------------------------- encoding

    def to_wire(self) -> bytes:
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | self.rcode
        header = struct.pack("!HHHHHH", self.id, flags,
                              len(self.questions), len(self.answers),
                              len(self.authorities), len(self.additionals))
        out = bytearray(header)
        for q in self.questions:
            out += encode_name(q.name) + struct.pack("!HH", type_to_num(q.qtype), q.qclass)

        def write_rr(rr):
            b = bytearray()
            b += encode_name(rr.name)
            rdata = encode_rdata(rr.rtype, rr.value)
            b += struct.pack("!HHIH", type_to_num(rr.rtype), rr.rclass, rr.ttl, len(rdata))
            b += rdata
            return bytes(b)

        for rr in self.answers:
            out += write_rr(rr)
        for rr in self.authorities:
            out += write_rr(rr)
        for rr in self.additionals:
            out += write_rr(rr)
        return bytes(out)


def new_query_id() -> int:
    return random.randint(0, 0xFFFF)
