"""
Real DNSSEC zone signing using ECDSAP256SHA256 (algorithm 13, RFC 6605).

This generates a genuine signing key per zone, publishes a real DNSKEY
record, and produces RFC 4034-compliant canonical RRSIGs that a real
validating resolver can verify -- there is no protocol-level shortcut
here. What NovaDNS does *not* do (documented in the README): NSEC/NSEC3
authenticated denial-of-existence, automatic key rollover, and getting
the DS record into a real parent zone (that step is manual -- copy the
DS record NovaDNS shows you into your registrar/parent zone).
"""
import hashlib
import struct
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

from . import wire

ALGORITHM_ECDSAP256SHA256 = 13


_BASE32HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV"


def base32hex_encode(data: bytes) -> str:
    """RFC 4648 §7 base32hex, no padding -- the encoding NSEC3 owner
    names use (RFC 5155 §1.3), distinct from ordinary base32."""
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * ((5 - len(bits) % 5) % 5)
    return "".join(_BASE32HEX_ALPHABET[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def base32hex_decode(s: str) -> bytes:
    s = s.upper()
    bits = "".join(f"{_BASE32HEX_ALPHABET.index(c):05b}" for c in s)
    bits = bits[: len(bits) - len(bits) % 8]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def nsec3_hash(owner_fqdn: str, salt_hex: str, iterations: int) -> str:
    """RFC 5155 §5: IH(salt, x, 0) = H(x || salt); IH(salt, x, k) =
    H(IH(salt, x, k-1) || salt). Returns the base32hex hashed owner
    name (uppercase, matching how validators compare it)."""
    salt = bytes.fromhex(salt_hex) if salt_hex else b""
    x = wire.encode_name(owner_fqdn.lower())
    digest = hashlib.sha1(x + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return base32hex_encode(digest)


def build_nsec3_rdata(next_hashed_owner_b32: str, type_names: list, salt_hex: str = "",
                       iterations: int = 0, flags: int = 0) -> bytes:
    """RFC 5155 §3.2: hash_algorithm(1)=1(SHA-1) + flags(1) + iterations(2)
    + salt_length(1) + salt + hash_length(1) + next_hashed_owner + type bitmap."""
    salt = bytes.fromhex(salt_hex) if salt_hex else b""
    next_owner = base32hex_decode(next_hashed_owner_b32)
    type_nums = sorted({wire.QTYPE[t] for t in type_names if t in wire.QTYPE})
    windows = {}
    for num in type_nums:
        w, bit = num // 256, num % 256
        windows.setdefault(w, bytearray(32))
        windows[w][bit // 8] |= (0x80 >> (bit % 8))
    bitmap = bytearray()
    for w in sorted(windows):
        b = bytes(windows[w])
        length = len(b)
        while length > 0 and b[length - 1] == 0:
            length -= 1
        if length == 0:
            continue
        bitmap += struct.pack("!BB", w, length) + b[:length]
    return (struct.pack("!BBHB", 1, flags, iterations, len(salt)) + salt +
            struct.pack("!B", len(next_owner)) + next_owner + bytes(bitmap))


def canonical_key(fqdn: str):
    """RFC 4034 6.1 canonical ordering key: compare labels right-to-left
    (i.e. TLD first), lowercase. Sorting names by this key gives the
    canonical zone ordering NSEC's 'next owner name' walk depends on."""
    fqdn = fqdn.rstrip(".").lower()
    return tuple(reversed(fqdn.split("."))) if fqdn else ()


def build_nsec_rdata(next_owner_fqdn: str, type_names: list) -> bytes:
    """RFC 4034 4.1: next-owner-name (wire, uncompressed) + a type
    bitmap covering every RR type present at this owner name."""
    next_wire = wire.encode_name(next_owner_fqdn.lower())
    type_nums = sorted({wire.QTYPE[t] for t in type_names if t in wire.QTYPE})
    windows = {}
    for num in type_nums:
        w, bit = num // 256, num % 256
        windows.setdefault(w, bytearray(32))
        windows[w][bit // 8] |= (0x80 >> (bit % 8))
    out = bytearray(next_wire)
    for w in sorted(windows):
        bitmap = bytes(windows[w])
        length = len(bitmap)
        while length > 0 and bitmap[length - 1] == 0:
            length -= 1
        if length == 0:
            continue
        out += struct.pack("!BB", w, length) + bitmap[:length]
    return bytes(out)


def generate_key(flags=257):
    """Generates a P-256 signing key. flags=257 marks it as a
    Secure-Entry-Point key usable as both KSK and ZSK (simplest model for
    a self-managed zone with no separate key rollover process)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    pubkey_bytes = public_numbers.x.to_bytes(32, "big") + public_numbers.y.to_bytes(32, "big")

    dnskey_rdata = _dnskey_rdata(flags, pubkey_bytes)
    key_tag = _key_tag(dnskey_rdata)
    ds_digest = _ds_digest(dnskey_rdata)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    return {
        "private_key_pem": private_pem,
        "public_key_hex": pubkey_bytes.hex(),
        "key_tag": key_tag,
        "flags": flags,
        "algorithm": ALGORITHM_ECDSAP256SHA256,
        "ds_digest_sha256": ds_digest,
        "dnskey_rdata_hex": dnskey_rdata.hex(),
    }


def _dnskey_rdata(flags, pubkey_bytes):
    return struct.pack("!HBB", flags, 3, ALGORITHM_ECDSAP256SHA256) + pubkey_bytes


def _key_tag(dnskey_rdata: bytes) -> int:
    """RFC 4034 Appendix B checksum (used by all algorithms except the
    obsolete algorithm 1)."""
    total = 0
    for i, b in enumerate(dnskey_rdata):
        if i % 2 == 0:
            total += b << 8
        else:
            total += b
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def _ds_digest(dnskey_rdata: bytes, owner_wire: bytes = b"\x00") -> str:
    """DS digest type 2 (SHA-256) over the *canonical owner name* + DNSKEY
    RDATA. Caller passes the real canonical zone-apex wire name in
    ds_digest_for_zone(); this default (root) is only a placeholder."""
    return hashlib.sha256(owner_wire + dnskey_rdata).hexdigest()


def ds_digest_for_zone(zone_name: str, dnskey_rdata_hex: str) -> str:
    owner_wire = wire.encode_name(zone_name.lower())
    return hashlib.sha256(owner_wire + bytes.fromhex(dnskey_rdata_hex)).hexdigest()


def _count_labels(fqdn: str) -> int:
    fqdn = fqdn.rstrip(".")
    return len([l for l in fqdn.split(".") if l]) if fqdn else 0


def sign_rrset(private_key_pem: str, key_tag: int, zone_name: str, owner_fqdn: str,
               rtype: str, ttl: int, rdata_list_bytes: list, inception=None, expiration=None):
    """Builds an RFC 4034-canonical RRSIG covering one RRset (one or more
    RRs sharing owner name + type). rdata_list_bytes is the already
    wire-encoded RDATA for each RR in the set."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)

    now = int(time.time())
    inception = inception or (now - 3600)               # small clock-skew allowance
    expiration = expiration or (now + 30 * 24 * 3600)     # 30-day validity, re-sign before then

    signer_name_wire = wire.encode_name(zone_name.lower())
    owner_wire = wire.encode_name(owner_fqdn.lower())
    labels = _count_labels(owner_fqdn)
    type_covered = wire.QTYPE[rtype]

    rrsig_rdata_prefix = struct.pack("!HBBIIIH", type_covered, ALGORITHM_ECDSAP256SHA256, labels,
                                      ttl, expiration, inception, key_tag) + signer_name_wire

    # Canonical RRset: sort RRs by canonical RDATA bytes (RFC 4034 6.3),
    # each in owner+type+class+ttl+rdlength+rdata wire form.
    canonical_rrs = b""
    for rdata in sorted(rdata_list_bytes):
        canonical_rrs += owner_wire + struct.pack("!HHIH", type_covered, wire.QCLASS_IN, ttl, len(rdata)) + rdata

    signing_input = rrsig_rdata_prefix + canonical_rrs
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    rrsig_rdata = rrsig_rdata_prefix + raw_signature
    return {"raw_hex": rrsig_rdata.hex(), "type_covered": rtype,
            "expiration": expiration, "inception": inception}
