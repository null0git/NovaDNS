import json
import struct
from . import wire, dnssec
from .. import db as dbmod


def get_or_create_key(db, zone):
    row = dbmod.query(db, "SELECT * FROM dnssec_keys WHERE zone_id=?", (zone["id"],), one=True)
    if row:
        return row
    key = dnssec.generate_key()
    ds = dnssec.ds_digest_for_zone(zone["name"], key["dnskey_rdata_hex"])
    key_id = dbmod.execute(db, """INSERT INTO dnssec_keys
        (zone_id, algorithm, key_tag, flags, private_key_pem, public_key_hex, ds_digest_sha256)
        VALUES (?,?,?,?,?,?,?)""",
        (zone["id"], key["algorithm"], key["key_tag"], key["flags"],
         key["private_key_pem"], key["public_key_hex"], ds))
    return dbmod.query(db, "SELECT * FROM dnssec_keys WHERE id=?", (key_id,), one=True)


def _dnskey_rdata_hex(key_row):
    rdata = struct.pack("!HBB", key_row["flags"], 3, key_row["algorithm"]) + bytes.fromhex(key_row["public_key_hex"])
    return rdata.hex()


def sign_zone(db, zone, use_nsec3=None):
    """(Re)signs every RRset in the zone, including authenticated
    denial-of-existence -- either RFC 4034 NSEC (plain-name chain) or
    RFC 5155 NSEC3 (hashed, zone-walk-resistant chain), depending on
    the zone's nsec3_enabled flag (or the use_nsec3 override). Also
    signs the DNSKEY RRset. Idempotent -- safe to call again after any
    record change."""
    key = get_or_create_key(db, zone)
    zone_name = zone["name"].rstrip(".")
    nsec3 = zone["nsec3_enabled"] if use_nsec3 is None else use_nsec3
    salt = zone["nsec3_salt"] or ""
    iterations = zone["nsec3_iterations"] or 0

    # Publish/replace the DNSKEY record at the apex.
    dnskey_rdata_hex = _dnskey_rdata_hex(key)
    dbmod.execute(db, "DELETE FROM records WHERE zone_id=? AND rtype='DNSKEY'", (zone["id"],))
    dnskey_ttl = max(zone["default_ttl"], 3600)
    dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                  (zone["id"], "@", "DNSKEY", dnskey_ttl, json.dumps({"raw_hex": dnskey_rdata_hex})))

    # Clear old signatures/denial-of-existence records before regenerating.
    dbmod.execute(db, "DELETE FROM records WHERE zone_id=? AND rtype IN ('RRSIG','NSEC','NSEC3','NSEC3PARAM')",
                  (zone["id"],))

    records = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype NOT IN ('DNSKEY','RRSIG','NSEC','NSEC3','NSEC3PARAM')",
                           (zone["id"],))
    groups = {}          # (name, rtype) -> [rows]
    types_by_name = {}    # name -> set(rtype)
    for r in records:
        groups.setdefault((r["name"], r["rtype"]), []).append(r)
        types_by_name.setdefault(r["name"], set()).add(r["rtype"])
    groups[("@", "DNSKEY")] = [dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype='DNSKEY'",
                                            (zone["id"],), one=True)]
    types_by_name.setdefault("@", set()).add("DNSKEY")

    # SOA lives on the zones table (see resolver._synth_soa_rr), not as a
    # records row -- synthesize one here purely so it gets an RRSIG and
    # shows up in the apex's type bitmap like a real SOA should.
    soa_value = {"mname": zone["soa_mname"] or f"ns1.{zone_name}.", "rname": zone["soa_rname"] or f"admin.{zone_name}.",
                 "serial": zone["soa_serial"], "refresh": zone["soa_refresh"], "retry": zone["soa_retry"],
                 "expire": zone["soa_expire"], "minimum": zone["soa_minimum"]}
    groups[("@", "SOA")] = [{"ttl": zone["default_ttl"], "data_json": json.dumps(soa_value)}]
    types_by_name.setdefault("@", set()).add("SOA")

    def owner_fqdn(name):
        return zone_name if name == "@" else f"{name}.{zone_name}"

    denial_count = 0
    if nsec3:
        # RFC 5155: publish NSEC3PARAM at the apex, then one NSEC3 per
        # owned name, keyed by its hashed owner name and chained in
        # hash order (not canonical name order -- that's the whole
        # point, it's what makes zone-walking infeasible).
        dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                      (zone["id"], "@", "NSEC3PARAM", zone["default_ttl"],
                       json.dumps({"raw_hex": struct.pack('!BBHB', 1, 0, iterations, len(bytes.fromhex(salt)) if salt else 0).hex() + salt})))
        types_by_name.setdefault("@", set()).add("NSEC3PARAM")

        hashed = {name: dnssec.nsec3_hash(owner_fqdn(name), salt, iterations) for name in types_by_name}
        names_by_hash = sorted(types_by_name.keys(), key=lambda n: hashed[n])
        n = len(names_by_hash)
        for i, name in enumerate(names_by_hash):
            next_name = names_by_hash[(i + 1) % n]
            type_bitmap_types = types_by_name[name] | {"RRSIG"}
            if name == "@":
                type_bitmap_types.add("NSEC3PARAM")
            nsec3_rdata = dnssec.build_nsec3_rdata(hashed[next_name], list(type_bitmap_types), salt, iterations)
            hashed_owner_name = hashed[name].lower()
            rec_id = dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                                    (zone["id"], hashed_owner_name, "NSEC3", zone["default_ttl"],
                                     json.dumps({"raw_hex": nsec3_rdata.hex(), "covers_name": name})))
            groups[(hashed_owner_name, "NSEC3")] = [dbmod.query(db, "SELECT * FROM records WHERE id=?", (rec_id,), one=True)]
        denial_count = n
    else:
        # RFC 4034 NSEC: canonical-order every owned name, point each one
        # at the next (wrapping around), listing the types present there.
        names_sorted = sorted(types_by_name.keys(), key=lambda n: dnssec.canonical_key(owner_fqdn(n)))
        for i, name in enumerate(names_sorted):
            next_name = names_sorted[(i + 1) % len(names_sorted)]
            type_bitmap_types = types_by_name[name] | {"NSEC", "RRSIG"}
            nsec_rdata = dnssec.build_nsec_rdata(owner_fqdn(next_name), list(type_bitmap_types))
            rec_id = dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                                    (zone["id"], name, "NSEC", zone["default_ttl"], json.dumps({"raw_hex": nsec_rdata.hex()})))
            groups[(name, "NSEC")] = [dbmod.query(db, "SELECT * FROM records WHERE id=?", (rec_id,), one=True)]
        denial_count = len(names_sorted)

    # --- Sign every RRset (including DNSKEY and the NSEC/NSEC3 chain).
    signed_count = 0
    for (name, rtype), rows in groups.items():
        rows = [r for r in rows if r is not None]
        if not rows:
            continue
        ofqdn = zone_name if (nsec3 and rtype == "NSEC3") else owner_fqdn(name)
        if nsec3 and rtype == "NSEC3":
            ofqdn = f"{name}.{zone_name}"  # name is already the hashed label here
        ttl = rows[0]["ttl"] or zone["default_ttl"]
        rdata_bytes_list = []
        for row in rows:
            value = json.loads(row["data_json"])
            try:
                rdata_bytes_list.append(wire.encode_rdata(rtype, value))
            except wire.DNSError:
                continue
        if not rdata_bytes_list:
            continue
        rrsig = dnssec.sign_rrset(key["private_key_pem"], key["key_tag"], zone_name, ofqdn,
                                   rtype, ttl, rdata_bytes_list)
        dbmod.execute(db, "INSERT INTO records (zone_id, name, rtype, ttl, data_json) VALUES (?,?,?,?,?)",
                      (zone["id"], name, "RRSIG", ttl,
                       json.dumps({"raw_hex": rrsig["raw_hex"], "type_covered": rtype})))
        signed_count += 1

    dbmod.execute(db, "UPDATE zones SET dnssec_enabled=1, nsec3_enabled=?, soa_serial=soa_serial+1, updated_at=datetime('now') WHERE id=?",
                  (1 if nsec3 else 0, zone["id"]))
    return {"key_tag": key["key_tag"], "algorithm": key["algorithm"], "rrsets_signed": signed_count,
            "nsec_records": denial_count, "nsec3": bool(nsec3), "ds_digest_sha256": key["ds_digest_sha256"]}


def get_rrsig_for(db, zone_id, name, covered_rtype):
    rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype='RRSIG' AND name=?", (zone_id, name))
    return [r for r in rows if json.loads(r["data_json"]).get("type_covered") == covered_rtype]


def find_covering_nsec(db, zone, qname):
    """Finds the NSEC or NSEC3 record proving qname doesn't exist,
    matching whichever denial-of-existence scheme the zone uses."""
    if zone["nsec3_enabled"]:
        return _find_covering_nsec3(db, zone, qname)
    zone_name = zone["name"].rstrip(".")
    nsec_rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype='NSEC'", (zone["id"],))
    if not nsec_rows:
        return None

    def ofqdn(name):
        return zone_name if name == "@" else f"{name}.{zone_name}"

    qkey = dnssec.canonical_key(qname)
    entries = sorted(nsec_rows, key=lambda r: dnssec.canonical_key(ofqdn(r["name"])))
    n = len(entries)
    for i, row in enumerate(entries):
        owner_key = dnssec.canonical_key(ofqdn(row["name"]))
        next_row = entries[(i + 1) % n]
        next_key = dnssec.canonical_key(ofqdn(next_row["name"]))
        if next_key <= owner_key:  # wrap-around entry (last -> first)
            if owner_key < qkey or qkey <= next_key:
                return row
        elif owner_key < qkey <= next_key:
            return row
        elif owner_key < qkey and i == n - 1:
            return row
    return entries[-1]  # falls in the wrap-around gap after the last name


def _find_covering_nsec3(db, zone, qname):
    """RFC 5155 simplified: hashes qname with the zone's NSEC3 params
    and finds the NSEC3 record whose (owner-hash, next-hash) range
    covers it. This proves the exact queried name has no hash match in
    the chain -- the same level of rigor as our NSEC proof (a full
    closest-encloser + wildcard non-existence chain is not built)."""
    zone_name = zone["name"].rstrip(".")
    qhash = dnssec.nsec3_hash(qname, zone["nsec3_salt"] or "", zone["nsec3_iterations"] or 0)
    rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype='NSEC3'", (zone["id"],))
    if not rows:
        return None
    entries = sorted(rows, key=lambda r: r["name"])  # name = hashed owner, already base32hex-sortable
    n = len(entries)
    for i, row in enumerate(entries):
        owner_hash = row["name"]
        next_row = entries[(i + 1) % n]
        next_hash = next_row["name"]
        if next_hash <= owner_hash:  # wrap-around
            if owner_hash < qhash or qhash <= next_hash:
                return row
        elif owner_hash < qhash <= next_hash:
            return row
    return entries[-1]
