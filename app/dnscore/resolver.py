"""
The resolution pipeline. For every incoming query, in order:

  1. Maintenance mode check
  2. Filtering (blocklists / allowlists / categories)
  3. Rewrite engine (exact / wildcard / regex, client + time scoped)
  4. Cache lookup
  5. Authoritative zone lookup
  6. Recursive/forwarding lookup (with failover across upstreams)
  7. Cache store + query log

This module has no Flask dependency so it can run entirely inside the
DNS server's own thread/process.
"""
import fnmatch
import ipaddress
import json
import re
import socket
import time
import datetime

from . import wire
from .cache import DNSCache
from .. import db as dbmod
from . import zonesigning

UPSTREAM_TIMEOUT = 4.0


class Resolver:
    def __init__(self, db_path):
        self.db_path = db_path
        self.cache = DNSCache()
        self._settings_cache = {}
        self._settings_cache_at = 0

    def _db(self):
        return dbmod.get_db_nocontext(self.db_path)

    def _get_setting(self, key, default=None):
        now = time.time()
        if now - self._settings_cache_at > 5:  # refresh at most every 5s
            db = self._db()
            rows = dbmod.query(db, "SELECT key, value FROM settings")
            self._settings_cache = {r["key"]: r["value"] for r in rows}
            self._settings_cache_at = now
        return self._settings_cache.get(key, default)

    def is_allowed_by_acl(self, client_ip):
        """Empty/unset ACL = allow all (matches how most home/office DNS
        servers behave out of the box). A configured ACL restricts which
        client networks may query this server at all."""
        raw = self._get_setting("acl_networks", "")
        if not raw:
            return True
        try:
            ip = ipaddress.ip_address(client_ip)
        except ValueError:
            return True
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                elif client_ip == entry:
                    return True
            except ValueError:
                continue
        return False

    # --------------------------------------------------------------- zones

    def _synth_soa_rr(self, zone):
        """SOA fields live on the zones table itself (soa_mname, soa_serial,
        etc.) rather than requiring a matching row in `records` -- this is
        the single source of truth so simple-mode zones, AXFR, and
        negative-caching authority sections all agree with each other."""
        zone_fqdn = zone["name"].rstrip(".") + "."
        value = {
            "mname": zone["soa_mname"] or f"ns1.{zone_fqdn}",
            "rname": zone["soa_rname"] or f"admin.{zone_fqdn}",
            "serial": zone["soa_serial"], "refresh": zone["soa_refresh"],
            "retry": zone["soa_retry"], "expire": zone["soa_expire"], "minimum": zone["soa_minimum"],
        }
        return wire.ResourceRecord(zone_fqdn, "SOA", zone["default_ttl"], value)

    def _find_zone(self, qname: str):
        db = self._db()
        qname_l = qname.rstrip(".").lower()
        rows = dbmod.query(db, "SELECT * FROM zones WHERE ztype='authoritative'")
        best = None
        for z in rows:
            zn = z["name"].rstrip(".").lower()
            if qname_l == zn or qname_l.endswith("." + zn):
                if best is None or len(zn) > len(best["name"]):
                    best = z
        return best

    def _lookup_authoritative(self, qname: str, qtype: str, client_ip: str = "127.0.0.1"):
        zone = self._find_zone(qname)
        if not zone:
            return None, None
        db = self._db()
        qname_l = qname.rstrip(".").lower()
        zone_l = zone["name"].rstrip(".").lower()
        relative = "@" if qname_l == zone_l else qname_l[: -(len(zone_l) + 1)]

        if qtype == "SOA" and relative == "@":
            return zone, ("SOA", [{"__synthetic_soa__": True}])

        # RFC 1034 §4.3.3: a wildcard only ever answers for a name that
        # doesn't exist in the zone at all (no record of any type). It
        # must never apply alongside an explicit record for that same
        # name -- otherwise a zone with both e.g. "www A 1.2.3.4" and
        # "* A 9.9.9.9" would incorrectly return both for a query
        # against "www", and a wildcard could shadow a CNAME lookup
        # for a name that has its own CNAME but no matching-type record.
        name_exists = bool(dbmod.query(db, "SELECT 1 FROM records WHERE zone_id=? AND name=? LIMIT 1",
                                        (zone["id"], relative)))
        lookup_name = relative if name_exists else "*"

        if qtype == "ANY":
            # RFC 1035 §3.2.3: ANY means "everything you have for this name",
            # not a literal record type -- fetch every real record here,
            # each keeping its own actual rtype (handled downstream since
            # _row_to_rr always reads row['rtype'], never the query type).
            rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype NOT IN ('NSEC') AND name=?",
                                (zone["id"], lookup_name))
            rows = self._apply_split_dns(rows, client_ip)
            if not rows and relative == "@":
                return zone, ("ANY", [{"__synthetic_soa__": True}])
            return zone, ("ANY", rows)

        def records_for(rtype):
            rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND rtype=? AND name=?",
                                (zone["id"], rtype, lookup_name))
            return self._apply_split_dns(rows, client_ip)

        rows = records_for(qtype)
        if not rows and qtype != "CNAME":
            cname_rows = records_for("CNAME")
            if cname_rows:
                return zone, ("CNAME", cname_rows)
        return zone, (qtype, rows)

    def _apply_split_dns(self, rows, client_ip):
        """When multiple rows share a name+type, rows scoped to a specific
        client network/group take priority over the unscoped ones -- e.g.
        an internal A record for LAN clients vs. a public A record for
        everyone else. Falls back to the unscoped rows if none match."""
        scoped = [r for r in rows if r["client_match"] and self._client_matches(client_ip, r["client_match"])]
        if scoped:
            return scoped
        return [r for r in rows if not r["client_match"]]

    def _row_to_rr(self, name, row, default_ttl):
        value = json.loads(row["data_json"])
        ttl = row["ttl"] if row["ttl"] else default_ttl
        return wire.ResourceRecord(name, row["rtype"], ttl, value)

    # ------------------------------------------------------------ filtering

    def _is_blocked(self, qname: str, client_ip: str):
        db = self._db()
        qname_l = qname.rstrip(".").lower()
        allow = dbmod.query(db, "SELECT * FROM block_entries WHERE list_type='allow'")
        for a in allow:
            if self._domain_matches(qname_l, a["domain"], a["is_regex"]):
                return False
        blocks = dbmod.query(db, """
            SELECT be.* FROM block_entries be
            JOIN blocklists bl ON bl.id = be.blocklist_id
            WHERE be.list_type='block' AND bl.enabled=1
            UNION ALL
            SELECT * FROM block_entries WHERE list_type='block' AND blocklist_id IS NULL
        """)
        for b in blocks:
            if b["client_match"] and not self._client_matches(client_ip, b["client_match"]):
                continue
            if self._domain_matches(qname_l, b["domain"], b["is_regex"]):
                return True
        return False

    @staticmethod
    def _domain_matches(qname, pattern, is_regex):
        pattern = pattern.rstrip(".").lower()
        if is_regex:
            try:
                return re.search(pattern, qname) is not None
            except re.error:
                return False
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return qname == suffix or qname.endswith("." + suffix)
        return qname == pattern

    def _client_matches(self, client_ip, match):
        if not match:
            return False
        if match.startswith("group:"):
            return self._client_in_group(client_ip, match[len("group:"):])
        try:
            if "/" in match:
                return ipaddress.ip_address(client_ip) in ipaddress.ip_network(match, strict=False)
            return client_ip == match
        except ValueError:
            return False

    def _client_in_group(self, client_ip, group_name):
        db = self._db()
        group = dbmod.query(db, "SELECT id FROM client_groups WHERE name=?", (group_name,), one=True)
        if not group:
            return False
        entries = dbmod.query(db, "SELECT cidr_or_ip FROM client_group_entries WHERE group_id=?", (group["id"],))
        for e in entries:
            try:
                if "/" in e["cidr_or_ip"]:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(e["cidr_or_ip"], strict=False):
                        return True
                elif client_ip == e["cidr_or_ip"]:
                    return True
            except ValueError:
                continue
        return False

    # -------------------------------------------------------------- rewrite

    def _apply_rewrite(self, qname: str, qtype: str, client_ip: str):
        db = self._db()
        qname_l = qname.rstrip(".").lower()
        rules = dbmod.query(db, "SELECT * FROM rewrite_rules WHERE enabled=1 AND rtype=? ORDER BY priority ASC", (qtype,))
        now = datetime.datetime.now().strftime("%H:%M")
        for r in rules:
            if r["client_match"] and not self._client_matches(client_ip, r["client_match"]):
                continue
            if r["time_start"] and r["time_end"]:
                if not (r["time_start"] <= now <= r["time_end"]):
                    continue
            pattern = r["pattern"].rstrip(".").lower()
            matched = False
            if r["match_type"] == "exact":
                matched = qname_l == pattern
            elif r["match_type"] == "wildcard":
                matched = fnmatch.fnmatch(qname_l, pattern)
            elif r["match_type"] == "regex":
                try:
                    matched = re.search(pattern, qname_l) is not None
                except re.error:
                    matched = False
            if matched:
                dbmod.execute(db, "UPDATE rewrite_rules SET hits = hits + 1 WHERE id=?", (r["id"],))
                value = json.loads(r["rewrite_value"])
                return wire.ResourceRecord(qname, qtype, value.get("ttl", 300), value)
        return None

    # ------------------------------------------------------------ forwarders

    def _get_forwarders(self, qname: str):
        db = self._db()
        qname_l = qname.rstrip(".").lower()
        conditional = dbmod.query(db, """SELECT * FROM forwarders WHERE enabled=1
                                          AND condition_domain IS NOT NULL ORDER BY priority ASC""")
        for f in conditional:
            suffix = f["condition_domain"].rstrip(".").lower()
            if qname_l == suffix or qname_l.endswith("." + suffix):
                return [f]
        return dbmod.query(db, """SELECT * FROM forwarders WHERE enabled=1
                                   AND condition_domain IS NULL ORDER BY priority ASC""")

    def _forward_query(self, qname, qtype, forwarders, want_dnssec=False):
        req = wire.Message()
        req.id = wire.new_query_id()
        req.rd = 1
        req.questions.append(wire.Question(qname, qtype))
        if want_dnssec:
            req.additionals.append(wire.ResourceRecord(".", "OPT", 0, {"raw_hex": ""}, rclass=1232))
            # DO bit lives in the upper byte of the OPT TTL field (extended flags).
            req.additionals[0].ttl = 0x00008000
        payload = req.to_wire()

        for fw in forwarders:
            start = time.time()
            try:
                if fw["protocol"] == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(UPSTREAM_TIMEOUT)
                    sock.sendto(payload, (fw["address"], fw["port"]))
                    data, _ = sock.recvfrom(65535)
                    sock.close()
                elif fw["protocol"] == "tcp":
                    sock = socket.create_connection((fw["address"], fw["port"]), timeout=UPSTREAM_TIMEOUT)
                    sock.sendall(len(payload).to_bytes(2, "big") + payload)
                    data = self._read_tcp_response(sock)
                    sock.close()
                elif fw["protocol"] == "dot":
                    data = self._forward_dot(fw, payload)
                elif fw["protocol"] == "doh":
                    data = self._forward_doh(fw, payload)
                else:
                    continue
                latency = (time.time() - start) * 1000
                db = self._db()
                dbmod.execute(db, "UPDATE forwarders SET last_latency_ms=?, last_check=datetime('now'), healthy=1 WHERE id=?",
                               (latency, fw["id"]))
                return wire.Message.from_wire(data)
            except Exception as e:
                db = self._db()
                dbmod.execute(db, "UPDATE forwarders SET healthy=0, last_check=datetime('now') WHERE id=?", (fw["id"],))
                continue
        return None

    @staticmethod
    def _read_tcp_response(sock):
        rlen = int.from_bytes(sock.recv(2), "big")
        data = b""
        while len(data) < rlen:
            chunk = sock.recv(rlen - len(data))
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _forward_dot(fw, payload):
        """DNS-over-TLS (RFC 7858): same 2-byte-length-prefixed message as
        plain TCP DNS, wrapped in a standard TLS session (default port 853)."""
        import ssl
        ctx = ssl.create_default_context()
        port = fw["port"] if fw["port"] and fw["port"] != 53 else 853
        with socket.create_connection((fw["address"], port), timeout=UPSTREAM_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=fw["address"]) as tls:
                tls.sendall(len(payload).to_bytes(2, "big") + payload)
                return Resolver._read_tcp_response(tls)

    @staticmethod
    def _forward_doh(fw, payload):
        """DNS-over-HTTPS (RFC 8484): POST the raw wire-format message to a
        DoH endpoint. `address` may be a bare hostname (assumes the
        standard /dns-query path) or a full URL."""
        import urllib.request
        address = fw["address"]
        url = address if address.startswith("http") else f"https://{address}/dns-query"
        req = urllib.request.Request(url, data=payload, method="POST", headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message",
        })
        with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
            return resp.read()

    # --------------------------------------------------------------- main

    def resolve(self, qname: str, qtype: str, client_ip: str = "127.0.0.1", dnssec_ok: bool = False, trace: bool = False):
        """Returns (answers, rcode, source, authority, is_authoritative, trace_steps).

        `source` is for logging/monitoring ("cache" | "authoritative" |
        "forward" | "blocked" | "rewritten" | "maintenance") and doesn't
        by itself tell you whether the DNS header's AA bit should be
        set -- a cache HIT for data that originated from our own zone is
        still authoritative data, just served fast. `is_authoritative`
        is the one server.py actually uses for the AA bit, so a reply
        is only ever marked authoritative when it is genuinely ours,
        never when it was forwarded (cached or not).

        `trace_steps` is [] unless trace=True (the Live Query Trace
        feature); building it costs a few dict appends, skipped
        entirely on the normal hot path."""
        t0 = time.time()
        cache_qtype = f"{qtype}:DO" if dnssec_ok else qtype
        steps = [] if trace else None

        def mark(stage, decision, extra=None):
            if steps is not None:
                steps.append({"stage": stage, "decision": decision, "elapsed_ms": round((time.time() - t0) * 1000, 3),
                              **(extra or {})})

        maint = dbmod.query(self._db(), "SELECT * FROM maintenance WHERE id=1", one=True)
        mark("maintenance", "active" if (maint and maint["enabled"]) else "not active")
        if maint and maint["enabled"]:
            self._log(qname, qtype, client_ip, wire.RCODE["SERVFAIL"], "maintenance", t0)
            return [], wire.RCODE["SERVFAIL"], "maintenance", [], False, steps or []

        acl_ok = self.is_allowed_by_acl(client_ip)
        mark("acl", "allowed" if acl_ok else "refused")
        if not acl_ok:
            return [], wire.RCODE["REFUSED"], "blocked", [], False, steps or []

        blocked = self._is_blocked(qname, client_ip)
        mark("blocklists", "blocked" if blocked else "clear")
        if blocked:
            self._log(qname, qtype, client_ip, wire.RCODE["NXDOMAIN"], "blocked", t0)
            return [], wire.RCODE["NXDOMAIN"], "blocked", [], False, steps or []

        rewritten = self._apply_rewrite(qname, qtype, client_ip)
        mark("rewrite_engine", "matched" if rewritten else "no match")
        if rewritten:
            self._log(qname, qtype, client_ip, 0, "rewritten", t0)
            return [rewritten], 0, "rewritten", [], False, steps or []

        cached = self.cache.get(qname, cache_qtype)
        mark("cache_lookup", "hit" if cached is not None else "miss")
        if cached is not None:
            self._log(qname, qtype, client_ip, cached["rcode"], "cache", t0)
            return (cached["records"] or [], cached["rcode"], "cache", cached.get("authority") or [],
                    cached.get("origin") == "authoritative", steps or [])

        zone, result = self._lookup_authoritative(qname, qtype, client_ip)
        mark("split_dns_and_authoritative_lookup",
             f"zone '{zone['name']}' matched" if zone else "no local zone matched",
             {"answer_found": bool(zone and result and result[1])})
        if zone and result and result[1]:
            rtype_used, rows = result
            default_ttl = zone["default_ttl"]
            if rows == [{"__synthetic_soa__": True}]:
                answers = [self._synth_soa_rr(zone)]
            else:
                answers = [self._row_to_rr(qname, row, default_ttl) for row in rows]
            if dnssec_ok and zone["dnssec_enabled"] and rtype_used != "ANY":
                zone_l = zone["name"].rstrip(".").lower()
                qname_l = qname.rstrip(".").lower()
                relative = "@" if qname_l == zone_l else qname_l[: -(len(zone_l) + 1)]
                db = self._db()
                for sig_row in zonesigning.get_rrsig_for(db, zone["id"], relative, rtype_used):
                    answers.append(self._row_to_rr(qname, sig_row, default_ttl))
                mark("dnssec", "RRSIG attached")
            elif rtype_used == "ANY":
                # the raw ANY fetch already pulled every record at this name,
                # including any RRSIGs that already exist there -- nothing
                # more to attach.
                mark("dnssec", "RRSIGs already included in ANY result" if dnssec_ok and zone["dnssec_enabled"] else "not requested")
            self.cache.set(qname, cache_qtype, answers, 0, origin="authoritative")
            self._log(qname, qtype, client_ip, 0, "authoritative", t0)
            return answers, 0, "authoritative", [], True, steps or []
        if zone:
            # authoritative zone matched but no such record -> NXDOMAIN, do not forward.
            # RFC 2308: include the zone's SOA in authority so resolvers can
            # negative-cache correctly; add the NSEC denial proof alongside
            # it when DNSSEC was requested.
            authority = [self._synth_soa_rr(zone)]
            if dnssec_ok and zone["dnssec_enabled"]:
                authority += self._nsec_proof(zone, qname)
                mark("dnssec", "NSEC denial proof attached")
            self.cache.set(qname, cache_qtype, [], wire.RCODE["NXDOMAIN"], authority=authority, origin="authoritative")
            self._log(qname, qtype, client_ip, wire.RCODE["NXDOMAIN"], "authoritative", t0)
            return [], wire.RCODE["NXDOMAIN"], "authoritative", authority, True, steps or []

        forwarders = self._get_forwarders(qname)
        mark("forwarder_selection", f"{len(forwarders)} candidate(s)" if forwarders else "none configured")
        if forwarders:
            resp = self._forward_query(qname, qtype, forwarders, want_dnssec=dnssec_ok)
            mark("forward", "responded" if resp is not None else "no response / all unhealthy")
            if resp is not None:
                self.cache.set(qname, cache_qtype, resp.answers, resp.rcode, origin="forward")
                self._log(qname, qtype, client_ip, resp.rcode, "forward", t0)
                return resp.answers, resp.rcode, "forward", resp.authorities, False, steps or []

        self._log(qname, qtype, client_ip, wire.RCODE["SERVFAIL"], "forward", t0)
        return [], wire.RCODE["SERVFAIL"], "forward", [], False, steps or []

    def _nsec_proof(self, zone, qname):
        db = self._db()
        nsec_row = zonesigning.find_covering_nsec(db, zone, qname)
        if not nsec_row:
            return []
        default_ttl = zone["default_ttl"]
        proof = [self._row_to_rr(qname, nsec_row, default_ttl)]
        for sig_row in zonesigning.get_rrsig_for(db, zone["id"], nsec_row["name"], "NSEC"):
            proof.append(self._row_to_rr(qname, sig_row, default_ttl))
        return proof

    def axfr(self, zone_name: str, client_ip: str):
        """RFC 5936 zone transfer. Returns (records, error) -- error is a
        short string ('refused' | 'not_found') on failure. Denied by
        default: an empty allow-list means AXFR is refused for everyone,
        unlike ordinary query ACLs which default to allow-all."""
        raw_acl = self._get_setting("axfr_allowed_clients", "")
        if not raw_acl.strip():
            return None, "refused"
        allowed = False
        try:
            ip = ipaddress.ip_address(client_ip)
            for entry in raw_acl.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                if "/" in entry and ip in ipaddress.ip_network(entry, strict=False):
                    allowed = True
                    break
                if client_ip == entry:
                    allowed = True
                    break
        except ValueError:
            pass
        if not allowed:
            return None, "refused"

        db = self._db()
        zone = dbmod.query(db, "SELECT * FROM zones WHERE name=?", (zone_name.rstrip("."),), one=True)
        if not zone:
            return None, "not_found"
        zone_fqdn = zone["name"].rstrip(".") + "."
        default_ttl = zone["default_ttl"]
        records = [self._synth_soa_rr(zone)]
        other_rows = dbmod.query(db, "SELECT * FROM records WHERE zone_id=? AND NOT (name='@' AND rtype='SOA')",
                                  (zone["id"],))
        for row in other_rows:
            name = zone_fqdn if row["name"] == "@" else f"{row['name']}.{zone_fqdn}"
            records.append(self._row_to_rr(name, row, default_ttl))
        records.append(records[0])  # closing SOA per RFC 5936
        return records, None

    def _log(self, qname, qtype, client_ip, rcode, source, t0):
        try:
            db = self._db()
            latency_ms = (time.time() - t0) * 1000
            dbmod.execute(db, """INSERT INTO query_log (client_ip, qname, qtype, rcode, source, latency_ms)
                                  VALUES (?,?,?,?,?,?)""",
                          (client_ip, qname, qtype, rcode, source, latency_ms))
            row = dbmod.query(db, "SELECT id FROM clients WHERE ip=?", (client_ip,), one=True)
            if row:
                dbmod.execute(db, "UPDATE clients SET last_seen=datetime('now'), query_count=query_count+1 WHERE ip=?",
                              (client_ip,))
            else:
                dbmod.execute(db, "INSERT INTO clients (ip, query_count) VALUES (?, 1)", (client_ip,))
        except Exception:
            pass  # logging must never break resolution
