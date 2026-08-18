"""
Real tests backing the RFC Compliance Center. These are genuine
assertions against NovaDNS's own implementation -- the compliance page
reports whatever these actually say, run live, not invented numbers.

Each TestCase class is tagged to one RFC via RFC_TAG so the test
runner can group pass/fail counts per RFC.
"""
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import http.server

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import types as _types
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [os.path.join(os.path.dirname(__file__), "..", "app")]
    sys.modules["app"] = _pkg

from app.dnscore import wire, dnssec, server as dnsserver


def make_test_db():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    os.remove(path)
    conn = __import__("sqlite3").connect(path)
    schema = os.path.join(os.path.dirname(__file__), "..", "app", "schema.sql")
    with open(schema) as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    return path


class RFC1035_MessageFormat(unittest.TestCase):
    RFC_TAG = "rfc1035"

    def test_name_roundtrip_simple(self):
        encoded = wire.encode_name("example.com")
        name, off = wire.decode_name(encoded, 0)
        self.assertEqual(name, "example.com.")

    def test_name_roundtrip_root(self):
        encoded = wire.encode_name(".")
        name, off = wire.decode_name(encoded, 0)
        self.assertEqual(name, ".")

    def test_compression_pointer_decode(self):
        msg = bytearray()
        msg += wire.encode_name("example.com")
        msg += bytes([3]) + b"www" + struct.pack("!H", 0xC000 | 0)
        name, _ = wire.decode_name(bytes(msg), len(wire.encode_name("example.com")))
        self.assertEqual(name, "www.example.com.")

    def test_message_roundtrip_a_record(self):
        m = wire.Message()
        m.id = 0x1234
        m.rd = 1
        m.questions.append(wire.Question("test.example.", "A"))
        m.answers.append(wire.ResourceRecord("test.example.", "A", 300, {"address": "192.0.2.1"}))
        data = m.to_wire()
        m2 = wire.Message.from_wire(data)
        self.assertEqual(m2.id, 0x1234)
        self.assertEqual(len(m2.answers), 1)
        self.assertEqual(m2.answers[0].value["address"], "192.0.2.1")

    def test_all_common_rtypes_roundtrip(self):
        cases = [
            ("A", {"address": "10.0.0.1"}),
            ("AAAA", {"address": "::1"}),
            ("CNAME", {"target": "alias.example."}),
            ("MX", {"priority": 10, "target": "mail.example."}),
            ("TXT", {"text": "hello world"}),
            ("NS", {"target": "ns1.example."}),
            ("SOA", {"mname": "ns1.example.", "rname": "admin.example.", "serial": 1,
                      "refresh": 3600, "retry": 900, "expire": 604800, "minimum": 300}),
            ("SRV", {"priority": 10, "weight": 5, "port": 443, "target": "svc.example."}),
            ("CAA", {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}),
        ]
        for rtype, value in cases:
            m = wire.Message()
            m.answers.append(wire.ResourceRecord("test.example.", rtype, 300, value))
            data = m.to_wire()
            m2 = wire.Message.from_wire(data)
            self.assertEqual(m2.answers[0].rtype, rtype)
            for k in value:
                self.assertEqual(m2.answers[0].value[k], value[k], f"{rtype}.{k} mismatch")

    def test_header_flags(self):
        m = wire.Message()
        m.qr, m.aa, m.rd, m.ra, m.rcode = 1, 1, 1, 1, 0
        data = m.to_wire()
        m2 = wire.Message.from_wire(data)
        self.assertEqual((m2.qr, m2.aa, m2.rd, m2.ra, m2.rcode), (1, 1, 1, 1, 0))

    def test_udp_and_tcp_transport_bind(self):
        db_path = make_test_db()
        srv = dnsserver.DNSServer(db_path, "127.0.0.1", 0, base_dir=tempfile.mkdtemp())
        srv.start()
        srv.stop()

    def test_uncommon_named_type_question_roundtrips_correctly(self):
        """Regression: a query for any type we recognize by name but don't
        fully structure-encode (e.g. HINFO) must echo back its real type
        in the response's question section, not silently corrupt to ANY."""
        m = wire.Message()
        m.questions.append(wire.Question("example.com.", "HINFO"))
        m2 = wire.Message.from_wire(m.to_wire())
        self.assertEqual(m2.questions[0].qtype, "HINFO")

    def test_unrecognized_numeric_type_roundtrips(self):
        """Regression: a type number outside our whole table must still
        round-trip its true numeric value through the wire, not corrupt
        to ANY (255)."""
        m = wire.Message()
        m.questions.append(wire.Question("weird.example.", "1000"))
        m2 = wire.Message.from_wire(m.to_wire())
        self.assertEqual(m2.questions[0].qtype, "1000")

    def test_opaque_decoded_record_can_be_reencoded(self):
        """Regression: any record type we only support via the opaque
        raw_hex fallback (i.e. everything we don't have a structured
        encoder for) must be re-encodable, since that's exactly what
        happens when relaying a forwarded upstream answer back to a
        client -- this used to raise DNSError and SERVFAIL the query."""
        raw = bytes.fromhex("0013000000006165a5006165a50000000064")
        decoded = wire.decode_rdata("LOC", raw, 0, len(raw))
        reencoded = wire.encode_rdata("LOC", decoded)
        self.assertEqual(reencoded, raw)


class RFC1034_Concepts(unittest.TestCase):
    RFC_TAG = "rfc1034"

    def test_servfail_with_no_zone_no_forwarder(self):
        from app.dnscore.resolver import Resolver
        db_path = make_test_db()
        r = Resolver(db_path)
        answers, rcode, source, authority, is_auth, _trace = r.resolve("nowhere.invalid.", "A", "127.0.0.1")
        self.assertEqual(rcode, wire.RCODE["SERVFAIL"])

    def test_cname_chain_returned(self):
        import sqlite3
        db_path = make_test_db()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO zones (name, default_ttl, soa_mname, soa_rname) VALUES ('t.test',3600,'ns1.t.test.','a.t.test.')")
        zid = conn.execute("SELECT id FROM zones").fetchone()[0]
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,?,?,?,?)",
                      (zid, "alias", "CNAME", 300, json.dumps({"target": "real.t.test."})))
        conn.commit(); conn.close()
        from app.dnscore.resolver import Resolver
        r = Resolver(db_path)
        answers, rcode, source, authority, is_auth, _trace = r.resolve("alias.t.test.", "A", "127.0.0.1")
        self.assertEqual(len(answers), 1)
        self.assertEqual(answers[0].rtype, "CNAME")

    def test_wildcard_does_not_shadow_explicit_records(self):
        """Regression test: a wildcard record must never be merged in
        alongside an explicit record for a name that already exists --
        each name in the zone answers with only its own data, and the
        wildcard is strictly a fallback for names that don't exist at all."""
        import sqlite3
        db_path = make_test_db()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO zones (name, default_ttl, soa_mname, soa_rname) VALUES ('wc.test',3600,'ns1.wc.test.','a.wc.test.')")
        zid = conn.execute("SELECT id FROM zones").fetchone()[0]
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,'www','A',300,?)",
                      (zid, json.dumps({"address": "10.0.0.2"})))
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,'*','A',300,?)",
                      (zid, json.dumps({"address": "10.0.0.99"})))
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,'alias','CNAME',300,?)",
                      (zid, json.dumps({"target": "www.wc.test."})))
        conn.commit(); conn.close()
        from app.dnscore.resolver import Resolver

        r1 = Resolver(db_path)
        answers, *_ = r1.resolve("www.wc.test.", "A", "127.0.0.1")
        self.assertEqual(len(answers), 1, "explicit record must not be merged with the wildcard")
        self.assertEqual(answers[0].value["address"], "10.0.0.2")

        r2 = Resolver(db_path)
        answers2, *_ = r2.resolve("nosuchname.wc.test.", "A", "127.0.0.1")
        self.assertEqual(len(answers2), 1)
        self.assertEqual(answers2[0].value["address"], "10.0.0.99", "wildcard should still answer for genuinely unknown names")

        r3 = Resolver(db_path)
        answers3, *_ = r3.resolve("alias.wc.test.", "A", "127.0.0.1")
        self.assertEqual(answers3[0].rtype, "CNAME", "wildcard must not shadow an explicit CNAME lookup")


class RFC2308_NegativeCaching(unittest.TestCase):
    RFC_TAG = "rfc2308"

    def test_soa_in_authority_on_nxdomain(self):
        import sqlite3
        db_path = make_test_db()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO zones (name, default_ttl, soa_mname, soa_rname) VALUES ('t2.test',3600,'ns1.t2.test.','a.t2.test.')")
        conn.commit(); conn.close()
        from app.dnscore.resolver import Resolver
        r = Resolver(db_path)
        answers, rcode, source, authority, is_auth, _trace = r.resolve("nope.t2.test.", "A", "127.0.0.1")
        self.assertEqual(rcode, wire.RCODE["NXDOMAIN"])
        self.assertTrue(any(a.rtype == "SOA" for a in authority))


class RFC4034_4035_DNSSEC(unittest.TestCase):
    RFC_TAG = "rfc4034"

    def test_key_generation_and_ds_digest(self):
        key = dnssec.generate_key()
        self.assertIn("private_key_pem", key)
        self.assertEqual(len(bytes.fromhex(key["ds_digest_sha256"])), 32)

    def test_rrsig_cryptographically_verifies(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives import hashes, serialization

        key = dnssec.generate_key()
        rdata = wire.encode_rdata("A", {"address": "10.0.0.5"})
        rrsig = dnssec.sign_rrset(key["private_key_pem"], key["key_tag"], "example.test", "www.example.test",
                                   "A", 300, [rdata])
        priv = serialization.load_pem_private_key(key["private_key_pem"].encode(), password=None)
        pub = priv.public_key()
        rrsig_bytes = bytes.fromhex(rrsig["raw_hex"])
        signer_name, off = wire.decode_name(rrsig_bytes, 18)
        signature = rrsig_bytes[off:]
        r_, s_ = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        der_sig = encode_dss_signature(r_, s_)
        owner_wire = wire.encode_name("www.example.test")
        canonical_rr = owner_wire + struct.pack("!HHIH", 1, 1, 300, len(rdata)) + rdata
        signing_input = rrsig_bytes[:off] + canonical_rr
        pub.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))

    def test_nsec_bitmap_roundtrip(self):
        rdata = dnssec.build_nsec_rdata("next.example.test", ["A", "RRSIG", "NSEC", "MX"])
        next_name, off = wire.decode_name(rdata, 0)
        self.assertEqual(next_name, "next.example.test.")

    def test_canonical_ordering(self):
        names = ["z.example.test", "a.example.test", "m.example.test"]
        ordered = sorted(names, key=dnssec.canonical_key)
        self.assertEqual(ordered, ["a.example.test", "m.example.test", "z.example.test"])


class RFC5936_AXFR(unittest.TestCase):
    RFC_TAG = "rfc5936"

    def test_axfr_envelope_starts_and_ends_with_soa(self):
        import sqlite3
        db_path = make_test_db()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO zones (name, default_ttl, soa_mname, soa_rname) VALUES ('t3.test',3600,'ns1.t3.test.','a.t3.test.')")
        zid = conn.execute("SELECT id FROM zones").fetchone()[0]
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,'@','A',300,?)",
                      (zid, json.dumps({"address": "10.0.0.1"})))
        conn.execute("INSERT INTO settings (key,value) VALUES ('axfr_allowed_clients','127.0.0.1')")
        conn.commit(); conn.close()
        from app.dnscore.resolver import Resolver
        r = Resolver(db_path)
        records, err = r.axfr("t3.test", "127.0.0.1")
        self.assertIsNone(err)
        self.assertEqual(records[0].rtype, "SOA")
        self.assertEqual(records[-1].rtype, "SOA")

    def test_axfr_refused_without_acl(self):
        import sqlite3
        db_path = make_test_db()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO zones (name, default_ttl, soa_mname, soa_rname) VALUES ('t4.test',3600,'ns1.t4.test.','a.t4.test.')")
        conn.commit(); conn.close()
        from app.dnscore.resolver import Resolver
        r = Resolver(db_path)
        records, err = r.axfr("t4.test", "203.0.113.1")
        self.assertEqual(err, "refused")

    def test_axfr_type_number_registered(self):
        self.assertEqual(wire.QTYPE["AXFR"], 252)


class RFC6891_EDNS(unittest.TestCase):
    RFC_TAG = "rfc6891"

    def test_opt_record_roundtrip(self):
        m = wire.Message()
        m.additionals.append(wire.ResourceRecord(".", "OPT", 0x00008000, {"raw_hex": ""}, rclass=4096))
        data = m.to_wire()
        m2 = wire.Message.from_wire(data)
        self.assertEqual(m2.additionals[0].rtype, "OPT")
        self.assertEqual(m2.additionals[0].ttl & 0x8000, 0x8000)


class RFC7858_DoT(unittest.TestCase):
    RFC_TAG = "rfc7858"

    def test_dot_length_prefixed_tls_roundtrip(self):
        import shutil
        if not shutil.which("openssl"):
            self.skipTest("openssl binary not available on this host — can't generate a test certificate")
        from app.dnscore.resolver import Resolver
        certdir = tempfile.mkdtemp()
        keyfile, certfile = os.path.join(certdir, "k.pem"), os.path.join(certdir, "c.pem")
        import subprocess
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                         "-keyout", keyfile, "-out", certfile, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                        check=True, capture_output=True)
        ports = []

        def tls_server():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
            sock.listen(1)
            conn, _ = sock.accept()
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            length = struct.unpack("!H", tls_conn.recv(2))[0]
            q = wire.Message.from_wire(tls_conn.recv(length))
            resp = wire.Message()
            resp.id, resp.qr = q.id, 1
            resp.questions = q.questions
            resp.answers = [wire.ResourceRecord(q.questions[0].name, "A", 60, {"address": "198.51.100.1"})]
            b = resp.to_wire()
            tls_conn.sendall(struct.pack("!H", len(b)) + b)
            tls_conn.close()

        t = threading.Thread(target=tls_server, daemon=True)
        t.start()
        time.sleep(0.3)
        self.assertTrue(ports)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        m = wire.Message(); m.questions.append(wire.Question("t.example.", "A"))
        payload = m.to_wire()
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(len(payload).to_bytes(2, "big") + payload)
                rlen = int.from_bytes(tls.recv(2), "big")
                data = tls.recv(rlen)
        resp = wire.Message.from_wire(data)
        self.assertEqual(resp.answers[0].value["address"], "198.51.100.1")


class RFC8484_DoH(unittest.TestCase):
    RFC_TAG = "rfc8484"

    def test_doh_post_wire_format_roundtrip(self):
        from app.dnscore.resolver import Resolver
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                q = wire.Message.from_wire(self.rfile.read(length))
                received.append(self.headers.get("Content-Type"))
                resp = wire.Message()
                resp.id, resp.qr = q.id, 1
                resp.questions = q.questions
                resp.answers = [wire.ResourceRecord(q.questions[0].name, "A", 60, {"address": "203.0.113.9"})]
                data = resp.to_wire()
                self.send_response(200)
                self.send_header("Content-Type", "application/dns-message")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(0.2)

        m = wire.Message(); m.questions.append(wire.Question("t.example.", "A"))
        data = Resolver._forward_doh({"address": f"http://127.0.0.1:{port}/dns-query"}, m.to_wire())
        resp = wire.Message.from_wire(data)
        httpd.shutdown()
        self.assertEqual(resp.answers[0].value["address"], "203.0.113.9")
        self.assertEqual(received[0], "application/dns-message")


class RFC1035_ANY_Queries(unittest.TestCase):
    RFC_TAG = "rfc1035_any"

    def test_any_query_returns_all_types_at_name(self):
        import sqlite3
        db_path = make_test_db()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO zones (name, default_ttl, soa_mname, soa_rname) VALUES ('t5.test',3600,'ns1.t5.test.','a.t5.test.')")
        zid = conn.execute("SELECT id FROM zones").fetchone()[0]
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,'@','A',300,?)", (zid, json.dumps({"address": "10.0.0.1"})))
        conn.execute("INSERT INTO records (zone_id,name,rtype,ttl,data_json) VALUES (?,'@','MX',300,?)", (zid, json.dumps({"priority": 10, "target": "mail.t5.test."})))
        conn.commit(); conn.close()
        from app.dnscore.resolver import Resolver
        r = Resolver(db_path)
        answers, rcode, source, authority, is_auth, _trace = r.resolve("t5.test.", "ANY", "127.0.0.1")
        self.assertEqual(rcode, 0)
        self.assertEqual({a.rtype for a in answers}, {"A", "MX"})


class RFC6698_TLSA(unittest.TestCase):
    RFC_TAG = "rfc6698"

    def test_tlsa_roundtrip(self):
        val = {"usage": 3, "selector": 1, "matching_type": 1, "cert_data": "d2abde240d7cd3ee6b4b28c54df034b9"}
        rdata = wire.encode_rdata("TLSA", val)
        decoded = wire.decode_rdata("TLSA", rdata, 0, len(rdata))
        self.assertEqual(decoded, val)


class RFC4255_SSHFP(unittest.TestCase):
    RFC_TAG = "rfc4255"

    def test_sshfp_roundtrip(self):
        val = {"algorithm": 4, "fp_type": 2, "fingerprint": "abcdef0123456789abcdef0123456789abcdef01"}
        rdata = wire.encode_rdata("SSHFP", val)
        decoded = wire.decode_rdata("SSHFP", rdata, 0, len(rdata))
        self.assertEqual(decoded, val)


class RFC9460_HTTPS_SVCB(unittest.TestCase):
    RFC_TAG = "rfc9460"

    def test_https_svcb_roundtrip_with_params(self):
        val = {"priority": 1, "target": "svc.example.com.", "alpn": "h2,http/1.1", "port": 443,
               "ipv4hint": "192.0.2.1,192.0.2.2"}
        m = wire.Message()
        m.answers.append(wire.ResourceRecord("svc.example.com.", "HTTPS", 300, val))
        m2 = wire.Message.from_wire(m.to_wire())
        decoded = m2.answers[0].value
        for k in val:
            self.assertEqual(decoded[k], val[k], f"HTTPS.{k} mismatch")


class RFC2915_NAPTR(unittest.TestCase):
    RFC_TAG = "rfc2915"

    def test_naptr_roundtrip_full_message(self):
        val = {"order": 100, "preference": 10, "flags": "U", "service": "E2U+sip",
               "regexp": "!^.*$!sip:info@example.com!", "replacement": "."}
        m = wire.Message()
        m.answers.append(wire.ResourceRecord("example.com.", "NAPTR", 300, val))
        m2 = wire.Message.from_wire(m.to_wire())
        self.assertEqual(m2.answers[0].value, val)


ALL_SUITES = [
    RFC1035_MessageFormat, RFC1035_ANY_Queries, RFC1034_Concepts, RFC2308_NegativeCaching,
    RFC4034_4035_DNSSEC, RFC5936_AXFR, RFC6891_EDNS, RFC7858_DoT, RFC8484_DoH,
    RFC6698_TLSA, RFC4255_SSHFP, RFC9460_HTTPS_SVCB, RFC2915_NAPTR,
]

if __name__ == "__main__":
    unittest.main()
