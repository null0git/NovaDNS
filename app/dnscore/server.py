"""
The network-facing DNS server: UDP and TCP listeners, each in their
own thread, both driven by the same Resolver pipeline.

Reliability notes (learned the hard way from real device testing):
  - We ALWAYS send back a response (SERVFAIL at worst) instead of
    silently dropping a packet on error. A dropped UDP packet means the
    client just times out and retries/gives up -- which looks exactly
    like "the DNS server isn't working" even when 99% of it is fine.
  - Every exception is logged to logs/novadns.log instead of swallowed,
    so failures are debuggable instead of invisible.
  - We echo EDNS0 (OPT pseudo-record) support back to the client when
    it's offered, which several modern stub resolvers (systemd-resolved,
    Windows) expect before they'll trust a response.
"""
import ipaddress
import socket
import struct
import threading
import time

from . import wire
from .resolver import Resolver
from .ratelimit import RateLimiter
from ..utils.logsetup import get_logger


class DNSServer:
    def __init__(self, db_path, bind_addr="0.0.0.0", port=53, base_dir=None):
        self.db_path = db_path
        self.bind_addr = bind_addr
        self.port = port
        self.resolver = Resolver(db_path)
        self.rate_limiter = RateLimiter(capacity=200, refill_per_sec=100)
        self.log = get_logger(base_dir or ".")
        self._udp_sock = None
        self._tcp_sock = None
        self._threads = []
        self._running = False
        self.started_at = None
        self.bind_error = None
        self.stats = {"queries": 0, "refused_acl": 0, "rate_limited": 0, "errors": 0}

    def start(self):
        self._running = True
        self.started_at = time.time()
        try:
            self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_sock.bind((self.bind_addr, self.port))
            t = threading.Thread(target=self._udp_loop, daemon=True, name="novadns-udp")
            t.start()
            self._threads.append(t)
            self.log.info(f"UDP listener bound on {self.bind_addr}:{self.port}")
        except Exception as e:
            self.bind_error = str(e)
            self.log.error(f"UDP bind failed on {self.bind_addr}:{self.port} - {e}")

        try:
            self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_sock.bind((self.bind_addr, self.port))
            self._tcp_sock.listen(128)
            t = threading.Thread(target=self._tcp_loop, daemon=True, name="novadns-tcp")
            t.start()
            self._threads.append(t)
            self.log.info(f"TCP listener bound on {self.bind_addr}:{self.port}")
        except Exception as e:
            if not self.bind_error:
                self.bind_error = str(e)
            self.log.error(f"TCP bind failed on {self.bind_addr}:{self.port} - {e}")

    def stop(self):
        self._running = False
        for s in (self._udp_sock, self._tcp_sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass

    def is_running(self):
        return self._running and self.bind_error is None

    # ------------------------------------------------------------- UDP

    def _udp_loop(self):
        while self._running:
            try:
                data, addr = self._udp_sock.recvfrom(65535)
            except OSError:
                break
            except Exception as e:
                self.log.error(f"UDP recv error: {e}")
                continue
            threading.Thread(target=self._handle_udp_packet, args=(data, addr), daemon=True).start()

    def _handle_udp_packet(self, data, addr):
        resp_bytes = self._safe_process(data, addr[0])
        try:
            if resp_bytes and self._udp_sock:
                self._udp_sock.sendto(resp_bytes, addr)
        except Exception as e:
            self.log.error(f"UDP send error to {addr}: {e}")

    # ------------------------------------------------------------- TCP

    def _tcp_loop(self):
        while self._running:
            try:
                conn, addr = self._tcp_sock.accept()
            except OSError:
                break
            except Exception as e:
                self.log.error(f"TCP accept error: {e}")
                continue
            threading.Thread(target=self._handle_tcp_conn, args=(conn, addr), daemon=True).start()

    def _handle_tcp_conn(self, conn, addr):
        try:
            conn.settimeout(8.0)
            length_bytes = conn.recv(2)
            if len(length_bytes) < 2:
                return
            (length,) = struct.unpack("!H", length_bytes)
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            resp_bytes = self._safe_process(data, addr[0], via_tcp=True)
            if resp_bytes:
                conn.sendall(struct.pack("!H", len(resp_bytes)) + resp_bytes)
        except Exception as e:
            self.log.error(f"TCP handling error from {addr}: {e}")
        finally:
            conn.close()

    # ---------------------------------------------------------- pipeline

    def _safe_process(self, data, client_ip, via_tcp=False):
        """Wraps _process so a bug anywhere in the pipeline still yields a
        SERVFAIL reply instead of a silently dropped packet."""
        self.stats["queries"] += 1
        try:
            return self._process(data, client_ip, via_tcp=via_tcp)
        except Exception as e:
            self.stats["errors"] += 1
            self.log.error(f"resolve error for {client_ip}: {e}")
            try:
                query = wire.Message.from_wire(data)
                resp = wire.Message()
                resp.id = query.id
                resp.qr = 1
                resp.rd = query.rd
                resp.ra = 1
                resp.rcode = wire.RCODE["SERVFAIL"]
                resp.questions = query.questions
                return resp.to_wire()
            except Exception:
                return None  # truly unparseable input - nothing safe to reply with

    def _process(self, data, client_ip, via_tcp=False):
        query = wire.Message.from_wire(data)
        resp = wire.Message()
        resp.id = query.id
        resp.qr = 1
        resp.opcode = query.opcode
        resp.rd = query.rd
        resp.ra = 1
        resp.questions = query.questions

        client_wants_edns = any(rr.rtype == "OPT" for rr in query.additionals)
        dnssec_ok = any(rr.rtype == "OPT" and (rr.ttl & 0x00008000) for rr in query.additionals)

        if not query.questions:
            resp.rcode = wire.RCODE["FORMERR"]
            return resp.to_wire()

        if not self.resolver.is_allowed_by_acl(client_ip):
            self.stats["refused_acl"] += 1
            resp.rcode = wire.RCODE["REFUSED"]
            return resp.to_wire()

        if not self.rate_limiter.allow(client_ip):
            self.stats["rate_limited"] += 1
            resp.rcode = wire.RCODE["REFUSED"]
            return resp.to_wire()

        q = query.questions[0]

        if q.qtype == "AXFR":
            if not via_tcp:
                resp.rcode = wire.RCODE["REFUSED"]  # AXFR must use TCP (RFC 5936); tell the client to retry there
                return resp.to_wire()
            records, error = self.resolver.axfr(q.name, client_ip)
            if error == "refused":
                resp.rcode = wire.RCODE["REFUSED"]
            elif error == "not_found":
                resp.rcode = wire.RCODE["NXDOMAIN"]
            else:
                resp.aa = 1
                resp.rcode = 0
                resp.answers = records
            return resp.to_wire()

        answers, rcode, source, authority, is_authoritative, _trace = self.resolver.resolve(
            q.name, q.qtype, client_ip, dnssec_ok=dnssec_ok)
        resp.aa = 1 if is_authoritative else 0
        resp.rcode = rcode
        resp.answers = answers
        resp.authorities = authority
        if client_wants_edns:
            resp.additionals = [wire.ResourceRecord(".", "OPT", 0, {"raw_hex": ""}, rclass=1232)]
        return resp.to_wire()
