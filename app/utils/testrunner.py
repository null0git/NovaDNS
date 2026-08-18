"""Runs the real test suite (tests/test_rfc_compliance.py) and reports
genuine pass/fail counts grouped by RFC. No numbers here are invented --
whatever the tests actually do is what gets shown."""
import io
import os
import sys
import time
import unittest

RFC_META = {
    "rfc1035": {"title": "RFC 1035 — Domain Names, Implementation and Specification",
                "modules": ["wire.py (message parser/encoder)", "compression", "UDP/TCP transport", "Resource Records"]},
    "rfc1035_any": {"title": "RFC 1035 §3.2.3 — ANY Queries",
                    "modules": ["Returns every real record type at a name, not a literal 'ANY' type"]},
    "rfc1034": {"title": "RFC 1034 — Domain Names, Concepts and Facilities",
                "modules": ["Zone/authoritative model", "CNAME resolution"]},
    "rfc2308": {"title": "RFC 2308 — Negative Caching of DNS Queries",
                "modules": ["SOA in authority section on NXDOMAIN/NODATA"]},
    "rfc4034": {"title": "RFC 4034 / 4035 / 6605 — DNSSEC Records, Protocol & ECDSA",
                "modules": ["DNSKEY", "RRSIG signing/verification (ECDSAP256SHA256)", "NSEC", "canonical ordering"]},
    "rfc4255": {"title": "RFC 4255 — SSHFP Resource Record", "modules": ["Structured algorithm/fp_type/fingerprint encoding"]},
    "rfc5936": {"title": "RFC 5936 — DNS Zone Transfer Protocol (AXFR)",
                "modules": ["AXFR envelope", "AXFR access control"]},
    "rfc6698": {"title": "RFC 6698 — TLSA (DANE)", "modules": ["Structured usage/selector/matching_type encoding"]},
    "rfc6891": {"title": "RFC 6891 — Extension Mechanisms for DNS (EDNS0)", "modules": ["OPT pseudo-record", "DO bit"]},
    "rfc7858": {"title": "RFC 7858 — DNS over TLS", "modules": ["Length-prefixed TLS transport"]},
    "rfc8484": {"title": "RFC 8484 — DNS over HTTPS", "modules": ["POST application/dns-message"]},
    "rfc9460": {"title": "RFC 9460 — HTTPS/SVCB Records", "modules": ["SvcParam encoding: alpn, port, ipv4hint, ipv6hint"]},
    "rfc2915": {"title": "RFC 2915 — NAPTR Resource Record", "modules": ["order/preference/flags/service/regexp/replacement encoding"]},
}

# RFCs we don't claim compliance for -- listed honestly rather than omitted,
# so the page doesn't imply silence means "done".
NOT_IMPLEMENTED = {
    "rfc9250": {"title": "RFC 9250 — DNS over QUIC", "reason": "No pure-stdlib QUIC implementation; aioquic dependency not included."},
    "rfc5155": {"title": "RFC 5155 — NSEC3", "reason": "NSEC is implemented; hashed NSEC3 is not."},
    "rfc8555": {"title": "RFC 8555 — ACME", "reason": "Not implemented; use a reverse proxy for publicly-trusted certificates."},
}


class _Result(unittest.TextTestResult):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.per_test = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.per_test.append({"name": test._testMethodName, "class": test.__class__.__name__,
                               "rfc": getattr(test, "RFC_TAG", None), "status": "pass"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.per_test.append({"name": test._testMethodName, "class": test.__class__.__name__,
                               "rfc": getattr(test, "RFC_TAG", None), "status": "fail",
                               "detail": self._exc_info_to_string(err, test)})

    def addError(self, test, err):
        super().addError(test, err)
        self.per_test.append({"name": test._testMethodName, "class": test.__class__.__name__,
                               "rfc": getattr(test, "RFC_TAG", None), "status": "error",
                               "detail": self._exc_info_to_string(err, test)})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.per_test.append({"name": test._testMethodName, "class": test.__class__.__name__,
                               "rfc": getattr(test, "RFC_TAG", None), "status": "skip", "detail": reason})


def _load_suite_module():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    test_file = os.path.join(base_dir, "tests", "test_rfc_compliance.py")
    if not os.path.exists(test_file):
        raise RuntimeError(f"Compliance test file not found at {test_file} — the 'tests/' folder "
                            f"must sit alongside 'app/' in the project directory.")
    import importlib.util
    spec = importlib.util.spec_from_file_location("novadns_test_rfc_compliance", test_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_compliance_tests():
    suite_module = _load_suite_module()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in suite_module.ALL_SUITES:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, resultclass=_Result, verbosity=0)
    start = time.time()
    result = runner.run(suite)
    elapsed = time.time() - start

    by_rfc = {}
    for t in result.per_test:
        rfc = t["rfc"] or "unclassified"
        by_rfc.setdefault(rfc, {"passed": 0, "failed": 0, "skipped": 0, "tests": []})
        if t["status"] == "pass":
            by_rfc[rfc]["passed"] += 1
        elif t["status"] == "skip":
            by_rfc[rfc]["skipped"] += 1
        else:
            by_rfc[rfc]["failed"] += 1
        by_rfc[rfc]["tests"].append(t)

    rfcs = []
    for tag, meta in RFC_META.items():
        data = by_rfc.get(tag, {"passed": 0, "failed": 0, "skipped": 0, "tests": []})
        total = data["passed"] + data["failed"]  # skipped tests don't count toward compliance %
        pct = round(100 * data["passed"] / total, 1) if total else None
        rfcs.append({
            "tag": tag, "title": meta["title"], "modules": meta["modules"],
            "tests_passed": data["passed"], "tests_failed": data["failed"], "tests_skipped": data["skipped"],
            "compliance_pct": pct, "tests": data["tests"],
            "status": "no_tests" if total == 0 else ("fully_passing" if data["failed"] == 0 else "has_failures"),
        })

    return {
        "rfcs": rfcs,
        "not_implemented": [{"tag": k, **v} for k, v in NOT_IMPLEMENTED.items()],
        "total_passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "total_failed": len(result.failures) + len(result.errors),
        "total_skipped": len(result.skipped),
        "total_run": result.testsRun,
        "elapsed_sec": round(elapsed, 3),
    }
