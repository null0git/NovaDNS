#!/usr/bin/env python3
"""
Run NovaDNS.

  python3 run.py

Environment variables:
  NOVADNS_DB        path to the SQLite database (default: ./data/novadns.sqlite)
  NOVADNS_SECRET    Flask session secret (set a real one in production)
  NOVADNS_BIND      address the DNS server binds to (default: 0.0.0.0)
  NOVADNS_DNS_PORT  DNS listener port (default: 5353; use 53 for production —
                     see README for granting the port-53 capability without root)
  NOVADNS_WEB_PORT  web UI port (default: 8080)
"""
import os
import sqlite3
from app import create_app

app = create_app()


def _tls_context():
    try:
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        rows = dict(conn.execute("SELECT key, value FROM settings WHERE key IN "
                                  "('https_enabled','tls_cert_path','tls_key_path')").fetchall())
        conn.close()
    except Exception:
        return None
    if rows.get("https_enabled") == "1" and rows.get("tls_cert_path") and rows.get("tls_key_path"):
        if os.path.exists(rows["tls_cert_path"]) and os.path.exists(rows["tls_key_path"]):
            return (rows["tls_cert_path"], rows["tls_key_path"])
    return None


if __name__ == "__main__":
    port = int(os.environ.get("NOVADNS_WEB_PORT", "8080"))
    ssl_context = _tls_context()
    if ssl_context:
        print(f"Serving admin UI over HTTPS on port {port} (self-signed certificate)")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("NOVADNS_DEBUG") == "1", ssl_context=ssl_context)
