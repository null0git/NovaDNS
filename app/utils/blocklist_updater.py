"""Scheduled blocklist updates. Real HTTP fetch via urllib, parsing the
two common public blocklist formats:
  - hosts-file style: "0.0.0.0 domain.com" / "127.0.0.1 domain.com"
  - plain domain list: one domain per line
Comments (#) and blank lines are ignored either way."""
import re
import threading
import time
import urllib.request
import urllib.error

from .. import db as dbmod
from .logsetup import get_logger

TIMEOUT = 15
HOSTS_LINE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.\-]+)")
DOMAIN_LINE = re.compile(r"^\s*([a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})\s*$")


def parse_blocklist_text(text):
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = HOSTS_LINE.match(line)
        if m:
            domains.add(m.group(1).lower())
            continue
        m = DOMAIN_LINE.match(line)
        if m:
            domains.add(m.group(1).lower())
    domains.discard("localhost")
    return domains


def fetch_and_sync(db_path_or_conn, blocklist_id, source_url):
    req = urllib.request.Request(source_url, headers={"User-Agent": "NovaDNS/4.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    domains = parse_blocklist_text(text)

    db = db_path_or_conn
    dbmod.execute(db, "DELETE FROM block_entries WHERE blocklist_id=?", (blocklist_id,))
    for d in domains:
        dbmod.execute(db, "INSERT INTO block_entries (blocklist_id, domain, list_type) VALUES (?,?,'block')", (blocklist_id, d))
    dbmod.execute(db, "UPDATE blocklists SET last_updated=datetime('now'), entry_count=? WHERE id=?",
                  (len(domains), blocklist_id))
    return len(domains)


class BlocklistUpdater:
    def __init__(self, db_path, base_dir, interval_hours=24):
        self.db_path = db_path
        self.interval = interval_hours * 3600
        self.log = get_logger(base_dir)
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True, name="novadns-blocklists").start()

    def stop(self):
        self._running = False

    def _db(self):
        return dbmod.get_db_nocontext(self.db_path)

    def _loop(self):
        time.sleep(10)  # let the app finish booting first
        while self._running:
            try:
                self._tick()
            except Exception as e:
                self.log.error(f"blocklist updater tick failed: {e}")
            time.sleep(self.interval)

    def _tick(self):
        db = self._db()
        lists = dbmod.query(db, "SELECT * FROM blocklists WHERE enabled=1 AND source_url IS NOT NULL AND source_url != ''")
        for bl in lists:
            try:
                count = fetch_and_sync(db, bl["id"], bl["source_url"])
                self.log.info(f"blocklist '{bl['name']}' synced: {count} entries")
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.log.error(f"blocklist '{bl['name']}' sync failed: {e}")
