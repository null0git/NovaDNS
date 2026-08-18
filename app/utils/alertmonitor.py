"""Background thread that turns 'things NovaDNS already knows about'
(unhealthy forwarders, high resource usage, stale backups) into actual
delivered notifications, with basic dedup so a still-ongoing problem
doesn't re-fire every cycle."""
import threading
import time
import json as _json

from .. import db as dbmod
from . import detect
from . import notify
from .logsetup import get_logger


class AlertMonitor:
    def __init__(self, db_path, get_dns_server_fn, base_dir, interval=30):
        self.db_path = db_path
        self.get_dns_server_fn = get_dns_server_fn
        self.interval = interval
        self.log = get_logger(base_dir)
        self._thread = None
        self._running = False
        self._recent = {}  # message -> last-fired timestamp, in-process dedup

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="novadns-alerts")
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._tick()
            except Exception as e:
                self.log.error(f"alert monitor tick failed: {e}")
            time.sleep(self.interval)

    def _db(self):
        return dbmod.get_db_nocontext(self.db_path)

    def _fire(self, severity, message, dedup_seconds=1800):
        now = time.time()
        if now - self._recent.get(message, 0) < dedup_seconds:
            return
        self._recent[message] = now
        db = self._db()
        dbmod.execute(db, "INSERT INTO alerts (severity, message) VALUES (?,?)", (severity, message))
        channels = dbmod.query(db, "SELECT * FROM notification_channels WHERE enabled=1")
        for ch in channels:
            config = _json.loads(ch["config_json"])
            ok, err = notify.dispatch(ch["channel"], config, message, subject=f"NovaDNS [{severity}]")
            if not ok:
                self.log.error(f"notification via {ch['channel']} failed: {err}")

    def _tick(self):
        db = self._db()
        srv = self.get_dns_server_fn()

        if srv and not srv.is_running():
            self._fire("critical", f"DNS listener is down: {srv.bind_error}")

        unhealthy = dbmod.query(db, "SELECT * FROM forwarders WHERE enabled=1 AND healthy=0")
        for fw in unhealthy:
            self._fire("warning", f"Upstream forwarder {fw['address']}:{fw['port']} is unhealthy")

        res = detect.get_system_resources()
        if res.get("cpu_percent") and res["cpu_percent"] > 90:
            self._fire("warning", f"CPU usage is high: {res['cpu_percent']}%")
        if res.get("memory_percent") and res["memory_percent"] > 90:
            self._fire("warning", f"Memory usage is high: {res['memory_percent']}%")
        if res.get("disk_percent") and res["disk_percent"] > 90:
            self._fire("warning", f"Disk usage is high: {res['disk_percent']}%")

        last_backup = dbmod.query(db, "SELECT * FROM backups ORDER BY created_at DESC LIMIT 1", one=True)
        if not last_backup:
            self._fire("info", "No backups have been taken yet", dedup_seconds=6 * 3600)

        maint = dbmod.query(db, "SELECT * FROM maintenance WHERE id=1", one=True)
        if maint and maint["enabled"]:
            self._fire("info", f"Maintenance mode is active: {maint['message']}", dedup_seconds=6 * 3600)
