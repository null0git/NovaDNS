from .. import db as dbmod
from . import detect


def get_setting(db, key, default=None):
    row = dbmod.query(db, "SELECT value FROM settings WHERE key=?", (key,), one=True)
    return row["value"] if row else default


def set_setting(db, key, value):
    dbmod.execute(db, "INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, str(value)))


def compute_health_score(db, dns_running):
    """Returns dict with overall 0-100 score plus component breakdown and
    plain-language recommendations, used on the home dashboard and the
    dedicated health page."""
    components = {}

    components["dns_availability"] = 100 if dns_running else 0

    res = detect.get_system_resources()
    cpu = res.get("cpu_percent") or 0
    mem = res.get("memory_percent") or 0
    disk = res.get("disk_percent") or 0
    components["cpu"] = max(0, 100 - cpu)
    components["memory"] = max(0, 100 - mem)
    components["disk"] = max(0, 100 - disk)

    forwarders = dbmod.query(db, "SELECT * FROM forwarders WHERE enabled=1")
    if forwarders:
        healthy = sum(1 for f in forwarders if f["healthy"])
        components["upstream_health"] = round(100 * healthy / len(forwarders))
    else:
        components["upstream_health"] = 100  # no forwarders configured = not penalized

    last_backup = dbmod.query(db, "SELECT * FROM backups ORDER BY created_at DESC LIMIT 1", one=True)
    components["backup_status"] = 100 if last_backup else 60

    cert_expiry_days = get_setting(db, "tls_cert_expiry_days")
    if cert_expiry_days is None:
        components["certificate_status"] = 80  # unknown/no cert configured
    else:
        days = int(cert_expiry_days)
        components["certificate_status"] = 100 if days > 14 else (50 if days > 0 else 0)

    weights = {
        "dns_availability": 0.30, "cpu": 0.10, "memory": 0.10, "disk": 0.10,
        "upstream_health": 0.20, "backup_status": 0.10, "certificate_status": 0.10,
    }
    overall = sum(components[k] * w for k, w in weights.items())
    overall = round(max(0, min(100, overall)))

    recommendations = []
    if components["dns_availability"] < 100:
        recommendations.append("The DNS listener is not running — check the port binding and restart the service.")
    if cpu > 80:
        recommendations.append("CPU usage is high. Consider reducing recursive/forwarding load or scaling up.")
    if mem > 85:
        recommendations.append("Memory usage is high — review cache size limits.")
    if disk > 85:
        recommendations.append("Disk usage is high — clear old backups or logs.")
    if components["upstream_health"] < 100:
        recommendations.append("One or more upstream forwarders are unhealthy — check Forwarders.")
    if not last_backup:
        recommendations.append("No backups have been taken yet — create one from Settings → Backups.")
    if components["certificate_status"] < 100:
        recommendations.append("TLS certificate is expiring soon or not configured — check Settings → Certificates.")
    if not recommendations:
        recommendations.append("Everything looks healthy. No action needed.")

    return {"overall": overall, "components": components, "recommendations": recommendations}
