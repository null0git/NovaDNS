import socket
import platform
import shutil
import os

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False


def get_local_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if not ip.startswith("127.") and ip != "::1":
                ips.add(ip)
    except Exception:
        pass
    # also probe outbound-socket trick (doesn't actually send packets)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    if not ips:
        ips.add("127.0.0.1")
    return sorted(ips)


def get_hostname_fqdn():
    try:
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
    except Exception:
        hostname, fqdn = "novadns", "novadns.local"
    return hostname, fqdn


def get_network_interfaces():
    ifaces = []
    if HAVE_PSUTIL:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                stats = psutil.net_if_stats().get(name)
                ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), None)
                ipv6 = next((a.address for a in addrs if a.family == socket.AF_INET6), None)
                ifaces.append({
                    "name": name, "ipv4": ipv4, "ipv6": ipv6,
                    "up": bool(stats.isup) if stats else None,
                })
        except Exception:
            pass
    return ifaces


def get_system_resources():
    data = {"cpu_percent": None, "memory_percent": None, "disk_percent": None,
            "memory_total_gb": None, "disk_total_gb": None, "load_avg": None}
    if HAVE_PSUTIL:
        try:
            data["cpu_percent"] = psutil.cpu_percent(interval=0.15)
            vm = psutil.virtual_memory()
            data["memory_percent"] = vm.percent
            data["memory_total_gb"] = round(vm.total / (1024 ** 3), 1)
            du = psutil.disk_usage("/")
            data["disk_percent"] = du.percent
            data["disk_total_gb"] = round(du.total / (1024 ** 3), 1)
        except Exception:
            pass
    try:
        data["load_avg"] = os.getloadavg()
    except (AttributeError, OSError):
        pass
    return data


def get_os_summary():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
    }


def port_is_free(port, bind_addr="0.0.0.0"):
    for family, socktype in ((socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_INET, socket.SOCK_STREAM)):
        s = socket.socket(family, socktype)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((bind_addr, port))
        except OSError:
            s.close()
            return False
        s.close()
    return True


def disk_free_gb(path="/"):
    try:
        total, used, free = shutil.disk_usage(path)
        return round(free / (1024 ** 3), 1)
    except Exception:
        return None
