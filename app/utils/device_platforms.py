"""Per-platform DNS connection instructions, shared between the
authenticated Device Setup Center and the public status page (so
visitors who aren't logged in can still see how to point their device
at this server)."""

PLATFORMS = [
    {"id": "windows", "name": "Windows", "steps": [
        "Open Settings → Network & Internet → Change adapter options.",
        "Right-click your active adapter → Properties.",
        "Select Internet Protocol Version 4 (TCP/IPv4) → Properties.",
        "Choose 'Use the following DNS server addresses' and enter the server IP shown below.",
        "Click OK, then run 'ipconfig /flushdns' from Command Prompt."]},
    {"id": "macos", "name": "macOS", "steps": [
        "Open System Settings → Network.",
        "Select your active connection → Details… (or DNS tab).",
        "Add the server IP shown below under DNS Servers.",
        "Click OK / Apply, then run 'sudo dscacheutil -flushcache' in Terminal."]},
    {"id": "linux", "name": "Linux", "steps": [
        "For NetworkManager: nmcli connection modify <conn> ipv4.dns \"<server-ip>\"",
        "Then: nmcli connection up <conn>",
        "For systemd-resolved: edit /etc/systemd/resolved.conf, set DNS=<server-ip>, then restart the service."]},
    {"id": "android", "name": "Android", "steps": [
        "Open Settings → Network & Internet → Private DNS (Android 9+) or per-Wi-Fi DNS override.",
        "Enter the server IP shown below.",
        "Save and reconnect to Wi-Fi to apply."]},
    {"id": "ios", "name": "iPhone / iPad", "steps": [
        "Open Settings → Wi-Fi → tap the (i) next to your network.",
        "Scroll to DNS → Configure DNS → Manual.",
        "Remove existing servers, add the IP shown below."]},
    {"id": "chromeos", "name": "ChromeOS", "steps": [
        "Open Settings → Network → Wi-Fi → your network → Network → Name servers.",
        "Choose Custom name servers and enter the server IP below."]},
    {"id": "router", "name": "Router", "steps": [
        "Log into your router's admin page (commonly 192.168.1.1 or 192.168.0.1).",
        "Find the WAN/Internet or DHCP DNS settings.",
        "Replace the primary DNS with the server IP below so all devices on the network use it automatically."]},
    {"id": "docker", "name": "Docker", "steps": [
        "Run containers with: docker run --dns=<server-ip> ...",
        "Or set it globally in /etc/docker/daemon.json: { \"dns\": [\"<server-ip>\"] } and restart the Docker daemon."]},
    {"id": "vm", "name": "Virtual Machine", "steps": [
        "Edit the VM's network adapter settings in your hypervisor.",
        "Set a static DNS entry pointing at the server IP below, or configure it inside the guest OS as with a physical machine."]},
    {"id": "cloud", "name": "Cloud Platform", "steps": [
        "In your VPC/network settings, set the custom DNS resolver to the server IP below.",
        "Ensure security groups/firewall rules allow UDP/TCP port 53 from your instances."]},
]
