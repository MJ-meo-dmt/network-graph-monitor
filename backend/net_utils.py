# net_utils.py
import socket
import ipaddress

RDNS_RETRY_SECONDS = 3600

def best_display_name(ip, state):
    device = state.get("devices", {}).get(ip, {})
    hostname = device.get("hostname") or state.get("hostnames", {}).get(ip)

    if hostname and isinstance(hostname, str):
        return hostname

    return ip


def set_hostname(state, ip, hostname):
    if not ip or not hostname:
        return

    if isinstance(hostname, bytes):
        hostname = hostname.decode(errors="ignore")

    hostname = str(hostname).strip().strip(".").replace("\x00", "")

    if hostname.startswith("b'") and hostname.endswith("'"):
        hostname = hostname[2:-1]

    if hostname.startswith('b"') and hostname.endswith('"'):
        hostname = hostname[2:-1]

    if not hostname:
        return

    domain_names = {
        "WORKGROUP",
        "MSHOME",
        "LOCAL",
        "HOME",
        "DOMAIN"
    }

    if hostname.upper() in domain_names:
        set_domain_name(state, ip, hostname)
        return

    current = state.setdefault("hostnames", {}).get(ip)

    if current and current.upper() not in domain_names:
        return

    state["hostnames"][ip] = hostname

    if ip in state.get("devices", {}):
        state["devices"][ip]["hostname"] = hostname


def add_unique_list_item(mapping, key, value, limit=50):
    if not key or not value:
        return

    items = mapping.setdefault(key, [])

    if value not in items:
        items.append(value)

    if len(items) > limit:
        del items[:-limit]


def flow_key(src, dst, protocol, src_port=None, dst_port=None):
    return f"{src}|{dst}|{protocol or 'unknown'}|{src_port or ''}|{dst_port or ''}"


def pair_key(src, dst):
    return f"{src}|{dst}"


def try_reverse_dns_hostname(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if name:
            return name.split(".")[0]
    except Exception:
        return None

    return None


def should_check_rdns(state, ip, now, retry_seconds=RDNS_RETRY_SECONDS):
    checked = state.setdefault("rdns_checked", {})
    last = float(checked.get(ip, 0) or 0)
    return now - last > retry_seconds


def set_domain_name(state, ip, domain):
    domain = clean_wire_string(domain)

    if not ip or not domain:
        return

    state.setdefault("domains", {})[ip] = domain

    if ip in state.get("devices", {}):
        state["devices"][ip]["domain"] = domain


def get_resolved_names_for_ip(state, ip, limit=8):
    if not ip:
        return []

    names = []

    primary = state.get("ip_name_map", {}).get(ip)
    if primary:
        names.append(primary)

    for name in state.get("dns_names", {}).get(ip, []) or []:
        if name and name not in names:
            names.append(name)

    return names[:limit]


def classify_ip(ip):
    if not ip:
        return "unknown"

    try:
        addr = ipaddress.ip_address(str(ip))

        if addr.is_multicast:
            return "multicast"

        if addr.is_loopback:
            return "loopback"

        if str(addr) == "255.255.255.255":
            return "broadcast"

        if str(ip).endswith(".255"):
            return "broadcast"

        if addr.is_private:
            return "local_device"

        return "external_host"

    except Exception:
        if str(ip).endswith(".255"):
            return "broadcast"

        return "unknown"


def is_ipv6_address(value):
    try:
        return ipaddress.ip_address(str(value)).version == 6
    except Exception:
        return False


def clean_wire_string(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        value = value.decode(errors="ignore")

    value = str(value).strip().strip(".").replace("\x00", "")

    if value.startswith("b'") and value.endswith("'"):
        value = value[2:-1]

    if value.startswith('b"') and value.endswith('"'):
        value = value[2:-1]

    return value.strip() or None


def clean_domain(domain):
    domain = clean_wire_string(domain)

    if not domain:
        return None

    domain = domain.lower()

    if domain.endswith(".in-addr.arpa") or domain.endswith(".ip6.arpa"):
        return None

    return domain

def normalize_mac(mac):
    if not mac:
        return None

    mac = str(mac).strip().lower().replace("-", ":")

    if mac in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return None

    parts = mac.split(":")
    if len(parts) != 6:
        return None

    try:
        parts = [f"{int(p, 16):02x}" for p in parts]
    except Exception:
        return None

    return ":".join(parts)


def is_linkable_device_ip(ip):
    group = classify_ip(ip)

    return group in {
        "local_device",
        "gateway",
        "loopback"
    }