# identity.py

import re
import csv
import os
from config import oui_csv_path
from net_ports import (
    PORT_ROLE_HINTS,
    WINDOWS_PORTS,
    LINUX_PORTS,
    PRINTER_PORTS,
    CAMERA_PORTS,
)

OUI_CACHE = None

def normalize_oui_prefix(value):
    if not value:
        return None

    value = str(value).strip().upper()

    # Fix Excel/scientific notation damage like 8.87E+027 by ignoring bad rows
    if "E+" in value or "." in value:
        return None

    value = value.replace("-", "").replace(":", "").replace(".", "")

    if len(value) < 6:
        value = value.zfill(6)

    value = value[:6]

    if len(value) != 6:
        return None

    try:
        int(value, 16)
    except ValueError:
        return None

    return f"{value[0:2]}:{value[2:4]}:{value[4:6]}"


def load_oui_map():
    global OUI_CACHE

    if OUI_CACHE is not None:
        return OUI_CACHE

    path = oui_csv_path()
    mapping = {}

    if not os.path.exists(path):
        print("OUI file not found at data/oui/oui.csv (vendor lookup disabled)\n")
        print("Download OUI CSV from: https://standards-oui.ieee.org/oui/oui.csv")
        OUI_CACHE = {}
        return OUI_CACHE

    with open(path, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            prefix = normalize_oui_prefix(row.get("Assignment"))
            vendor = (row.get("Organization Name") or "").strip()

            if prefix and vendor:
                mapping[prefix] = vendor

    OUI_CACHE = mapping
    print(f"Loaded {len(mapping)} OUI vendor prefixes")
    return mapping

def compact_ip(ip):
    if not ip:
        return ip

    ip = str(ip)

    if ":" in ip:
        return ip[:10] + "…" + ip[-6:]

    return ip

def clean_name(name):
    if not name:
        return None

    name = str(name).strip().strip(".")
    name = name.replace("\x00", "")

    if not name:
        return None

    return name

def is_l2_switch_like(device, group):
    protocols = device.get("protocols", {}) or {}

    if group == "switch":
        return True

    return any(
        protocols.get(p, 0) > 0
        for p in ("stp", "rstp", "mstp", "cdp", "lldp", "vtp", "cisco_l2", "lacp")
    )

def guess_vendor(mac, oui_map=None):
    if not mac:
        return None

    prefix = mac.upper().replace("-", ":")[:8]

    if oui_map and prefix in oui_map:
        return oui_map[prefix]

    return None

def guess_os(device):
    ports = set(device.get("ports", []) or [])
    protocols = device.get("protocols", {}) or {}
    hostname = clean_name(device.get("hostname")) or ""
    mac = str(device.get("mac") or "").upper()

    if any(protocols.get(p, 0) > 0 for p in ("stp", "rstp", "mstp", "cdp", "lldp", "vtp", "cisco_l2", "lacp")):
        return "Network device", 0.9

    scores = {
        "Windows": 0,
        "Linux": 0,
        "Printer": 0,
        "Camera/IoT": 0,
        "Network device": 0,
    }

    # Router/network device hints first
    if 53 in ports or 67 in ports or 68 in ports:
        return "Network device", 0.75

    if protocols.get("arp", 0) > 100 and protocols.get("dns", 0) > 20:
        return "Network device", 0.65

    if re.search(r"huawei|router|gateway|fibre|fiber|ont|cpe", hostname, re.I):
        return "Router device", 0.9

    # Then normal OS guesses
    if ports & WINDOWS_PORTS:
        return "Windows", 0.65

    if ports & LINUX_PORTS:
        return "Linux", 0.55

    if ports & PRINTER_PORTS:
        return "Printer", 0.8

    if ports & CAMERA_PORTS:
        return "Camera/IoT", 0.65

    if protocols.get("netbios", 0) > 0:
        scores["Windows"] += 3

    if protocols.get("arp", 0) > 50:
        scores["Network device"] += 1

    if re.search(r"win|desktop|laptop|pc", hostname, re.I):
        scores["Windows"] += 2

    best = max(scores, key=scores.get)

    if scores[best] <= 0:
        return None, 0.0

    confidence = min(1.0, scores[best] / 8)
    return best, confidence


def guess_role(ip, device, group):
    ports = set(device.get("ports", []) or {})
    protocols = device.get("protocols", {}) or {}

    if group == "switch" or any(protocols.get(p, 0) > 0 for p in ("stp", "rstp", "mstp", "cdp", "lldp", "vtp", "cisco_l2", "lacp")):
        return "Network switch"

    if group == "gateway":
        return "Gateway"

    if 53 in ports or protocols.get("dns", 0) > 100:
        return "DNS-active device"

    for port in ports:
        if port in PORT_ROLE_HINTS:
            return PORT_ROLE_HINTS[port]

    if group == "external_host":
        return "External host"

    if group == "local_device":
        return "LAN device"

    return group or "Device"


def build_device_identity(ip, device, group, state):
    hostname = clean_name(device.get("hostname") or state.get("hostnames", {}).get(ip))
    dns_answer_name = clean_name(state.get("ip_name_map", {}).get(ip))
    mac = device.get("mac")

    vendor = guess_vendor(mac, load_oui_map())
    switch_like = is_l2_switch_like(device, group)

    if group == "external_host":
        vendor = None
        name = dns_answer_name or hostname or ip
    elif switch_like:
        if hostname:
            name = hostname
        elif vendor:
            name = f"{vendor} switch"
        else:
            name = "Network switch"
    else:
        name = hostname or ip

    os_guess, os_confidence = guess_os(device)
    role = guess_role(ip, device, group)

    if switch_like:
        role = "Network switch"
        os_guess = "Network device"
        os_confidence = max(os_confidence, 0.9)

    meta = []

    if vendor and "huawei" in vendor.lower():
        os_guess = "Router/Network device"
        os_confidence = max(os_confidence, 0.85)

    if vendor:
        meta.append(vendor)

    if meta:
        display_name = compact_ip(name) if name == ip else name
        label_line_1 = f"{display_name} ({meta[0]})"
    else:
        label_line_1 = compact_ip(name) if name == ip else name

    label_line_2 = compact_ip(ip)

    confidence = 0.2

    if hostname or dns_answer_name:
        confidence += 0.4

    if vendor:
        confidence += 0.2

    if os_guess:
        confidence += os_confidence * 0.2

    if switch_like:
        protocols = device.get("protocols", {}) or {}

        if protocols.get("stp", 0) > 0:
            confidence += 0.25

        if protocols.get("cdp", 0) > 0 or protocols.get("lldp", 0) > 0:
            confidence += 0.25

        if protocols.get("vtp", 0) > 0 or protocols.get("cisco_l2", 0) > 0 or protocols.get("lacp", 0) > 0:
            confidence += 0.15

    confidence = min(1.0, confidence)

    return {
        "name": name,
        "hostname": hostname,
        "dns_answer_name": dns_answer_name,
        "vendor": vendor,
        "os": os_guess,
        "os_confidence": os_confidence,
        "role": role,
        "label_line_1": label_line_1,
        "label_line_2": label_line_2,
        "confidence": confidence
    }