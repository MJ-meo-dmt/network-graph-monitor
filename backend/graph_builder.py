# graph_builder.py

import json
import os
import time
import ipaddress
import threading
import subprocess
import re
import uuid

from state_schema import empty_state, normalize_state
from session_manager import get_current_state_path
from identity import build_device_identity
from net_utils import (
    classify_ip,
    is_ipv6_address,
    get_resolved_names_for_ip,
    set_domain_name,
    should_check_rdns,
    try_reverse_dns_hostname,
    flow_key,
    pair_key,
    add_unique_list_item,
    set_hostname,
    best_display_name,
)

from net_ports import (
    VPN_PROXY_PORTS,
    ADMIN_PORTS,
    REMOTE_ACCESS_PORTS,
    SENSITIVE_PORT_LABELS,
    SERVICE_PORTS,
    WIRED_NAME_HINTS,
    WIRED_SERVICE_PORTS,
    MOBILE_NAME_HINTS
)
from heuristics import run_heuristics


STATE_LOCK = threading.RLock()
LAST_GOOD_STATE = None

RECENT_FLOW_WINDOW_SECONDS = 1800
MAX_EVENTS = None

INFRA_ROUTES = {
    "local_to_switch",
    "switch_to_gateway",
    "gateway_to_switch",
    "switch_to_local",
    "dns_to_switch",
    "dns_to_gateway",
}

GATEWAY_EXTERNAL_ROUTES = {
    "gateway_to_external",
    "external_to_gateway",
    "gateway_to_external_dns",
}


def get_state_path():
    return get_current_state_path()


def load_state():
    global LAST_GOOD_STATE

    state_path = get_state_path()

    with STATE_LOCK:
        if not os.path.exists(state_path):
            state = empty_state()
            LAST_GOOD_STATE = state
            return state

        try:
            with open(state_path, "r", encoding="utf-8") as f:
                state = normalize_state(json.load(f))
                LAST_GOOD_STATE = state
                return state
        except Exception as e:
            print("State read error, using last good state:", e)
            return LAST_GOOD_STATE or empty_state()


def save_state(state):
    global LAST_GOOD_STATE

    state = normalize_state(state)
    state_path = get_state_path()
    tmp_path = f"{state_path}.{uuid.uuid4().hex}.tmp"

    with STATE_LOCK:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

        for _ in range(5):
            try:
                os.replace(tmp_path, state_path)
                LAST_GOOD_STATE = state
                return
            except PermissionError:
                time.sleep(0.05)

        os.replace(tmp_path, state_path)
        LAST_GOOD_STATE = state

def get_access_path(state, ip):
    manual = state.get("access_paths", {}).get(ip)
    if manual:
        return manual

    device = state.get("devices", {}).get(ip, {})
    hostname = str(device.get("hostname") or "").lower()
    mac = str(device.get("mac") or "").lower()
    protocols = device.get("protocols", {}) or {}
    ports = set(device.get("ports", []) or [])

    bad_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

    if mac in bad_macs:
        return "gateway"

    if any(h in hostname for h in WIRED_NAME_HINTS):
        return "switch"

    if ports & WIRED_SERVICE_PORTS:
        return "switch"

    if any(h in hostname for h in MOBILE_NAME_HINTS):
        return "gateway"

    if protocols.get("arp", 0) > 0 and not ports:
        return "gateway"

    return "switch"

def get_os_default_gateway():
    try:
        output = subprocess.check_output(
            ["ipconfig"],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode(errors="ignore")

        for line in output.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    gw = parts[1].strip()
                    if gw and gw != "":
                        return gw
    except Exception:
        pass

    return None

def detect_dns_servers(state):
    servers = set()

    for flow in state.get("flows", {}).values():
        if flow.get("protocol") != "dns":
            continue

        dst = flow.get("to")
        if dst and classify_ip(dst) == "local_device":
            servers.add(dst)

    return list(servers)





def detect_tunnels_and_proxies(state):
    findings = []

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")
        dst_port = flow.get("dst_port")
        proto = flow.get("protocol")

        if classify_ip(src) != "local_device":
            continue

        if classify_ip(dst) != "external_host":
            continue

        if dst_port in VPN_PROXY_PORTS:
            findings.append({
                "src": src,
                "dst": dst,
                "port": dst_port,
                "protocol": proto,
                "type": "possible_vpn_or_proxy"
            })

    return findings[:50]


def detect_gateway(state):
    # 1. Manual override wins
    if state.get("gateway_override"):
        return state["gateway_override"]

    # 2. Keep gateway stable once detected
    if state.get("gateway"):
        return state["gateway"]

    # 3. Try OS default gateway first
    os_gateway = get_os_default_gateway()

    if os_gateway:
        state["gateway"] = os_gateway
        return os_gateway

    # 4. Fallback: traffic heuristic
    candidates = {}

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")

        if not src or not dst:
            continue

        for ip in [src, dst]:
            device = state.get("devices", {}).get(ip, {})
            protocols = device.get("protocols", {})

            score = 0

            if classify_ip(ip) == "local_device":
                score += int(protocols.get("arp", 0) or 0) * 2
                score += int(protocols.get("dns", 0) or 0)

                ports = set(device.get("ports", []))

                if 53 in ports:
                    score += 50

                if 67 in ports or 68 in ports:
                    score += 50

            if score > 0:
                candidates[ip] = candidates.get(ip, 0) + score

    if not candidates:
        return None

    gateway = max(candidates, key=candidates.get)
    state["gateway"] = gateway
    return gateway


def external_boundary_summary(state):
    externals = set()

    for flow in state.get("flows", {}).values():
        for ip in [flow.get("from"), flow.get("to")]:
            if classify_ip(ip) == "external_host":
                externals.add(ip)

    return {
        "external_hosts": len(externals),
        "label": "Internet / ISP boundary"
    }

def detect_nat_summary(state, gateway):
    local_clients = set()
    external_targets = set()

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")

        if not src or not dst:
            continue

        if classify_ip(src) == "local_device" and classify_ip(dst) == "external_host":
            local_clients.add(src)
            external_targets.add(dst)

    return {
        "likely_nat": bool(gateway and len(local_clients) >= 1 and len(external_targets) >= 3),
        "local_clients": len(local_clients),
        "external_targets": len(external_targets),
        "gateway": gateway
    }


def make_segment_edge(src, dst, etype, e, route, actual_src=None, actual_dst=None, weight_scale=0.6):
    data = dict(e.get("data", {}))
    packets = int(data.get("packets", 0) or 0)
    bytes_count = int(data.get("bytes", 0) or 0)

    data["visual_route"] = route

    if actual_src:
        data["actual_src"] = actual_src

    if actual_dst:
        data["actual_dst"] = actual_dst

    data["connections"] = [{
        "actual_src": actual_src or e.get("from"),
        "actual_dst": actual_dst or e.get("to"),
        "type": etype,
        "packets": packets,
        "bytes": bytes_count,
        "ports": data.get("ports", []),
        "domains": data.get("domains", []),
        "protocols": data.get("protocols", {})
    }]

    return {
        "from": src,
        "to": dst,
        "type": etype,
        "weight": max(0.5, float(e.get("weight", 1) or 1) * weight_scale),
        "data": data
    }


def merge_visual_edges(edges):
    merged = {}

    for e in edges:
        data = e.get("data", {})
        route = data.get("visual_route")

        # Only merge internal infrastructure segments.
        if route not in INFRA_ROUTES:
            key = f"{e.get('from')}|{e.get('to')}|{e.get('type')}|{route}|{data.get('actual_src')}|{data.get('actual_dst')}"
        else:
            key = f"{e.get('from')}|{e.get('to')}|{route}"

        if key not in merged:
            merged[key] = e
            continue

        cur = merged[key]
        cur_data = cur.setdefault("data", {})

        cur_data["packets"] = int(cur_data.get("packets", 0) or 0) + int(data.get("packets", 0) or 0)
        cur_data["bytes"] = int(cur_data.get("bytes", 0) or 0) + int(data.get("bytes", 0) or 0)

        cur["weight"] = min(6, float(cur.get("weight", 1) or 1) + float(e.get("weight", 1) or 1) * 0.18)

        for k, v in data.get("protocols", {}).items():
            cur_data.setdefault("protocols", {})
            cur_data["protocols"][k] = cur_data["protocols"].get(k, 0) + v

        route = cur_data.get("visual_route")

        if route in INFRA_ROUTES:
            cur["type"] = "mixed"
        else:
            cur["type"] = relationship_type(set(cur_data.get("protocols", {}).keys()))

        for k, v in data.get("services", {}).items():
            cur_data.setdefault("services", {})
            cur_data["services"][k] = cur_data["services"].get(k, 0) + v

        for k, v in data.get("categories", {}).items():
            cur_data.setdefault("categories", {})
            cur_data["categories"][k] = cur_data["categories"].get(k, 0) + v

        for p in data.get("ports", []):
            cur_data.setdefault("ports", [])
            if p not in cur_data["ports"]:
                cur_data["ports"].append(p)

        for d in data.get("domains", []):
            cur_data.setdefault("domains", [])
            if d not in cur_data["domains"]:
                cur_data["domains"].append(d)

        cur_data.setdefault("connections", [])
        cur_data["connections"].extend(data.get("connections", []))

    return list(merged.values())

def make_visual_edges(state, edges, gateway, dns_servers=None, switch_id=None):
    dns_servers = set(dns_servers or [])

    if not gateway:
        return edges

    visual = []

    for e in edges:
        src = e.get("from")
        dst = e.get("to")
        etype = e.get("type")

        src_type = classify_ip(src)
        dst_type = classify_ip(dst)

        # PC -> Switch -> Pi-hole
        if (
            switch_id
            and src_type == "local_device"
            and dst_type == "local_device"
            and src != gateway
            and dst != gateway
            and get_access_path(state, src) == "switch"
            and get_access_path(state, dst) == "switch"
        ):
            s1 = make_segment_edge(
                src, switch_id, etype, e,
                "local_to_switch",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s2 = make_segment_edge(
                switch_id, dst, etype, e,
                "switch_to_local",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            logical = dict(e)
            logical["type"] = e.get("type")
            logical["weight"] = max(0.4, float(e.get("weight", 1) or 1) * 0.35)
            logical["data"] = dict(e.get("data", {}))
            logical["data"]["visual_route"] = "logical_direct"
            logical["data"]["through_switch"] = switch_id

            visual.extend([s1, s2, logical])
            continue

        # DNS server -> external DNS goes through gateway:
        # Pi-hole -> Router -> External DNS
        if etype == "dns" and src in dns_servers and dst_type == "external_host":
        #if src in dns_servers and dst_type == "external_host":
            half_weight = max(0.5, float(e.get("weight", 1) or 1) * 0.6)

            a = dict(e)
            a["from"] = src
            a["to"] = gateway
            a["type"] = etype
            a["weight"] = half_weight
            a["data"] = dict(e.get("data", {}))
            a["data"]["visual_route"] = "dns_to_gateway"
            a["data"]["actual_dst"] = dst

            b = dict(e)
            b["from"] = gateway
            b["to"] = dst
            b["type"] = etype
            b["weight"] = half_weight
            b["data"] = dict(e.get("data", {}))
            b["data"]["visual_route"] = "gateway_to_external_dns"
            b["data"]["actual_src"] = src

            if switch_id:
                s1 = dict(e)
                s1["from"] = src
                s1["to"] = switch_id
                s1["type"] = etype
                s1["weight"] = half_weight
                s1["data"] = dict(e.get("data", {}))
                s1["data"]["visual_route"] = "dns_to_switch"
                s1["data"]["actual_dst"] = dst

                s2 = dict(e)
                s2["from"] = switch_id
                s2["to"] = gateway
                s2["type"] = etype
                s2["weight"] = half_weight
                s2["data"] = dict(e.get("data", {}))
                s2["data"]["visual_route"] = "switch_to_gateway"
                s2["data"]["actual_src"] = src
                s2["data"]["actual_dst"] = dst

                b = dict(e)
                b["from"] = gateway
                b["to"] = dst
                b["type"] = etype
                b["weight"] = half_weight
                b["data"] = dict(e.get("data", {}))
                b["data"]["visual_route"] = "gateway_to_external_dns"
                b["data"]["actual_src"] = src

                visual.extend([s1, s2, b])
            else:
                visual.extend([a, b])
                continue

        # Local device -> external host goes through gateway:
        # PC -> Router -> External
        if src_type == "local_device" and dst_type == "external_host" and src != gateway:
            half_weight = max(0.5, float(e.get("weight", 1) or 1) * 0.6)

            a = dict(e)
            a["from"] = src
            a["to"] = gateway
            a["type"] = etype
            a["weight"] = half_weight
            a["data"] = dict(e.get("data", {}))
            a["data"]["visual_route"] = "local_to_gateway"
            a["data"]["actual_dst"] = dst

            b = dict(e)
            b["from"] = gateway
            b["to"] = dst
            b["type"] = etype
            b["weight"] = half_weight
            b["data"] = dict(e.get("data", {}))
            b["data"]["visual_route"] = "gateway_to_external"
            b["data"]["actual_src"] = src

            logical = dict(e)
            logical["type"] = e.get("type")
            logical["weight"] = max(0.4, float(e.get("weight", 1) or 1) * 0.35)
            logical["data"] = dict(e.get("data", {}))
            logical["data"]["visual_route"] = "logical_direct"
            logical["data"]["through_gateway"] = gateway

            if switch_id:
                s1 = make_segment_edge(
                    src, switch_id, etype, e,
                    "local_to_switch",
                    actual_src=src,
                    actual_dst=dst,
                    weight_scale=0.6
                )

                s2 = make_segment_edge(
                    switch_id, gateway, etype, e,
                    "switch_to_gateway",
                    actual_src=src,
                    actual_dst=dst,
                    weight_scale=0.6
                )

                visual.extend([s1, s2, b, logical])
            else:
                visual.extend([a, b, logical])
            continue

        # External host -> local device goes through gateway:
        # External -> Router -> PC
        if src_type == "external_host" and dst_type == "local_device" and dst != gateway:
            half_weight = max(0.5, float(e.get("weight", 1) or 1) * 0.6)

            a = dict(e)
            a["from"] = src
            a["to"] = gateway
            a["type"] = etype
            a["weight"] = half_weight
            a["data"] = dict(e.get("data", {}))
            a["data"]["visual_route"] = "external_to_gateway"
            a["data"]["actual_dst"] = dst

            b = dict(e)
            b["from"] = gateway
            b["to"] = dst
            b["type"] = etype
            b["weight"] = half_weight
            b["data"] = dict(e.get("data", {}))
            b["data"]["visual_route"] = "gateway_to_local"
            b["data"]["actual_src"] = src

            logical = dict(e)
            logical["type"] = e.get("type")
            logical["weight"] = max(0.4, float(e.get("weight", 1) or 1) * 0.35)
            logical["data"] = dict(e.get("data", {}))
            logical["data"]["visual_route"] = "logical_direct"
            logical["data"]["through_gateway"] = gateway

            if switch_id:
                s1 = make_segment_edge(
                    gateway, switch_id, etype, e,
                    "gateway_to_switch",
                    actual_src=src,
                    actual_dst=dst,
                    weight_scale=0.6
                )

                s2 = make_segment_edge(
                    switch_id, dst, etype, e,
                    "switch_to_local",
                    actual_src=src,
                    actual_dst=dst,
                    weight_scale=0.6
                )

                visual.extend([a, s1, s2, logical])
            else:
                visual.extend([a, b, logical])

            continue

        # Local wired/switch device -> local Wi-Fi/gateway device
        # Example: PC -> Switch -> Gateway -> Phone
        if (
            switch_id
            and src_type == "local_device"
            and dst_type == "local_device"
            and src != gateway
            and dst != gateway
            and src != dst
            and get_access_path(state, src) == "switch"
            and get_access_path(state, dst) == "gateway"
        ):
            s1 = make_segment_edge(
                src, switch_id, etype, e,
                "local_to_switch",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s2 = make_segment_edge(
                switch_id, gateway, etype, e,
                "switch_to_gateway",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s3 = make_segment_edge(
                gateway, dst, etype, e,
                "gateway_to_local",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            logical = make_segment_edge(
                src, dst, etype, e,
                "logical_direct",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.25
            )

            visual.extend([s1, s2, s3, logical])
            continue

        # Local Wi-Fi/gateway device -> local wired/switch device
        # Example: Phone -> Gateway -> Switch -> PC
        if (
            switch_id
            and src_type == "local_device"
            and dst_type == "local_device"
            and src != gateway
            and dst != gateway
            and src != dst
            and get_access_path(state, src) == "gateway"
            and get_access_path(state, dst) == "switch"
        ):
            s1 = make_segment_edge(
                src, gateway, etype, e,
                "local_to_gateway",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s2 = make_segment_edge(
                gateway, switch_id, etype, e,
                "gateway_to_switch",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s3 = make_segment_edge(
                switch_id, dst, etype, e,
                "switch_to_local",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            logical = make_segment_edge(
                src, dst, etype, e,
                "logical_direct",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.25
            )

            visual.extend([s1, s2, s3, logical])
            continue

        # Local device -> local device should visually pass through the access switch
        if (
            switch_id
            and src_type == "local_device"
            and dst_type == "local_device"
            and get_access_path(state, src) == "switch"
            and get_access_path(state, dst) == "switch"
            and src != gateway
            and dst != gateway
            and src != dst
        ):
            half_weight = max(0.5, float(e.get("weight", 1) or 1) * 0.6)

            s1 = make_segment_edge(
                src, switch_id, etype, e,
                "local_to_switch",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s2 = make_segment_edge(
                switch_id, dst, etype, e,
                "switch_to_local",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            logical = make_segment_edge(
                src, dst, etype, e,
                "logical_direct",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.28
            )

            visual.extend([s1, s2, logical])
            continue
        
        # Local device -> gateway should visually pass through switch
        if (
            switch_id
            and src_type == "local_device"
            and dst == gateway
            and get_access_path(state, src) == "switch"
            and src != gateway
        ):
            s1 = make_segment_edge(
                src, switch_id, etype, e,
                "local_to_switch",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s2 = make_segment_edge(
                switch_id, gateway, etype, e,
                "switch_to_gateway",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            visual.extend([s1, s2])
            continue

        # Gateway -> local device should visually pass through switch
        if (
            switch_id
            and src == gateway
            and dst_type == "local_device"
            and get_access_path(state, dst) == "switch"
            and dst != gateway
        ):
            s1 = make_segment_edge(
                gateway, switch_id, etype, e,
                "gateway_to_switch",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            s2 = make_segment_edge(
                switch_id, dst, etype, e,
                "switch_to_local",
                actual_src=src,
                actual_dst=dst,
                weight_scale=0.6
            )

            visual.extend([s1, s2])
            continue
        visual.append(e)

    return merge_visual_edges(visual)

def update_l2_state(state, event):
    now = float(event.get("timestamp", time.time()))
    src_mac = event.get("src_mac")
    switch_name = event.get("l2_device_name")
    proto = event.get("protocol", "l2")
    name = event.get("l2_device_name")
    meta = event.get("l2_meta") or {}

    if not src_mac:
        return

    # If a switch already exists, treat later unnamed L2 MACs as interfaces.
    existing_switch = state.get("default_switch")

    if existing_switch and existing_switch in state.get("l2_devices", {}):
        node_id = existing_switch
    else:
        node_id = f"l2:{src_mac.lower()}"

    if node_id not in state["l2_devices"]:
        state["l2_devices"][node_id] = {
            "id": node_id,
            "mac": src_mac,
            "name": name or f"Switch {src_mac}",
            "kind": event.get("l2_kind", "l2_device"),
            "first_seen": now,
            "last_seen": now,
            "protocols": {},
            "packets": 0,
            "bytes": 0
        }

    dev = state["l2_devices"][node_id]
    interfaces = dev.setdefault("interfaces", {})

    if src_mac:
        iface = interfaces.setdefault(src_mac.lower(), {
            "mac": src_mac,
            "first_seen": now,
            "last_seen": now,
            "protocols": {},
            "packets": 0,
            "bytes": 0
        })

        iface["last_seen"] = now
        iface["packets"] = int(iface.get("packets", 0) or 0) + 1
        iface["bytes"] = int(iface.get("bytes", 0) or 0) + int(event.get("size", 0) or 0)

        iface_protocols = iface.setdefault("protocols", {})
        iface_protocols[proto] = int(iface_protocols.get(proto, 0) or 0) + 1

    dev["last_seen"] = now
    dev["packets"] = int(dev.get("packets", 0) or 0) + 1
    dev["bytes"] = int(dev.get("bytes", 0) or 0) + int(event.get("size", 0) or 0)

    generic_l2_names = {
    "internetwork",
    "switch",
    "router",
    "bridge",
    "network switch",
    }

    current_name = str(dev.get("name") or "").strip().lower()

    if switch_name and (
        not dev.get("name")
        or dev["name"].startswith("Switch ")
        or current_name in generic_l2_names
    ):
        dev["name"] = switch_name

    protocols = dev.setdefault("protocols", {})
    protocols[proto] = int(protocols.get(proto, 0) or 0) + 1

    # Pick the first observed switch-like L2 node as default visual access switch.
    if not state.get("default_switch") and dev.get("kind") == "switch":
        state["default_switch"] = node_id

    # Deal with meta:
    if meta.get("hostname"):
        current_name = str(dev.get("name") or "").strip().lower()
        if (
            not dev.get("name")
            or dev["name"].startswith("Switch ")
            or current_name in generic_l2_names
            or current_name == "operating"
        ):
            dev["name"] = meta["hostname"]
    
    if meta.get("platform"):
        dev["platform"] = meta["platform"]

    if meta.get("capabilities"):
        dev["capabilities"] = meta["capabilities"]
    
    if meta.get("device_id"):
        dev["device_id"] = meta["device_id"]

    if meta.get("management_ip"):
        dev["management_ip"] = meta["management_ip"]

    if meta.get("software_version"):
        dev["software_version"] = meta["software_version"]

    if meta.get("vtp_domain"):
        dev["vtp_domain"] = meta["vtp_domain"]

    if meta.get("duplex"):
        dev["duplex"] = meta["duplex"]

    # Future topology
    if meta.get("port_id"):
        ports_seen = dev.setdefault("ports_seen", [])

        if meta["port_id"] not in ports_seen:
            ports_seen.append(meta["port_id"])

def update_state(event):
    state = load_state()

    src = event.get("src_ip")
    dst = event.get("dst_ip")

    if not src or not dst:
        if event.get("category") == "layer2" or event.get("transport") == "l2":
            update_l2_state(state, event)
            state["events"].append(event)

            if MAX_EVENTS is not None:
                state["events"] = state["events"][-MAX_EVENTS:]

            save_state(state)

        return

    now = float(event.get("timestamp", time.time()))
    proto = event.get("protocol", "unknown")
    size = int(event.get("size", 0) or 0)

    # -------------------------------------------------
    # Ensure devices exist before scoring/flagging them
    # -------------------------------------------------
    for ip, mac_key in [(src, "src_mac"), (dst, "dst_mac")]:
        if ip not in state["devices"]:
            state["devices"][ip] = {
                "id": ip,
                "ip": ip,
                "mac": event.get(mac_key) if classify_ip(ip) != "external_host" else None,
                "first_seen": now,
                "last_seen": now,
                "packets": 0,
                "bytes": 0,
                "protocols": {},
                "services": {},
                "categories": {},
                "ports": [],
                "flags": []
            }

        dev = state["devices"][ip]

        if (
            classify_ip(ip) == "local_device"
            and not dev.get("hostname")
            and should_check_rdns(state, ip, now)
        ):
            state["rdns_checked"][ip] = now

            rdns_name = try_reverse_dns_hostname(ip)

            if rdns_name:
                dev["hostname"] = rdns_name
                state.setdefault("hostnames", {})[ip] = rdns_name

        dev["last_seen"] = now
        dev["packets"] = int(dev.get("packets", 0)) + 1
        dev["bytes"] = int(dev.get("bytes", 0)) + size

        # Only trust MAC addresses for local/broadcast/multicast/ARP nodes.
        # External hosts will usually show the router's MAC, not the real remote MAC.
        bad_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

        mac_value = str(event.get(mac_key) or "").lower()

        if (
            mac_value
            and mac_value not in bad_macs
            and not dev.get("mac")
            and classify_ip(ip) in {"local_device", "gateway", "broadcast", "multicast", "loopback"}
        ):
            dev["mac"] = event.get(mac_key)

        protocols = dev.setdefault("protocols", {})
        protocols[proto] = int(protocols.get(proto, 0)) + 1

        service = event.get("service")
        category = event.get("category")

        if service:
            services = dev.setdefault("services", {})
            services[service] = int(services.get(service, 0)) + 1

        if category:
            categories = dev.setdefault("categories", {})
            categories[category] = int(categories.get(category, 0)) + 1

    # -------------------------------------------------
    # Destination port tracking
    # -------------------------------------------------
    if event.get("dst_port"):
        ports = state["devices"][dst].setdefault("ports", [])
        if event["dst_port"] not in ports:
            ports.append(event["dst_port"])

    # -------------------------------------------------
    # Scanner tracking - must use lists because JSON
    # cannot serialize sets.
    # -------------------------------------------------
    scanner_map = state.setdefault("scanner_map", {})

    existing = scanner_map.get(src)

    # migrate old format: src -> []
    if isinstance(existing, list):
        src_scan = {
            "targets": existing,
            "ports": []
        }

    # normal new format: src -> {"targets": [], "ports": []}
    elif isinstance(existing, dict):
        src_scan = existing
        src_scan.setdefault("targets", [])
        src_scan.setdefault("ports", [])

    # missing/broken format
    else:
        src_scan = {
            "targets": [],
            "ports": []
        }

    scanner_map[src] = src_scan

    if dst not in src_scan["targets"]:
        src_scan["targets"].append(dst)

    if event.get("dst_port") and event["dst_port"] not in src_scan["ports"]:
        src_scan["ports"].append(event["dst_port"])

    if len(src_scan["targets"]) > 40 and len(src_scan["ports"]) > 12:
        state["devices"][src]["scanner"] = True
        add_flag(state["devices"][src], "possible_scanner")

    # -------------------------------------------------
    # External-heavy tracking
    # -------------------------------------------------
    external_map = state.setdefault("external_map", {})
    external_targets = external_map.setdefault(src, [])

    if classify_ip(dst) == "external_host" and dst not in external_targets:
        external_targets.append(dst)

    if len(external_targets) > 50:
        state["devices"][src]["external_heavy"] = True
        add_flag(state["devices"][src], "external_heavy")

    # -------------------------------------------------
    # DNS-heavy tracking
    # -------------------------------------------------
    dns_map = state.setdefault("dns_map", {})
    dns_domains = dns_map.setdefault(src, [])

    if proto == "dns" and event.get("domain"):
        if event["domain"] not in dns_domains:
            dns_domains.append(event["domain"])

    if len(dns_domains) > 100:
        state["devices"][src]["dns_spam"] = True
        add_flag(state["devices"][src], "dns_heavy")

    # -------------------------------------------------
    # DNS names seen + DNS answer IP/name mapping
    # -------------------------------------------------
    if proto == "dns" and event.get("domain"):
        dns_names = state.setdefault("dns_names", {})

        # This means the source talked about / queried this DNS name.
        add_unique_list_item(dns_names, src, event["domain"], limit=100)

        # Keep your old dns_map count behavior too
        dns_map = state.setdefault("dns_map", {})
        dns_domains = dns_map.setdefault(src, [])
        if event["domain"] not in dns_domains:
            dns_domains.append(event["domain"])

    # DNS answers can map names to returned IPs.
    for ans in event.get("dns_answers", []) or []:
        name = ans.get("name")
        value = ans.get("value")

        if not name or not value:
            continue

        # If DNS answer value looks like an IP, remember name for that IP.
        try:
            ipaddress.ip_address(value)
            add_unique_list_item(state.setdefault("dns_names", {}), value, name, limit=100)
            state.setdefault("ip_name_map", {})[value] = name
        except Exception:
            pass

    # NetBIOS/LLMNR/mDNS-style hostname if analyzer found one
    if event.get("hostname"):
        set_hostname(state, src, event["hostname"])

    # -------------------------------------------------
    # Raw flow tracking
    # -------------------------------------------------
    key = flow_key(
        src,
        dst,
        proto,
        event.get("src_port"),
        event.get("dst_port")
    )

    if key not in state["flows"]:
        state["flows"][key] = {
            "from": src,
            "to": dst,
            "protocol": proto,
            "service": event.get("service"),
            "category": event.get("category"),
            "routing": event.get("routing"),
            "routing_protocol": event.get("routing_protocol"),
            "routing_type": event.get("routing_type"),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port"),
            "packets": 0,
            "bytes": 0,
            "first_seen": now,
            "last_seen": now,
            "domains": [],
            "dns_queries": [],
            "tcp_flags": {}
        }

    flow = state["flows"][key]
    flow["packets"] = int(flow.get("packets", 0)) + 1
    flow["bytes"] = int(flow.get("bytes", 0)) + size
    flow["last_seen"] = now

    if event.get("tcp_flags"):
        flags = flow.setdefault("tcp_flags", {})
        flags[event["tcp_flags"]] = int(flags.get(event["tcp_flags"], 0)) + 1

    if event.get("domain"):
        if proto == "dns":
            if event["domain"] not in flow.setdefault("dns_queries", []):
                flow["dns_queries"].append(event["domain"])
        else:
            if event["domain"] not in flow.setdefault("domains", []):
                flow["domains"].append(event["domain"])

    # -------------------------------------------------
    # Recent event ring buffer
    # -------------------------------------------------
    state["events"].append(event)

    if MAX_EVENTS is not None:
        state["events"] = state["events"][-MAX_EVENTS:]

    # -------------------------------------------------
    # Prune stale flows so graph remains live
    # -------------------------------------------------
    prune_old_flows(state, now)

    save_state(state)


def add_flag(device, flag):
    flags = device.setdefault("flags", [])
    if flag not in flags:
        flags.append(flag)


# Not working will come back to this maybe
def prune_old_flows(state, now):
    return
    #flows = state.get("flows", {})
    #fresh = {}

    #for key, flow in flows.items():
    #    last_seen = float(flow.get("last_seen", 0) or 0)

    #    if now - last_seen <= RECENT_FLOW_WINDOW_SECONDS:
    #        fresh[key] = flow

    #state["flows"] = fresh


def importance_score(device):
    packets = int(device.get("packets", 0) or 0)
    ports = len(device.get("ports", []))
    protocols = len(device.get("protocols", {}))
    flags = len(device.get("flags", []))

    return min(10, packets / 60 + ports * 0.55 + protocols * 0.45 + flags * 0.9)


def assess_device_risk(ip, device, state):
    protocols = device.get("protocols", {}) or {}
    services = device.get("services", {}) or {}
    categories = device.get("categories", {}) or {}
    flags = device.get("flags", []) or []
    ports = set(device.get("ports", []) or [])

    scanner = state.get("scanner_map", {}).get(ip, {})
    external_targets = state.get("external_map", {}).get(ip, [])
    dns_domains = state.get("dns_map", {}).get(ip, [])

    target_count = len(scanner.get("targets", [])) if isinstance(scanner, dict) else 0
    scan_port_count = len(scanner.get("ports", [])) if isinstance(scanner, dict) else 0
    external_count = len(external_targets)
    dns_count = len(dns_domains)

    group = classify_ip(ip)
    role = guess_simple_role(device, group)

    score = 0
    findings = []

    def add(points, kind, reason, evidence=None, severity="medium"):
        nonlocal score
        score += points
        findings.append({
            "kind": kind,
            "severity": severity,
            "points": points,
            "reason": reason,
            "evidence": evidence or {}
        })

    # Ignore normal infra noise
    is_gateway = role == "gateway"
    is_dns_server = services.get("dns", 0) > 50 or 53 in ports
    is_known_infra = is_gateway or is_dns_server or role in {"printer", "switch", "multicast", "broadcast"}

    # 1. Real scan behavior: many ports AND multiple targets
    if scan_port_count >= 20 and target_count >= 5:
        add(
            5,
            "port_scan",
            "Touched many ports across multiple targets.",
            {"targets": target_count, "ports": scan_port_count},
            "high"
        )
    elif scan_port_count >= 12 and target_count >= 3:
        add(
            3,
            "possible_scan",
            "Touched an unusual number of destination ports.",
            {"targets": target_count, "ports": scan_port_count}
        )

    # 2. External fanout, but don't punish gateways/DNS heavily
    if not is_known_infra:
        if external_count >= 100:
            add(
                4,
                "large_external_fanout",
                "Talked to a very large number of external hosts.",
                {"external_targets": external_count},
                "high"
            )
        elif external_count >= 50:
            add(
                2,
                "external_fanout",
                "Talked to many external hosts.",
                {"external_targets": external_count}
            )

    # 3. DNS abuse/noise, but suppress Pi-hole/DNS server false positives
    if not is_dns_server:
        if dns_count >= 200:
            add(
                3,
                "dns_heavy",
                "Queried many unique DNS names.",
                {"dns_domains": dns_count}
            )
        elif dns_count >= 100:
            add(
                1,
                "dns_noisy",
                "DNS volume is elevated.",
                {"dns_domains": dns_count},
                "low"
            )

    seen_remote_access = sorted(p for p in ports if p in REMOTE_ACCESS_PORTS)

    if seen_remote_access and not is_known_infra:
        add(
            3,
            "remote_access_service_seen",
            "Remote access service observed on this device.",
            {"ports": {p: SENSITIVE_PORT_LABELS.get(p, "remote-access") for p in seen_remote_access}},
            "medium"
        )

    seen_risky = sorted(
        p for p in ports
        if p in ADMIN_PORTS or p in VPN_PROXY_PORTS or p in REMOTE_ACCESS_PORTS
    )

    if seen_risky and not is_known_infra:
        add(
            2,
            "sensitive_service_seen",
            "Sensitive management or lateral-movement service observed.",
            {"ports": {p: SENSITIVE_PORT_LABELS.get(p, SERVICE_PORTS.get(p, ("unknown",))[0]) for p in seen_risky}}
        )

    # 5. OT / ICS traffic should stand out
    if categories.get("ot", 0) > 0:
        add(
            4,
            "ot_traffic",
            "OT/ICS protocol observed.",
            {"ot_packets": categories.get("ot", 0)},
            "high"
        )

    # 6. Existing explicit flags still matter, but less blindly
    if "possible_scanner" in flags and scan_port_count >= 10:
        add(
            2,
            "scanner_flag",
            "Existing scanner flag confirmed by scan-port count.",
            {"scan_ports": scan_port_count}
        )

    score = min(10, score)

    return {
        "score": score,
        "findings": findings,
        "role_hint": role,
        "is_known_infra": is_known_infra
    }


def guess_simple_role(device, group):
    ports = set(device.get("ports", []) or [])
    services = device.get("services", {}) or {}

    if group == "gateway":
        return "gateway"

    if group in {"multicast", "broadcast"}:
        return group

    if services.get("dns", 0) > 50 or 53 in ports:
        return "dns_server"

    if 9100 in ports or 515 in ports or 631 in ports:
        return "printer"

    if 445 in ports or 3389 in ports:
        return "windows_host"

    return group or "device"


def relationship_type(protocols):
    """
    Pick a primary edge type for coloring.
    """
    priority = [
        "scan",
        "dns",
        "quic",
        "http",
        "tls",
        "tcp",
        "udp",
        "icmp",
        "arp"
    ]

    for p in priority:
        if p in protocols:
            return p

    return next(iter(protocols), "unknown")


def build_relationship_edges(state):
    """
    Merge raw flows into one relationship edge per src -> dst.
    This makes the graph much cleaner.
    """
    pairs = {}

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")

        if not src or not dst:
            continue

        key = pair_key(src, dst)

        if key not in pairs:
            pairs[key] = {
                "from": src,
                "to": dst,
                "protocols": {},
                "services": {},
                "categories": {},
                "tcp_flags": {},
                "ports": [],
                "packets": 0,
                "bytes": 0,
                "domains": [],
                "dns_queries": [],
                "routing": [],
                "first_seen": flow.get("first_seen"),
                "last_seen": flow.get("last_seen")
            }

        rel = pairs[key]
        proto = flow.get("protocol", "unknown")

        rel["protocols"][proto] = rel["protocols"].get(proto, 0) + int(flow.get("packets", 0) or 0)
        rel["packets"] += int(flow.get("packets", 0) or 0)
        rel["bytes"] += int(flow.get("bytes", 0) or 0)

        if flow.get("service"):
            rel["services"][flow["service"]] = rel["services"].get(flow["service"], 0) + int(flow.get("packets", 0) or 0)

        if flow.get("category"):
            rel["categories"][flow["category"]] = rel["categories"].get(flow["category"], 0) + int(flow.get("packets", 0) or 0)
        
        if flow.get("routing"):
            if flow["routing"] not in rel["routing"]:
                rel["routing"].append(flow["routing"])

        for flag, count in flow.get("tcp_flags", {}).items():
            rel["tcp_flags"][flag] = rel["tcp_flags"].get(flag, 0) + int(count or 0)

        if flow.get("dst_port") and flow.get("dst_port") not in rel["ports"]:
            rel["ports"].append(flow.get("dst_port"))

        # Only attach DNS labels to the edge when the edge endpoint itself
        # has a resolved DNS name.
        for endpoint in [dst, src]:
            if classify_ip(endpoint) == "external_host":
                for name in get_resolved_names_for_ip(state, endpoint):
                    if name not in rel["domains"]:
                        rel["domains"].append(name)
        
        # Keep DNS query names separate from resolved endpoint names.
        for query in flow.get("dns_queries", []):
            if query not in rel["dns_queries"]:
                rel["dns_queries"].append(query)

        if flow.get("last_seen"):
            rel["last_seen"] = max(float(rel.get("last_seen") or 0), float(flow.get("last_seen")))

    edges = []

    intelligence_edges = state.get("intelligence", {}).get("edges", {})

    for key, rel in pairs.items():
        protocols = set(rel["protocols"].keys())
        primary_type = relationship_type(protocols)

        if len(rel.get("ports", [])) > 15:
            primary_type = "scan"

        packets = rel.get("packets", 0)
        weight = min(6, 0.7 + packets / 35)

        edge_intel_key = f"{rel['from']}|{rel['to']}"
        edge_intel = intelligence_edges.get(edge_intel_key, {})
        edge_score = int(edge_intel.get("score", 0) or 0)

        edges.append({
            "from": rel["from"],
            "to": rel["to"],
            "type": primary_type,
            "weight": weight,
            "data": {
                "protocols": rel["protocols"],
                "services": rel["services"],
                "categories": rel["categories"],
                "tcp_flags": rel["tcp_flags"],
                "ports": rel["ports"],
                "packets": rel["packets"],
                "bytes": rel["bytes"],
                "domains": rel["domains"],
                "dns_queries": rel["dns_queries"],
                "routing": rel["routing"],
                "first_seen": rel["first_seen"],
                "last_seen": rel["last_seen"],

                # Intelligence fields
                "intelligence": edge_intel,
                "suspicion_score": edge_score,
                "flags": edge_intel.get("flags", []),
                "reasons": edge_intel.get("reasons", []),
                "confidence": edge_intel.get("confidence", "low"),
            }
        })

    return edges


def get_scan_target_count(state, ip):
    item = state.get("scanner_map", {}).get(ip, [])

    if isinstance(item, dict):
        return len(item.get("targets", []))

    if isinstance(item, list):
        return len(item)

    return 0


def get_scan_port_count(state, ip):
    item = state.get("scanner_map", {}).get(ip, [])

    if isinstance(item, dict):
        return len(item.get("ports", []))

    return 0

def get_default_switch(state):
    switch_id = state.get("default_switch")

    if switch_id and switch_id in state.get("l2_devices", {}):
        return switch_id

    for node_id, item in state.get("l2_devices", {}).items():
        if item.get("kind") == "switch":
            state["default_switch"] = node_id
            return node_id

    return None

def build_graph(state):
    state = normalize_state(state)

    try:
        state["intelligence"] = run_heuristics(state)
    except Exception as e:
        print("Heuristics error:", e)
        state["intelligence"] = {
            "nodes": {},
            "edges": {},
            "summary": {
                "error": str(e)
            }
        }

    nodes = []
    gateway = detect_gateway(state)

    filters = state.get("filters", {})
    show_ipv6 = filters.get("show_ipv6", False)

    for ip, device in state.get("devices", {}).items():
        if not show_ipv6 and is_ipv6_address(ip):
            continue

        risk_assessment = assess_device_risk(ip, device, state)
        risk = risk_assessment["score"]
        importance = importance_score(device)

        group = classify_ip(ip)

        if ip == gateway:
            group = "gateway"

        if risk >= 6 and not risk_assessment["is_known_infra"]:
            group = "suspicious"

        intel = state.get("intelligence", {}).get("nodes", {}).get(ip, {})
        intel_score = int(intel.get("score", 0) or 0)

        node_group = group

        if intel_score >= 75 and group not in {"gateway", "switch"}:
            node_group = "suspicious"

        identity = build_device_identity(ip, device, group, state)

        node_data = {
            "ip": ip,
            "identity": identity,
            "hostname": identity.get("hostname"),
            "domain": device.get("domain") or state.get("domains", {}).get(ip),
            "vendor": identity.get("vendor"),
            "os": identity.get("os"),
            "role": identity.get("role"),
            "display_name": identity.get("name"),
            "dns_names": state.get("dns_names", {}).get(ip, []),
            "dns_answer_name": identity.get("dns_answer_name"),
            "access_path": get_access_path(state, ip),

            "mac": device.get("mac"),
            "first_seen": device.get("first_seen"),
            "last_seen": device.get("last_seen"),
            "packets": device.get("packets", 0),
            "bytes": device.get("bytes", 0),
            "protocols": device.get("protocols", {}),
            "services": device.get("services", {}),
            "categories": device.get("categories", {}),
            "ports": sorted(device.get("ports", [])),
            "importance": importance,
            "risk": risk,
            "risk_findings": risk_assessment["findings"],
            "risk_role_hint": risk_assessment["role_hint"],
            "risk_is_known_infra": risk_assessment["is_known_infra"],
            "scanner": bool(device.get("scanner")),
            "dns_spam": bool(device.get("dns_spam")),
            "external_heavy": bool(device.get("external_heavy")),
            "target_count": get_scan_target_count(state, ip),
            "scan_port_count": get_scan_port_count(state, ip),
            "external_target_count": len(state.get("external_map", {}).get(ip, [])),
            "dns_domain_count": len(state.get("dns_map", {}).get(ip, [])),

            # Intelligence fields
            "intelligence": intel,
            "suspicion_score": intel_score,
            "flags": sorted(set((device.get("flags", []) or []) + (intel.get("flags", []) or []))),
            "reasons": intel.get("reasons", []),
            "confidence": intel.get("confidence", "low"),
        }

        nodes.append({
            "id": ip,
            "label": identity["label_line_1"],
            "group": node_group,
            "data": node_data
        })

    for node_id, l2 in state.get("l2_devices", {}).items():
        l2_device = {
            "id": node_id,
            "ip": node_id,
            "mac": l2.get("mac"),
            "hostname": l2.get("name"),
            "protocols": l2.get("protocols", {}),
            "services": {},
            "categories": {"layer2_control": sum((l2.get("protocols", {}) or {}).values())},
            "ports": [],
            "packets": l2.get("packets", 0),
            "bytes": l2.get("bytes", 0),
            "first_seen": l2.get("first_seen"),
            "last_seen": l2.get("last_seen"),
            "flags": []
        }

        identity = build_device_identity(node_id, l2_device, "switch", state)

        nodes.append({
            "id": node_id,
            "label": identity["label_line_1"],
            "group": "switch",
            "data": {
                "ip": node_id,
                "mac": l2.get("mac"),
                "kind": l2.get("kind"),
                "role": identity.get("role"),
                "vendor": identity.get("vendor"),
                "platform": l2.get("platform"),
                "capabilities": l2.get("capabilities"),
                "device_id": l2.get("device_id"),
                "management_ip": l2.get("management_ip"),
                "software_version": l2.get("software_version"),
                "vtp_domain": l2.get("vtp_domain"),
                "duplex": l2.get("duplex"),
                "ports_seen": list(l2.get("ports_seen", [])),
                "os": identity.get("os"),
                "display_name": identity.get("name"),
                "hostname": identity.get("hostname"),
                "domain": None,
                "dns_answer_name": None,
                "access_path": "switch",
                "protocols": l2.get("protocols", {}),
                "services": {},
                "categories": l2_device["categories"],
                "interfaces": l2.get("interfaces", {}),
                "ports": [],
                "packets": l2.get("packets", 0),
                "bytes": l2.get("bytes", 0),
                "first_seen": l2.get("first_seen"),
                "last_seen": l2.get("last_seen"),
                "identity": identity,
                "importance": 4,
                "risk": 0,
                "flags": [],
                "target_count": 0,
                "scan_port_count": 0,
                "external_target_count": 0,
                "dns_domain_count": 0
            }
        })

    raw_edges = build_relationship_edges(state)
    dns_servers = detect_dns_servers(state)
    switch_id = get_default_switch(state)
    edges = make_visual_edges(state, raw_edges, gateway, dns_servers, switch_id)

    if not show_ipv6:
        edges = [
            e for e in edges
            if not is_ipv6_address(e.get("from"))
            and not is_ipv6_address(e.get("to"))
        ]

    gateway_load = {"packets": 0, "bytes": 0, "external_edges": 0}

    if gateway:
        for e in edges:
            if e.get("from") == gateway or e.get("to") == gateway:
                data = e.get("data", {})
                gateway_load["packets"] += int(data.get("packets", 0) or 0)
                gateway_load["bytes"] += int(data.get("bytes", 0) or 0)

                if data.get("visual_route"):
                    gateway_load["external_edges"] += 1
    
    vlans = set()

    for event in state.get("events", []):
        for vlan in event.get("vlans", []) or []:
            if vlan is not None:
                vlans.add(vlan)

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_events": len(state.get("events", [])),
            "gateway": gateway,
            "gateway_load": gateway_load,
            "recent_flow_window_seconds": RECENT_FLOW_WINDOW_SECONDS,
            "nat": detect_nat_summary(state, gateway),
            "tunnels": detect_tunnels_and_proxies(state),
            "external_boundary": external_boundary_summary(state),
            "dns_servers": dns_servers,
            "default_switch": switch_id,
            "l2_devices": len(state.get("l2_devices", {})),
            "vlans": sorted(vlans),
            "intelligence": state.get("intelligence", {}).get("summary", {}),
        }
    }