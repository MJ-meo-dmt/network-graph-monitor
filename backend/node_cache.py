import json
import os
import time
import uuid
import threading

from config import ENABLE_NODE_CACHE, node_cache_path
from net_utils import normalize_mac, classify_ip
from identity import build_device_identity

LAST_NODE_CACHE_SAVE = 0
NODE_CACHE_SAVE_INTERVAL_SECONDS = 5

NODE_CACHE_LOCK = threading.RLock()
NODE_CACHE_MEMORY = None


def empty_node_cache():
    return {
        "version": 1,
        "updated_at": None,
        "nodes_by_ip": {},
        "nodes_by_mac": {}
    }


def ensure_node_cache_dir():
    path = node_cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)


def load_node_cache():
    global NODE_CACHE_MEMORY

    if not ENABLE_NODE_CACHE:
        return empty_node_cache()

    with NODE_CACHE_LOCK:
        if NODE_CACHE_MEMORY is not None:
            return NODE_CACHE_MEMORY

        path = node_cache_path()

        if not os.path.exists(path):
            NODE_CACHE_MEMORY = empty_node_cache()
            return NODE_CACHE_MEMORY

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                data = empty_node_cache()

            data.setdefault("version", 1)
            data.setdefault("nodes_by_ip", {})
            data.setdefault("nodes_by_mac", {})
            data.setdefault("updated_at", None)

            NODE_CACHE_MEMORY = data
            return NODE_CACHE_MEMORY

        except Exception as e:
            print("Node cache load error:", e)
            NODE_CACHE_MEMORY = empty_node_cache()
            return NODE_CACHE_MEMORY


def save_node_cache(cache=None, force=False):
    global NODE_CACHE_MEMORY
    global LAST_NODE_CACHE_SAVE

    if not ENABLE_NODE_CACHE:
        return

    with NODE_CACHE_LOCK:
        ensure_node_cache_dir()

        cache = cache or NODE_CACHE_MEMORY or empty_node_cache()
        NODE_CACHE_MEMORY = cache

        now = time.time()

        # Avoid hammering the cache file on every packet.
        if not force and LAST_NODE_CACHE_SAVE and now - LAST_NODE_CACHE_SAVE < NODE_CACHE_SAVE_INTERVAL_SECONDS:
            return

        cache["updated_at"] = now

        path = node_cache_path()
        tmp_path = f"{path}.{uuid.uuid4().hex}.tmp"

        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)

            # Windows can briefly lock destination files.
            # Retry a few times before giving up.
            last_error = None

            for _ in range(10):
                try:
                    os.replace(tmp_path, path)
                    LAST_NODE_CACHE_SAVE = now
                    return
                except PermissionError as e:
                    last_error = e
                    time.sleep(0.1)

            print("Node cache save error:", last_error)

        finally:
            # Clean up orphan temp file if replace failed.
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass


def _merge_unique(existing, incoming, limit=100):
    result = list(existing or [])

    for item in incoming or []:
        if item and item not in result:
            result.append(item)

    return result[-limit:]


def cache_key_for_device(ip, device):
    mac = normalize_mac(device.get("mac"))

    if mac:
        return "mac", mac

    return "ip", ip


def get_cached_node(ip=None, mac=None):
    if not ENABLE_NODE_CACHE:
        return None

    cache = load_node_cache()

    mac = normalize_mac(mac)

    if mac:
        mapped_ip = cache.get("nodes_by_mac", {}).get(mac)

        if mapped_ip:
            item = cache.get("nodes_by_ip", {}).get(mapped_ip)

            if item:
                return item

    if ip:
        return cache.get("nodes_by_ip", {}).get(ip)

    return None


def remember_node_from_state(state, ip, device):
    """
    Store stable device identity/details across sessions.

    This intentionally avoids caching volatile graph values like packet counts,
    risk scores, current protocols, and active edge data.
    """

    if not ENABLE_NODE_CACHE:
        return

    if not ip or not device:
        return

    group = classify_ip(ip)

    # Avoid caching broad external internet hosts unless you later decide otherwise.
    # For this tool the value is mainly known LAN nodes.
    if group not in {"local_device", "gateway", "broadcast", "multicast", "loopback"}:
        return

    cache = load_node_cache()
    now = time.time()

    mac = normalize_mac(device.get("mac"))

    try:
        identity = build_device_identity(ip, device, group, state)
    except Exception:
        identity = {}

    item = cache["nodes_by_ip"].get(ip, {})

    first_seen_global = item.get("first_seen_global") or device.get("first_seen") or now

    item.update({
        "ip": ip,
        "mac": mac or item.get("mac"),
        "hostname": device.get("hostname") or item.get("hostname"),
        "display_name": identity.get("name") or item.get("display_name") or device.get("hostname") or ip,
        "label_line_1": identity.get("label_line_1") or item.get("label_line_1"),
        "label_line_2": identity.get("label_line_2") or item.get("label_line_2") or ip,
        "vendor": identity.get("vendor") or item.get("vendor"),
        "os": identity.get("os") or item.get("os"),
        "os_confidence": identity.get("os_confidence") or item.get("os_confidence"),
        "role": identity.get("role") or item.get("role"),
        "identity_confidence": identity.get("confidence") or item.get("identity_confidence"),
        "dns_answer_name": identity.get("dns_answer_name") or item.get("dns_answer_name"),
        "dns_names": _merge_unique(
            item.get("dns_names", []),
            state.get("dns_names", {}).get(ip, []),
            limit=100
        ),
        "first_seen_global": first_seen_global,
        "last_seen_global": device.get("last_seen") or now,
        "seen_count": int(item.get("seen_count", 0) or 0) + (0 if item else 1),
    })

    cache["nodes_by_ip"][ip] = item

    if mac:
        cache["nodes_by_mac"][mac] = ip

    save_node_cache(cache, force=False)


def apply_cached_node_to_device(state, ip, device):
    """
    Enrich an in-session device from the persistent known-node cache.
    Does not overwrite stronger current-session observations.
    """

    if not ENABLE_NODE_CACHE:
        return device

    cached = get_cached_node(ip=ip, mac=device.get("mac"))

    if not cached:
        return device

    device.setdefault("known_node", True)
    device.setdefault("known_node_cache", {})

    device["known_node_cache"] = {
        "display_name": cached.get("display_name"),
        "hostname": cached.get("hostname"),
        "vendor": cached.get("vendor"),
        "os": cached.get("os"),
        "role": cached.get("role"),
        "first_seen_global": cached.get("first_seen_global"),
        "last_seen_global": cached.get("last_seen_global"),
        "seen_count": cached.get("seen_count"),
    }

    if not device.get("mac") and cached.get("mac"):
        device["mac"] = cached.get("mac")

    if not device.get("hostname") and cached.get("hostname"):
        device["hostname"] = cached.get("hostname")

    if cached.get("dns_names"):
        dns_names = state.setdefault("dns_names", {}).setdefault(ip, [])

        for name in cached.get("dns_names", []):
            if name not in dns_names:
                dns_names.append(name)

    return device


def preload_known_nodes_into_state(state):
    """
    Add cached LAN nodes to a new/empty session so they are visible before
    traffic is seen again.

    These nodes start with packets=0 and known_node=True.
    """

    if not ENABLE_NODE_CACHE:
        return state

    cache = load_node_cache()
    now = time.time()

    devices = state.setdefault("devices", {})

    for ip, cached in cache.get("nodes_by_ip", {}).items():
        if ip in devices:
            continue

        group = classify_ip(ip)

        if group not in {"local_device", "gateway", "broadcast", "multicast", "loopback"}:
            continue

        devices[ip] = {
            "id": ip,
            "ip": ip,
            "mac": cached.get("mac"),
            "hostname": cached.get("hostname"),
            "first_seen": now,
            "last_seen": cached.get("last_seen_global") or now,
            "packets": 0,
            "bytes": 0,
            "protocols": {},
            "services": {},
            "categories": {},
            "ports": [],
            "flags": [],
            "known_node": True,
            "known_node_cache": {
                "display_name": cached.get("display_name"),
                "hostname": cached.get("hostname"),
                "vendor": cached.get("vendor"),
                "os": cached.get("os"),
                "role": cached.get("role"),
                "first_seen_global": cached.get("first_seen_global"),
                "last_seen_global": cached.get("last_seen_global"),
                "seen_count": cached.get("seen_count"),
            }
        }

        if cached.get("dns_names"):
            state.setdefault("dns_names", {})[ip] = list(cached.get("dns_names", []))

    return state


def refresh_node_cache_from_state(state):
    """
    Manual refresh action for UI button.
    """

    if not ENABLE_NODE_CACHE:
        return {
            "enabled": False,
            "updated": 0
        }

    updated = 0

    for ip, device in state.get("devices", {}).items():
        remember_node_from_state(state, ip, device)
        updated += 1

    # Force one final write for manual refresh.
    save_node_cache(force=True)

    return {
        "enabled": True,
        "updated": updated,
        "timestamp": time.time()
    }