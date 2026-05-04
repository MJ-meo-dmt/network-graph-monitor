# app_intel_store.py

import json
import os
import time
import uuid
import threading
from config import APP_INTEL_DIR, APP_INTEL_CACHE_PATH, APP_FINGERPRINT_OVERRIDES_PATH

LOCK = threading.RLock()
CACHE = None
OVERRIDES = None


def empty_cache():
    return {
        "version": 1,
        "updated_at": None,
        "domains": {},
        "ip_to_domains": {},
        "domain_to_ips": {},
        "ip_app_hints": {},
        "domain_app_hints": {}
    }


def ensure_dir():
    os.makedirs(APP_INTEL_DIR, exist_ok=True)


def atomic_write_json(path, data):
    ensure_dir()
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)

    os.replace(tmp, path)


def load_cache():
    global CACHE

    with LOCK:
        if CACHE is not None:
            return CACHE

        ensure_dir()

        if not os.path.exists(APP_INTEL_CACHE_PATH):
            CACHE = empty_cache()
            atomic_write_json(APP_INTEL_CACHE_PATH, CACHE)
            return CACHE

        try:
            with open(APP_INTEL_CACHE_PATH, "r", encoding="utf-8") as f:
                CACHE = json.load(f)
        except Exception:
            CACHE = empty_cache()

        CACHE.setdefault("domains", {})
        CACHE.setdefault("ip_to_domains", {})
        CACHE.setdefault("domain_to_ips", {})
        CACHE.setdefault("ip_app_hints", {})
        CACHE.setdefault("domain_app_hints", {})

        return CACHE


def save_cache():
    with LOCK:
        cache = load_cache()
        cache["updated_at"] = time.time()
        atomic_write_json(APP_INTEL_CACHE_PATH, cache)


def load_overrides():
    global OVERRIDES

    with LOCK:
        if OVERRIDES is not None:
            return OVERRIDES

        ensure_dir()

        if not os.path.exists(APP_FINGERPRINT_OVERRIDES_PATH):
            OVERRIDES = []
            atomic_write_json(APP_FINGERPRINT_OVERRIDES_PATH, OVERRIDES)
            return OVERRIDES

        try:
            with open(APP_FINGERPRINT_OVERRIDES_PATH, "r", encoding="utf-8") as f:
                OVERRIDES = json.load(f)
        except Exception:
            OVERRIDES = []

        if not isinstance(OVERRIDES, list):
            OVERRIDES = []

        return OVERRIDES


def normalize_domain(domain):
    if not domain:
        return None

    return str(domain).strip().strip(".").lower() or None


def remember_dns_mapping(ip, domain):
    ip = str(ip or "").strip()
    domain = normalize_domain(domain)

    if not ip or not domain:
        return

    with LOCK:
        cache = load_cache()

        ip_domains = cache.setdefault("ip_to_domains", {}).setdefault(ip, [])
        if domain not in ip_domains:
            ip_domains.append(domain)

        domain_ips = cache.setdefault("domain_to_ips", {}).setdefault(domain, [])
        if ip not in domain_ips:
            domain_ips.append(ip)

        domain_item = cache.setdefault("domains", {}).setdefault(domain, {
            "first_seen": time.time(),
            "last_seen": time.time(),
            "ips": []
        })

        domain_item["last_seen"] = time.time()

        if ip not in domain_item.setdefault("ips", []):
            domain_item["ips"].append(ip)


def remember_app_hints(ip=None, domains=None, hints=None):
    if not hints:
        return

    domains = [normalize_domain(d) for d in (domains or [])]
    domains = [d for d in domains if d]

    with LOCK:
        cache = load_cache()

        if ip:
            current = cache.setdefault("ip_app_hints", {}).setdefault(str(ip), [])
            for hint in hints:
                if hint not in current:
                    current.append(hint)

        for domain in domains:
            current = cache.setdefault("domain_app_hints", {}).setdefault(domain, [])
            for hint in hints:
                if hint not in current:
                    current.append(hint)


def get_cached_domains_for_ip(ip):
    if not ip:
        return []

    return load_cache().get("ip_to_domains", {}).get(str(ip), []) or []


def get_cached_app_hints_for_ip(ip):
    if not ip:
        return []

    return load_cache().get("ip_app_hints", {}).get(str(ip), []) or []


def get_cached_app_hints_for_domains(domains):
    out = []

    for domain in domains or []:
        domain = normalize_domain(domain)
        if not domain:
            continue

        for hint in load_cache().get("domain_app_hints", {}).get(domain, []) or []:
            if hint not in out:
                out.append(hint)

    return out