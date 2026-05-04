# app_fingerprints.py
import ipaddress

from app_intel_store import (
    load_overrides,
    get_cached_domains_for_ip,
    get_cached_app_hints_for_ip,
    get_cached_app_hints_for_domains,
    remember_app_hints,
)

APP_FINGERPRINTS = [

    # -------------------------
    # Microsoft (split properly)
    # -------------------------

    {
        "name": "Microsoft Outlook / Exchange",
        "confidence": "medium",
        "domains": [
            "outlook.com",
            "outlook.office.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },
    {
        "name": "Microsoft 365 Core",
        "confidence": "low",
        "domains": [
            "office365.com",
            "microsoftonline.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },
    {
        "name": "Microsoft Teams",
        "confidence": "high",
        "domains": [
            "teams.microsoft.com",
            "msteams.net"
        ],
        "services": ["tls", "quic"],
        "ports": [443]
    },
    {
        "name": "Microsoft Skype / Legacy Comms",
        "confidence": "low",
        "domains": [
            "skype.com",
            "lync.com"
        ],
        "services": ["tls", "quic"],
        "ports": [443]
    },

    # -------------------------
    # Google (split by function)
    # -------------------------

    {
        "name": "YouTube",
        "confidence": "high",
        "domains": [
            "youtube.com",
            "googlevideo.com",
            "ytimg.com"
        ],
        "services": ["tls", "quic"],
        "ports": [443]
    },
    {
        "name": "Google APIs / Backend",
        "confidence": "medium",
        "domains": [
            "googleapis.com",
            "gstatic.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },
    {
        "name": "Google Core Services",
        "confidence": "low",
        "domains": [
            "google.com",
            "ggpht.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },

    # -------------------------
    # CDN / Infra (keep separate)
    # -------------------------

    {
        "name": "Cloudflare CDN",
        "confidence": "low",
        "domains": [
            "cloudflare.com",
            "cloudflare-dns.com",
            "cloudflare.net"
        ],
        "services": ["tls", "quic", "dns"],
        "ports": [443, 853]
    },

    # -------------------------
    # Apple
    # -------------------------

    {
        "name": "Apple iCloud",
        "confidence": "medium",
        "domains": [
            "icloud.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },
    {
        "name": "Apple Push Notification Service",
        "confidence": "high",
        "domains": [
            "push.apple.com"
        ],
        "services": ["tls"],
        "ports": [5223]
    },
    {
        "name": "Apple Services (General)",
        "confidence": "low",
        "domains": [
            "apple.com",
            "mzstatic.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },

    # -------------------------
    # Meta (split instead of bundle)
    # -------------------------

    {
        "name": "WhatsApp",
        "confidence": "high",
        "domains": [
            "whatsapp.net",
            "whatsapp.com"
        ],
        "services": ["tls", "quic"],
        "ports": [443, 5222]
    },
    {
        "name": "Instagram",
        "confidence": "medium",
        "domains": [
            "instagram.com"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },
    {
        "name": "Facebook",
        "confidence": "medium",
        "domains": [
            "facebook.com",
            "fbcdn.net"
        ],
        "services": ["tls", "https"],
        "ports": [443]
    },

    # -------------------------
    # Other Apps
    # -------------------------

    {
        "name": "Discord",
        "confidence": "high",
        "domains": [
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net"
        ],
        "services": ["tls", "quic"],
        "ports": [443]
    },
    {
        "name": "Steam",
        "confidence": "high",
        "domains": [
            "steampowered.com",
            "steamcommunity.com"
        ],
        "services": ["tls", "udp"],
        "ports": [443, 27015, 27036]
    },
    {
        "name": "Steam CDN",
        "confidence": "medium",
        "domains": [
            "steamstatic.com",
            "steamcontent.com"
        ],
        "services": ["tls"],
        "ports": [443]
    }
]


LOCAL_DOMAIN_OVERRIDES = [
    # Example:
    # {
    #     "name": "My Internal App",
    #     "confidence": "high",
    #     "domains": ["internal.company.local"],
    #     "services": ["tls", "http"],
    #     "ports": [443, 80]
    # }
]

APP_FINGERPRINT_EXCLUDED_PROTOCOLS = {
    "igmp",
    "ospf",
    "eigrp",
    "rip",
    "vrrp",
    "hsrp",
    "glbp",
    "pim",
    "arp",
    "lldp",
    "stp",
}

DOMAIN_CONTEXT_PROTOCOLS = {
    "tls",
    "https",
    "http",
    "quic",
    "dns",
    "tcp",
    "udp",
}


def normalize_protocol(value):
    if not value:
        return None
    return str(value).strip().lower() or None

def flow_has_app_layer_context(flow_or_rel):
    protocols = set()

    if flow_or_rel.get("protocol"):
        protocols.add(normalize_protocol(flow_or_rel.get("protocol")))

    for p in (flow_or_rel.get("protocols", {}) or {}).keys():
        protocols.add(normalize_protocol(p))

    protocols.discard(None)

    if protocols & DOMAIN_CONTEXT_PROTOCOLS:
        return True

    if flow_or_rel.get("service"):
        return True

    if flow_or_rel.get("domains") or flow_or_rel.get("dns_queries"):
        return True

    return False

def is_multicast_or_broadcast(value):
    if not value:
        return False

    try:
        ip = ipaddress.ip_address(str(value))
        return ip.is_multicast or ip.is_unspecified
    except Exception:
        pass

    return str(value).strip() == "255.255.255.255"


def is_app_fingerprint_candidate(flow_or_rel):
    """
    Decide whether this flow/edge should receive application fingerprints.

    Important:
    Control-plane, multicast, and L2/L3 discovery traffic should not inherit
    cached application domains from the endpoint.
    """

    protocols = set()

    if flow_or_rel.get("protocol"):
        protocols.add(normalize_protocol(flow_or_rel.get("protocol")))

    for p in (flow_or_rel.get("protocols", {}) or {}).keys():
        protocols.add(normalize_protocol(p))

    protocols.discard(None)

    if protocols & APP_FINGERPRINT_EXCLUDED_PROTOCOLS:
        return False

    src = flow_or_rel.get("from")
    dst = flow_or_rel.get("to")

    if is_multicast_or_broadcast(src) or is_multicast_or_broadcast(dst):
        return False

    return True

def normalize_domain(value):
    if not value:
        return None

    return str(value).strip().strip(".").lower() or None


def domain_matches(domain, suffix):
    domain = normalize_domain(domain)
    suffix = normalize_domain(suffix)

    if not domain or not suffix:
        return False

    return domain == suffix or domain.endswith("." + suffix)


def collect_context_domains(state, flow_or_rel):
    domains = []

    allow_cached_ip_domains = flow_has_app_layer_context(flow_or_rel)

    for value in flow_or_rel.get("domains", []) or []:
        value = normalize_domain(value)
        if value and value not in domains:
            domains.append(value)

    for value in flow_or_rel.get("dns_queries", []) or []:
        value = normalize_domain(value)
        if value and value not in domains:
            domains.append(value)

    for endpoint in [flow_or_rel.get("from"), flow_or_rel.get("to")]:
        if not endpoint:
            continue

        mapped = normalize_domain(state.get("ip_name_map", {}).get(endpoint))
        if mapped and mapped not in domains:
            domains.append(mapped)

        for value in state.get("dns_names", {}).get(endpoint, []) or []:
            value = normalize_domain(value)
            if value and value not in domains:
                domains.append(value)

        # Important:
        # Only reuse cached IP domains for flows that look application-layer.
        if allow_cached_ip_domains:
            for value in get_cached_domains_for_ip(endpoint):
                value = normalize_domain(value)
                if value and value not in domains:
                    domains.append(value)

    return domains


def app_hints_for(state, flow_or_rel, limit=1):
    if not is_app_fingerprint_candidate(flow_or_rel):
        return []

    domains = collect_context_domains(state, flow_or_rel)

    cached_hints = []
    for endpoint in [flow_or_rel.get("from"), flow_or_rel.get("to")]:
        for hint in get_cached_app_hints_for_ip(endpoint):
            if hint not in cached_hints:
                cached_hints.append(hint)

    for hint in get_cached_app_hints_for_domains(domains):
        if hint not in cached_hints:
            cached_hints.append(hint)

    services = set()
    if flow_or_rel.get("service"):
        services.add(str(flow_or_rel.get("service")).lower())

    for service in (flow_or_rel.get("services", {}) or {}).keys():
        services.add(str(service).lower())

    protocols = set(str(p).lower() for p in (flow_or_rel.get("protocols", {}) or {}).keys())

    if flow_or_rel.get("protocol"):
        protocols.add(str(flow_or_rel.get("protocol")).lower())

    ports = set()
    for p in flow_or_rel.get("ports", []) or []:
        try:
            ports.add(int(p))
        except Exception:
            pass

    for p in [flow_or_rel.get("src_port"), flow_or_rel.get("dst_port")]:
        try:
            if p is not None:
                ports.add(int(p))
        except Exception:
            pass

    fingerprints = load_overrides() + LOCAL_DOMAIN_OVERRIDES + APP_FINGERPRINTS
    results = []

    for fp in fingerprints:
        score = 0
        evidence = []

        matched_domains = []
        matched_services = []
        matched_ports = []

        for domain in domains:
            for suffix in fp.get("domains", []) or []:
                if domain_matches(domain, suffix):
                    matched_domains.append(domain)
                    break

        if not matched_domains:
            continue

        fp_services = set(str(s).lower() for s in fp.get("services", []) or [])
        matched_services = sorted((services | protocols) & fp_services)

        try:
            fp_ports = set(int(p) for p in fp.get("ports", []) or [])
        except Exception:
            fp_ports = set()

        matched_ports = sorted(ports & fp_ports)

        score += min(len(set(matched_domains)), 3) * 70
        score += min(len(matched_services), 2) * 15
        score += min(len(matched_ports), 2) * 5

        for d in list(dict.fromkeys(matched_domains))[:3]:
            evidence.append(f"domain match: {d}")

        for s in matched_services[:2]:
            evidence.append(f"service/protocol: {s}")

        for p in matched_ports[:2]:
            evidence.append(f"port: {p}")

        if score >= 80:
            confidence = "high"
        elif score >= 70:
            confidence = "medium"
        else:
            confidence = fp.get("confidence", "low")

        results.append({
            "name": fp.get("name", "Unknown app"),
            "confidence": confidence,
            "score": score,
            "evidence": evidence[:6]
        })

    results.sort(key=lambda x: x.get("score", 0), reverse=True)

    deduped = []
    seen = set()

    for item in results:
        name = item["name"]

        if name in seen:
            continue

        seen.add(name)
        deduped.append(item)

    if not deduped and cached_hints:
        return cached_hints[:limit]

    dominant = deduped[:limit]

    if dominant and domains:
        remember_app_hints(
            ip=flow_or_rel.get("to"),
            domains=domains,
            hints=dominant
        )

    return dominant