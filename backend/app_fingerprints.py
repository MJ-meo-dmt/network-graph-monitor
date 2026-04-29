# app_fingerprints.py

APP_FINGERPRINTS = [
    {
        "name": "Microsoft 365 / Outlook",
        "confidence": "medium",
        "domains": [
            "office365.com",
            "outlook.com",
            "outlook.office.com",
            "microsoft.com",
            "microsoftonline.com",
            "live.com",
            "msedge.net",
            "azureedge.net"
        ],
        "services": ["tls", "quic", "https"],
        "ports": [443]
    },
    {
        "name": "Microsoft Teams",
        "confidence": "medium",
        "domains": [
            "teams.microsoft.com",
            "skype.com",
            "lync.com",
            "msteams.net"
        ],
        "services": ["tls", "quic", "https"],
        "ports": [443]
    },
    {
        "name": "Google / Chrome / YouTube",
        "confidence": "medium",
        "domains": [
            "google.com",
            "youtube.com",
            "googlevideo.com",
            "gstatic.com",
            "googleapis.com",
            "ggpht.com",
            "ytimg.com"
        ],
        "services": ["tls", "quic", "https"],
        "ports": [443]
    },
    {
        "name": "Cloudflare",
        "confidence": "low",
        "domains": [
            "cloudflare.com",
            "cloudflare-dns.com",
            "cloudflare.net"
        ],
        "services": ["tls", "quic", "dns"],
        "ports": [443, 853]
    },
    {
        "name": "Apple Services",
        "confidence": "medium",
        "domains": [
            "apple.com",
            "icloud.com",
            "mzstatic.com",
            "push.apple.com"
        ],
        "services": ["tls", "quic", "https"],
        "ports": [443, 5223]
    },
    {
        "name": "Meta / Facebook / Instagram / WhatsApp",
        "confidence": "medium",
        "domains": [
            "facebook.com",
            "fbcdn.net",
            "instagram.com",
            "whatsapp.net",
            "whatsapp.com"
        ],
        "services": ["tls", "quic", "https"],
        "ports": [443, 5222]
    },
    {
        "name": "Discord",
        "confidence": "medium",
        "domains": [
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net"
        ],
        "services": ["tls", "quic", "https"],
        "ports": [443]
    },
    {
        "name": "Steam",
        "confidence": "medium",
        "domains": [
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com"
        ],
        "services": ["tls", "udp", "https"],
        "ports": [443, 27015, 27036]
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

    return domains


def app_hints_for(state, flow_or_rel, limit=5):
    domains = collect_context_domains(state, flow_or_rel)

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

    fingerprints = LOCAL_DOMAIN_OVERRIDES + APP_FINGERPRINTS
    results = []

    for fp in fingerprints:
        evidence = []

        for domain in domains:
            for suffix in fp.get("domains", []) or []:
                if domain_matches(domain, suffix):
                    evidence.append(f"domain match: {domain}")
                    break

        fp_services = set(str(s).lower() for s in fp.get("services", []) or [])
        service_hits = sorted((services | protocols) & fp_services)

        for s in service_hits:
            evidence.append(f"service/protocol: {s}")

        fp_ports = set(int(p) for p in fp.get("ports", []) or [])
        port_hits = sorted(ports & fp_ports)

        for p in port_hits:
            evidence.append(f"port: {p}")

        # Require a domain match OR a stronger service+port match.
        has_domain_match = any(e.startswith("domain match:") for e in evidence)
        has_service_port_match = bool(service_hits and port_hits)

        if not has_domain_match and not has_service_port_match:
            continue

        confidence = fp.get("confidence", "low")

        if has_domain_match and service_hits:
            confidence = "high" if confidence == "medium" else confidence

        results.append({
            "name": fp.get("name", "Unknown app"),
            "confidence": confidence,
            "evidence": evidence[:6]
        })

    deduped = []
    seen = set()

    for item in results:
        name = item["name"]

        if name in seen:
            continue

        seen.add(name)
        deduped.append(item)

    return deduped[:limit]