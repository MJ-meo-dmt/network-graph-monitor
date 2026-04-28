# heuristics.py

import math
import time
import ipaddress
from collections import defaultdict
from net_utils import classify_ip, clean_domain
from net_ports import (
    ADMIN_PORTS,
    CRYPTO_PORTS,
    TOR_COMMON_PORTS,
    DNS_SUSPICIOUS_TLDS,
    VPN_PROXY_PORTS,
    REMOTE_ACCESS_PORTS
)


def clamp_score(value):
    return max(0, min(100, int(round(value))))

def confidence_for_score(score):
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def entropy(value):
    value = str(value or "")
    if not value:
        return 0.0

    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1

    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def add_finding(bucket, key, flag, score, reason, category="suspicious", evidence=None):
    if not key:
        return

    item = bucket.setdefault(key, {
        "score": 0,
        "flags": [],
        "reasons": [],
        "categories": [],
        "confidence": "low",
        "evidence": []
    })

    if flag not in item["flags"]:
        item["flags"].append(flag)

    if reason not in item["reasons"]:
        item["reasons"].append(reason)

    if category and category not in item["categories"]:
        item["categories"].append(category)

    if evidence:
        item["evidence"].append(evidence)

    # Weighted additive score:
    # - keep first signal meaningful
    # - allow multiple weak signals to combine
    # - avoid instant 100 from one noisy heuristic
    previous = int(item.get("score", 0) or 0)
    combined = previous + (score * (1.0 - previous / 125.0))

    item["score"] = clamp_score(combined)
    item["confidence"] = confidence_for_score(item["score"])


def event_time(event):
    try:
        return float(event.get("timestamp") or 0)
    except Exception:
        return 0.0


def detect_beaconing(state, node_findings, edge_findings, now):
    """
    Detect regular repeated communication.

    Uses events rather than payload inspection.
    Works best when state["events"] has recent event history.
    """

    by_pair = defaultdict(list)

    for event in state.get("events", []) or []:
        src = event.get("src_ip")
        dst = event.get("dst_ip")
        proto = event.get("protocol") or "unknown"

        if not src or not dst:
            continue

        if classify_ip(src) != "local_device":
            continue

        # C2-like beaconing is most useful for local -> external.
        if classify_ip(dst) != "external_host":
            continue

        t = event_time(event)
        if t <= 0:
            continue

        by_pair[(src, dst, proto)].append(t)

    for (src, dst, proto), times in by_pair.items():
        times = sorted(set(times))

        if len(times) < 6:
            continue

        intervals = [
            times[i] - times[i - 1]
            for i in range(1, len(times))
            if times[i] - times[i - 1] > 0
        ]

        if len(intervals) < 5:
            continue

        avg = sum(intervals) / len(intervals)

        if avg < 5:
            continue

        variance = sum(abs(i - avg) for i in intervals) / len(intervals)
        jitter_ratio = variance / avg if avg else 1

        if jitter_ratio <= 0.18:
            score = 45

            if avg >= 20:
                score += 10

            if proto in {"tls", "https", "tcp"}:
                score += 8

            reason = f"regular outbound interval ~{avg:.1f}s"

            edge_key = f"{src}|{dst}"

            add_finding(
                node_findings,
                src,
                "possible_c2",
                score,
                reason,
                category="possible_c2",
                evidence={
                    "dst": dst,
                    "protocol": proto,
                    "samples": len(times),
                    "avg_interval": round(avg, 2),
                    "jitter_ratio": round(jitter_ratio, 3)
                }
            )

            add_finding(
                edge_findings,
                edge_key,
                "possible_c2",
                score,
                reason,
                category="possible_c2",
                evidence={
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "samples": len(times),
                    "avg_interval": round(avg, 2),
                    "jitter_ratio": round(jitter_ratio, 3)
                }
            )


def detect_dns_anomalies(state, node_findings, edge_findings):
    dns_names = state.get("dns_names", {}) or {}
    domains = state.get("domains", {}) or {}

    # domains: IP -> resolved/display domain
    for ip, domain in domains.items():
        inspect_domain(ip, domain, node_findings, None)

    # dns_names: src/ip -> queried names
    for owner, names in dns_names.items():
        if not isinstance(names, list):
            continue

        unique_domains = set()

        for domain in names:
            domain = clean_domain(domain)
            if not domain:
                continue

            unique_domains.add(domain)
            inspect_domain(owner, domain, node_findings, None)

        if len(unique_domains) > 80:
            add_finding(
                node_findings,
                owner,
                "dns_heavy",
                35,
                f"many unique DNS names ({len(unique_domains)})",
                category="dns"
            )


def inspect_domain(owner, domain, node_findings, edge_findings):
    domain = clean_domain(domain)
    if not domain:
        return

    labels = [x for x in domain.split(".") if x]
    if not labels:
        return

    longest = max(labels, key=len)
    domain_entropy = entropy(domain)
    label_entropy = entropy(longest)
    tld = labels[-1] if labels else ""

    if len(longest) >= 28 and label_entropy >= 3.7:
        add_finding(
            node_findings,
            owner,
            "dns_anomaly",
            42,
            "long high-entropy DNS label",
            category="dns",
            evidence={
                "domain": domain,
                "label": longest[:80],
                "entropy": round(label_entropy, 2)
            }
        )

    if len(domain) >= 70 and domain_entropy >= 3.9:
        add_finding(
            node_findings,
            owner,
            "possible_dns_tunnel",
            55,
            "very long high-entropy DNS name",
            category="possible_exfil",
            evidence={
                "domain": domain[:120],
                "entropy": round(domain_entropy, 2)
            }
        )

    if tld in DNS_SUSPICIOUS_TLDS and len(domain) > 25:
        add_finding(
            node_findings,
            owner,
            "dns_watchlist_tld",
            20,
            f"DNS query uses watchlist TLD .{tld}",
            category="dns",
            evidence={
                "domain": domain
            }
        )


def detect_fanout_and_scanning(state, node_findings, edge_findings):
    targets_by_src = defaultdict(set)
    ports_by_src = defaultdict(set)
    internal_targets_by_src = defaultdict(set)
    admin_targets_by_src = defaultdict(set)
    remote_targets_by_src = defaultdict(set)

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")
        dst_port = flow.get("dst_port")

        if not src or not dst:
            continue

        targets_by_src[src].add(dst)

        if dst_port:
            ports_by_src[src].add(dst_port)

        if classify_ip(src) == "local_device" and classify_ip(dst) == "local_device":
            internal_targets_by_src[src].add(dst)

            if dst_port in ADMIN_PORTS:
                admin_targets_by_src[src].add(dst)

            if dst_port in REMOTE_ACCESS_PORTS:
                remote_targets_by_src[src].add(dst)

    for src, targets in targets_by_src.items():
        target_count = len(targets)
        port_count = len(ports_by_src.get(src, set()))

        if target_count >= 25:
            add_finding(
                node_findings,
                src,
                "fanout",
                35,
                f"communicated with many targets ({target_count})",
                category="suspicious"
            )

        if target_count >= 15 and port_count >= 10:
            add_finding(
                node_findings,
                src,
                "scan_like",
                58,
                f"many targets and ports ({target_count} targets, {port_count} ports)",
                category="suspicious"
            )

    for src, targets in internal_targets_by_src.items():
        if len(targets) >= 10:
            add_finding(
                node_findings,
                src,
                "lateral_movement",
                55,
                f"internal fan-out to {len(targets)} LAN hosts",
                category="lateral_movement"
            )

    for src, targets in admin_targets_by_src.items():
        if len(targets) >= 5:
            add_finding(
                node_findings,
                src,
                "admin_protocol_fanout",
                65,
                f"admin protocol fan-out to {len(targets)} LAN hosts",
                category="lateral_movement"
            )

    for src, targets in remote_targets_by_src.items():
        if len(targets) >= 3:
            add_finding(
                node_findings,
                src,
                "remote_access_fanout",
                60,
                f"remote access fan-out to {len(targets)} LAN hosts",
                category="lateral_movement"
            )


def detect_exfil_like(state, node_findings, edge_findings):
    outbound_by_src = defaultdict(int)
    external_targets_by_src = defaultdict(set)

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")
        bytes_count = int(flow.get("bytes", 0) or 0)

        if classify_ip(src) != "local_device":
            continue

        if classify_ip(dst) != "external_host":
            continue

        outbound_by_src[src] += bytes_count
        external_targets_by_src[src].add(dst)

        if bytes_count >= 50_000_000:
            edge_key = f"{src}|{dst}"

            add_finding(
                node_findings,
                src,
                "possible_exfil",
                55,
                "large outbound transfer to external host",
                category="possible_exfil",
                evidence={
                    "dst": dst,
                    "bytes": bytes_count
                }
            )

            add_finding(
                edge_findings,
                edge_key,
                "possible_exfil",
                55,
                "large outbound transfer",
                category="possible_exfil",
                evidence={
                    "src": src,
                    "dst": dst,
                    "bytes": bytes_count
                }
            )

    for src, total_bytes in outbound_by_src.items():
        target_count = len(external_targets_by_src[src])

        if total_bytes >= 150_000_000 and target_count <= 3:
            add_finding(
                node_findings,
                src,
                "possible_exfil",
                65,
                "high outbound volume to few external destinations",
                category="possible_exfil",
                evidence={
                    "bytes": total_bytes,
                    "external_targets": target_count
                }
            )


def detect_tor_crypto_like(state, node_findings, edge_findings):
    external_tls_peers = defaultdict(set)
    external_crypto_peers = defaultdict(set)

    for flow in state.get("flows", {}).values():
        src = flow.get("from")
        dst = flow.get("to")
        dst_port = flow.get("dst_port")
        proto = str(flow.get("protocol") or "").lower()
        service = str(flow.get("service") or "").lower()
        bytes_count = int(flow.get("bytes", 0) or 0)
        packets = int(flow.get("packets", 0) or 0)

        if classify_ip(src) != "local_device":
            continue

        if classify_ip(dst) != "external_host":
            continue

        edge_key = f"{src}|{dst}"

        if dst_port in CRYPTO_PORTS:
            external_crypto_peers[src].add(dst)

            add_finding(
                edge_findings,
                edge_key,
                "crypto_like",
                45,
                f"known crypto/mining port {dst_port}",
                category="crypto"
            )

        if dst_port in TOR_COMMON_PORTS:
            if dst_port == 443:
                # 443 is too common; only weak supporting signal
                if proto in {"tls", "https", "tcp"} or service in {"tls", "https", "quic"}:
                    add_finding(
                        edge_findings,
                        edge_key,
                        "tor_possible_weak",
                        5,
                        "TLS/HTTPS on port 443; weak Tor-compatible signal only",
                        category="anonymity"
                    )
            else:
                add_finding(
                    node_findings,
                    src,
                    "tor_like",
                    45,
                    f"Tor-associated port {dst_port}",
                    category="anonymity"
                )

                add_finding(
                    edge_findings,
                    edge_key,
                    "tor_like",
                    45,
                    f"Tor-associated port {dst_port}",
                    category="anonymity"
                )
        
        if dst_port in VPN_PROXY_PORTS:
            add_finding(
                node_findings,
                src,
                "vpn_proxy_like",
                35,
                f"VPN/proxy-associated port {dst_port}",
                category="anonymity"
            )

            add_finding(
                edge_findings,
                edge_key,
                "vpn_proxy_like",
                35,
                f"VPN/proxy-associated port {dst_port}",
                category="anonymity"
            )

        if proto in {"tls", "https", "tcp"} or service in {"tls", "https", "quic"}:
            if packets >= 20 or bytes_count >= 250_000:
                external_tls_peers[src].add(dst)

    for src, peers in external_tls_peers.items():
        if len(peers) >= 8:
            add_finding(
                node_findings,
                src,
                "many_encrypted_external_peers",
                30,
                f"many encrypted external peers ({len(peers)})",
                category="anonymity"
            )

    for src, peers in external_crypto_peers.items():
        if len(peers) >= 3:
            add_finding(
                node_findings,
                src,
                "crypto_like",
                55,
                f"multiple crypto/mining peers ({len(peers)})",
                category="crypto"
            )


def summarize_findings(node_findings, edge_findings):
    all_flags = defaultdict(int)
    max_score = 0

    for bucket in (node_findings, edge_findings):
        for finding in bucket.values():
            max_score = max(max_score, int(finding.get("score", 0) or 0))

            for flag in finding.get("flags", []):
                all_flags[flag] += 1

    return {
        "max_score": max_score,
        "flag_counts": dict(sorted(all_flags.items())),
        "nodes_flagged": len(node_findings),
        "edges_flagged": len(edge_findings)
    }


def run_heuristics(state):
    """
    Main entry point.

    Returns:
    {
        "nodes": {
            "192.168.1.50": {
                "score": 72,
                "flags": [...],
                "reasons": [...],
                "categories": [...],
                "confidence": "medium",
                "evidence": [...]
            }
        },
        "edges": {
            "192.168.1.50|8.8.8.8": {...}
        },
        "summary": {...},
        "generated_at": 1234567890.0
    }
    """

    now = time.time()

    node_findings = {}
    edge_findings = {}

    detect_routing_control_plane(state, node_findings, edge_findings)
    detect_beaconing(state, node_findings, edge_findings, now)
    detect_dns_anomalies(state, node_findings, edge_findings)
    detect_fanout_and_scanning(state, node_findings, edge_findings)
    detect_exfil_like(state, node_findings, edge_findings)
    detect_tor_crypto_like(state, node_findings, edge_findings)

    return {
        "nodes": node_findings,
        "edges": edge_findings,
        "summary": summarize_findings(node_findings, edge_findings),
        "generated_at": now
    }

def detect_routing_control_plane(state, node_findings, edge_findings):
    routing_by_src = defaultdict(set)

    for flow in state.get("flows", {}).values():
        if flow.get("category") != "routing":
            continue

        src = flow.get("from")
        proto = flow.get("routing_protocol") or flow.get("protocol")

        if not src or not proto:
            continue

        routing_by_src[src].add(proto)

    for src, protocols in routing_by_src.items():
        add_finding(
            node_findings,
            src,
            "routing_control_plane",
            0,
            f"routing/control-plane traffic observed: {', '.join(sorted(protocols))}",
            category="routing",
            evidence={
                "protocols": sorted(protocols)
            }
        )