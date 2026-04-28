# analyzer.py

import time
from scapy.all import IP, IPv6, Ether, TCP, UDP, DNS, DNSQR, ARP, ICMP, raw
from scapy.all import Dot3, LLC, SNAP, Dot1Q
from scapy.layers.l2 import STP 
from scapy.contrib.lldp import LLDPDU
from scapy.layers.eap import EAPOL
from scapy.all import NBNSQueryRequest, NBNSQueryResponse
from net_ports import (
    SERVICE_PORTS,
    ROUTING_IP_PROTOCOLS,
    ROUTING_UDP_PORTS,
    ROUTING_MULTICASTS,
)

try:
    from scapy.contrib.cdp import (
        CDPMsgDeviceID,
        CDPMsgPortID,
        CDPMsgPlatform,
        CDPMsgCapabilities,
        CDPMsgAddr,
        CDPMsgSoftwareVersion,
        CDPMsgVTPMgmtDomain,
        CDPMsgDuplex,
    )
except Exception:
    CDPMsgDeviceID = None
    CDPMsgPortID = None
    CDPMsgPlatform = None
    CDPMsgCapabilities = None
    CDPMsgAddr = None
    CDPMsgSoftwareVersion = None
    CDPMsgVTPMgmtDomain = None
    CDPMsgDuplex = None


L2_PROTOCOL_MACS = {
    "01:00:0c:cc:cc:cc": "cdp",
    "01:00:0c:cc:cc:cd": "vtp",
    "01:00:0c:00:00:00": "cisco_l2",

    "01:80:c2:00:00:00": "stp",
    "01:80:c2:00:00:08": "stp",
    "01:80:c2:00:00:0e": "lldp",

    "01:80:c2:00:00:02": "lacp",
    "01:80:c2:00:00:03": "lacp",
}

def l2_kind_for_proto(proto):
    if proto in {"stp", "rstp", "mstp", "cdp", "lldp", "vtp", "cisco_l2", "lacp"}:
        return "switch"

    if proto in {"eapol", "dot1x"}:
        return "auth_control"

    if proto in {"vlan"}:
        return "vlan"

    return "l2_device"


def l2_category_for_proto(proto):
    if proto in {"stp", "rstp", "mstp", "cdp", "lldp", "vtp", "cisco_l2", "lacp"}:
        return "layer2_control"

    if proto in {"eapol", "dot1x"}:
        return "auth"

    if proto == "vlan":
        return "layer2"

    return "layer2"

def clean_l2_value(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        value = value.decode(errors="ignore")

    value = str(value).strip().strip(".").replace("\x00", "")

    # Clean stringified bytes like: b'FastEthernet0/3'
    if value.startswith("b'") and value.endswith("'"):
        value = value[2:-1]

    if value.startswith('b"') and value.endswith('"'):
        value = value[2:-1]

    return value.strip() or None

def extract_cdp_address_value(value):
    if value is None:
        return None

    try:
        if isinstance(value, (list, tuple)):
            for item in value:
                found = extract_cdp_address_value(item)
                if found:
                    return found

        text = clean_l2_value(value)

        if not text:
            return None

        # Keep this conservative: return IPv4-looking values only.
        parts = text.replace(",", " ").replace(";", " ").split()

        for part in parts:
            part = part.strip()

            if part.count(".") == 3:
                nums = part.split(".")

                if all(n.isdigit() and 0 <= int(n) <= 255 for n in nums):
                    return part

        return text if text.count(".") == 3 else None

    except Exception:
        return None


def normalize_duplex(value):
    value = clean_l2_value(value)

    if value is None:
        return None

    low = str(value).lower()

    if low in {"1", "full", "fullduplex", "full-duplex"}:
        return "full"

    if low in {"0", "half", "halfduplex", "half-duplex"}:
        return "half"

    return value


def routing_type_name(proto, pkt=None, dst=None, dst_port=None):
    if proto == "ospf":
        # OSPF packet types:
        names = {
            1: "hello",
            2: "database_description",
            3: "link_state_request",
            4: "link_state_update",
            5: "link_state_ack",
        }

        try:
            payload = bytes(pkt[IP].payload) if IP in pkt else bytes(pkt[IPv6].payload)
            if len(payload) >= 2:
                return names.get(payload[1], f"type_{payload[1]}")
        except Exception:
            pass

        return "ospf"

    if proto == "eigrp":
        return "eigrp"

    if proto == "pim":
        return "pim"

    if proto == "vrrp":
        return "vrrp"

    if proto == "rip":
        return "rip"

    if proto == "hsrp":
        if dst == "224.0.0.102":
            return "hsrp_v2"
        return "hsrp"

    if proto == "glbp":
        return "glbp"

    if proto == "igmp":
        return "igmp"

    return proto or "routing"


def detect_routing_control(pkt, event):
    dst = event.get("dst_ip")
    dst_port = event.get("dst_port")
    proto_name = None

    if IP in pkt:
        proto_name = ROUTING_IP_PROTOCOLS.get(int(pkt[IP].proto))
    elif IPv6 in pkt:
        proto_name = ROUTING_IP_PROTOCOLS.get(int(pkt[IPv6].nh))

    if not proto_name and event.get("transport") == "udp":
        proto_name = ROUTING_UDP_PORTS.get(dst_port)

    # IGMP is IP protocol 2. Keep separate because it is multicast control.
    if IP in pkt and int(pkt[IP].proto) == 2:
        proto_name = "igmp"

    if not proto_name:
        return False

    multicast_role = ROUTING_MULTICASTS.get(dst)
    rtype = routing_type_name(proto_name, pkt=pkt, dst=dst, dst_port=dst_port)

    event["protocol"] = proto_name
    event["service"] = proto_name
    event["category"] = "routing"
    event["routing_protocol"] = proto_name
    event["routing_type"] = rtype
    event["routing"] = {
        "protocol": proto_name,
        "type": rtype,
        "multicast_role": multicast_role,
        "router_id": None,
        "area_id": None,
        "group_id": None,
        "details": {}
    }

    # Best-effort OSPF fields from raw header.
    if proto_name == "ospf":
        try:
            payload = bytes(pkt[IP].payload) if IP in pkt else bytes(pkt[IPv6].payload)

            if len(payload) >= 16:
                router_id = ".".join(str(x) for x in payload[4:8])
                area_id = ".".join(str(x) for x in payload[8:12])

                event["routing"]["router_id"] = router_id
                event["routing"]["area_id"] = area_id
        except Exception:
            pass

    event["summary"] = (
        f"{event.get('src_ip')} -> {event.get('dst_ip')} "
        f"{proto_name.upper()} {rtype}"
    )

    return True

def extract_l2_metadata(pkt):
    meta = {}

    # --- LLDP ---
    if pkt.haslayer(LLDPDU):
        lldp = pkt[LLDPDU]

        try:
            for tlv in lldp.tlvlist:
                t = getattr(tlv, "type", None)

                # System Name
                if t == 5:
                    meta["hostname"] = clean_l2_name(str(tlv.value))

                # Port ID
                elif t == 2:
                    meta["port_id"] = str(tlv.value)

                # System Description (often contains platform)
                elif t == 6:
                    desc = str(tlv.value)
                    meta["platform"] = clean_l2_name(desc)

                # Capabilities
                elif t == 7:
                    meta["capabilities"] = str(tlv.value)

        except Exception:
            pass

    # --- CDP (fallback parse) ---
    if CDPMsgDeviceID and pkt.haslayer(CDPMsgDeviceID):
        try:
            device_id = clean_l2_name(pkt[CDPMsgDeviceID].val)
            meta["device_id"] = device_id
            meta["hostname"] = device_id
        except Exception:
            pass

    if CDPMsgPortID and pkt.haslayer(CDPMsgPortID):
        try:
            meta["port_id"] = clean_l2_value(pkt[CDPMsgPortID].iface)
        except Exception:
            pass

    if CDPMsgPlatform and pkt.haslayer(CDPMsgPlatform):
        try:
            meta["platform"] = clean_l2_value(pkt[CDPMsgPlatform].val)
        except Exception:
            pass

    if CDPMsgCapabilities and pkt.haslayer(CDPMsgCapabilities):
        try:
            meta["capabilities"] = clean_l2_value(pkt[CDPMsgCapabilities].cap)
        except Exception:
            pass
    
    if CDPMsgAddr and pkt.haslayer(CDPMsgAddr):
        try:
            addr_layer = pkt[CDPMsgAddr]
            meta["management_ip"] = (
                extract_cdp_address_value(getattr(addr_layer, "addr", None))
                or extract_cdp_address_value(getattr(addr_layer, "addresses", None))
                or extract_cdp_address_value(addr_layer)
            )
        except Exception:
            pass

    if CDPMsgSoftwareVersion and pkt.haslayer(CDPMsgSoftwareVersion):
        try:
            meta["software_version"] = clean_l2_value(pkt[CDPMsgSoftwareVersion].val)
        except Exception:
            pass

    if CDPMsgVTPMgmtDomain and pkt.haslayer(CDPMsgVTPMgmtDomain):
        try:
            meta["vtp_domain"] = clean_l2_value(pkt[CDPMsgVTPMgmtDomain].val)
        except Exception:
            pass

    if CDPMsgDuplex and pkt.haslayer(CDPMsgDuplex):
        try:
            meta["duplex"] = normalize_duplex(getattr(pkt[CDPMsgDuplex], "duplex", None))
        except Exception:
            pass

    return meta

def safe_int(value):
    try:
        return int(value)
    except Exception:
        return None

def get_l2_macs(pkt):
    if Ether in pkt:
        return pkt[Ether].src, pkt[Ether].dst

    if Dot3 in pkt:
        return pkt[Dot3].src, pkt[Dot3].dst

    return None, None


def clean_l2_name(value):
    if not value:
        return None

    value = clean_l2_value(value)
    if not value:
        return None

    # Keep only readable names
    if len(value) < 3:
        return None

    if not any(c.isalpha() for c in value):
        return None

    if not all((c.isalnum() or c in "-_./") for c in value):
        return None

    bad = {
        "cisco",
        "version",
        "port",
        "platform",
        "capabilities",
        "internetwork",
        "switch",
        "router",
        "transparent",
        "bridge",
        "operating"
    }
    if value.lower() in bad:
        return None

    return value[:64]

def detect_l2_control(pkt):
    src_mac, dst_mac = get_l2_macs(pkt)

    if not src_mac or not dst_mac:
        return None

    dst_mac = dst_mac.lower()

    proto = L2_PROTOCOL_MACS.get(dst_mac)

    # STP may be visible as an actual STP layer too
    if not proto and STP in pkt:
        proto = "stp"
    
    if not proto and EAPOL in pkt:
        proto = "eapol"

    if not proto:
        return None

    raw_text = ""

    try:
        raw_text = bytes(pkt).decode(errors="ignore")
    except Exception:
        raw_text = ""

    device_name = None

    for token in raw_text.replace("\x00", " ").replace("\r", " ").replace("\n", " ").split():
        token = token.strip()

        if len(token) < 3:
            continue

        if not any(c.isalpha() for c in token):
            continue

        bad = (
            "cisco",
            "version",
            "port",
            "platform",
            "capabilities",
            "internetwork",
            "switch",
            "router",
            "transparent",
            "bridge",
            "operating"
        )
        if token.lower().startswith(bad):
            continue

        device_name = clean_l2_name(token)
        if device_name:
            break
            
    return {
        "protocol": proto,
        "src_ip": None,
        "dst_ip": None,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "l2_device_name": device_name,
        "l2_kind": l2_kind_for_proto(proto),
        "service": proto,
        "category": l2_category_for_proto(proto),
        "transport": "l2",
        "summary": f"{proto.upper()} from {src_mac}"
    }

def guess_service(src_port, dst_port, transport):
    for port in [dst_port, src_port]:
        if port in SERVICE_PORTS:
            service, category = SERVICE_PORTS[port]

            if transport == "udp" and port == 443:
                return "quic", "web"

            return service, category

    return None, None

def tcp_flag_summary(flags):
    flags = str(flags)

    names = []

    if "S" in flags:
        names.append("SYN")
    if "A" in flags:
        names.append("ACK")
    if "F" in flags:
        names.append("FIN")
    if "R" in flags:
        names.append("RST")
    if "P" in flags:
        names.append("PSH")
    if "U" in flags:
        names.append("URG")

    return ",".join(names) if names else flags

def get_ip_pair(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst, "ipv4"

    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst, "ipv6"

    return None, None, None


def analyze_packet(pkt):
    now = time.time()

    event = {
        "timestamp": now,
        "src_ip": None,
        "dst_ip": None,
        "ip_version": None,
        "src_mac": None,
        "dst_mac": None,
        "protocol": "unknown",
        "src_port": None,
        "dst_port": None,
        "size": len(pkt),
        "domain": None,
        "dns_answers": [],
        "flags": None,
        "service": None,        # smb, rdp, ssh, modbus, s7, bacnet, etc.
        "category": None,       # web, name_resolution, ot, management, discovery, file_share
        "direction": None,      # local_to_external, external_to_local, local_to_local
        "summary": None,        # human readable short packet summary
        "ttl": None,
        "ip_len": None,
        "tcp_flags": None,
        "payload_len": 0,
        "transport": None,
        "l2_proto": None,
        "l2_details": {},
        "routing_protocol": None,
        "routing_type": None,
        "routing": None,
        "vlan": None,
        "vlans": []
    }

    src_mac, dst_mac = get_l2_macs(pkt)

    if src_mac:
        event["src_mac"] = src_mac

    if dst_mac:
        event["dst_mac"] = dst_mac

    if Dot3 in pkt:
        event["l2_proto"] = "dot3"

    if Dot1Q in pkt:
        event["l2_proto"] = event["l2_proto"] or "dot1q"
        event["vlan"] = safe_int(pkt[Dot1Q].vlan)

        try:
            event["vlans"] = [safe_int(layer.vlan) for layer in pkt.getlayers(Dot1Q)]
            event["vlans"] = [v for v in event["vlans"] if v is not None]
        except Exception:
            event["vlans"] = [event["vlan"]] if event["vlan"] is not None else []

        event["l2_details"]["vlan"] = event["vlan"]
        event["l2_details"]["vlans"] = event["vlans"]

    if LLC in pkt:
        event["l2_proto"] = event["l2_proto"] or "llc"
        event["l2_details"]["llc_dsap"] = safe_int(pkt[LLC].dsap)
        event["l2_details"]["llc_ssap"] = safe_int(pkt[LLC].ssap)
        event["l2_details"]["llc_ctrl"] = safe_int(pkt[LLC].ctrl)

    if SNAP in pkt:
        event["l2_proto"] = event["l2_proto"] or "snap"
        event["l2_details"]["snap_oui"] = safe_int(pkt[SNAP].OUI)
        event["l2_details"]["snap_code"] = safe_int(pkt[SNAP].code)

    if EAPOL in pkt:
        event["protocol"] = "eapol"
        event["service"] = "eapol"
        event["category"] = "auth"
        event["transport"] = "l2"
        event["l2_proto"] = "eapol"
        event["summary"] = f"EAPOL from {event.get('src_mac')} to {event.get('dst_mac')}"
        return event

    l2_event = detect_l2_control(pkt)
    l2_meta = extract_l2_metadata(pkt)

    if l2_event:
        event.update(l2_event)
        event["category"] = "layer2"
        event["service"] = l2_event["protocol"]
        event["transport"] = "l2"
        event["l2_meta"] = l2_meta
        return event

    if ARP in pkt:
        event["protocol"] = "arp"
        event["src_ip"] = pkt[ARP].psrc
        event["dst_ip"] = pkt[ARP].pdst
        event["ip_version"] = "arp"
        return event

    src, dst, ip_version = get_ip_pair(pkt)

    if not src or not dst:
        return None

    event["src_ip"] = src
    event["dst_ip"] = dst
    event["ip_version"] = ip_version

    if IP in pkt:
        event["ttl"] = int(pkt[IP].ttl)
        event["ip_len"] = int(pkt[IP].len or 0)
    elif IPv6 in pkt:
        event["ttl"] = int(pkt[IPv6].hlim)
        event["ip_len"] = int(pkt[IPv6].plen or 0)

    if TCP in pkt:
        event["src_port"] = int(pkt[TCP].sport)
        event["dst_port"] = int(pkt[TCP].dport)
        event["flags"] = str(pkt[TCP].flags)
        event["transport"] = "tcp"
        event["tcp_flags"] = tcp_flag_summary(pkt[TCP].flags)
        event["payload_len"] = max(0, len(bytes(pkt[TCP].payload)))

    if UDP in pkt:
        event["src_port"] = int(pkt[UDP].sport)
        event["dst_port"] = int(pkt[UDP].dport)
        event["transport"] = "udp"
        event["payload_len"] = max(0, len(bytes(pkt[UDP].payload)))
    
    if detect_routing_control(pkt, event):
        return event
    
    if DNS in pkt:
        event["protocol"] = "dns"

        if pkt.haslayer(DNSQR):
            try:
                event["domain"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                event["domain"] = None

        try:
            dns = pkt[DNS]

            for i in range(dns.ancount):
                rr = dns.an[i]

                name = None
                value = None

                if hasattr(rr, "rrname"):
                    name = rr.rrname.decode(errors="ignore").rstrip(".")

                if hasattr(rr, "rdata"):
                    value = rr.rdata
                    if isinstance(value, bytes):
                        value = value.decode(errors="ignore").rstrip(".")

                event["dns_answers"].append({
                    "name": name,
                    "value": str(value)
                })
        except Exception:
            pass

    elif TCP in pkt:
        event["protocol"] = "tcp"

        if event["dst_port"] == 80 or event["src_port"] == 80:
            event["protocol"] = "http"
        elif event["dst_port"] == 443 or event["src_port"] == 443:
            event["protocol"] = "tls"

    elif UDP in pkt:
        event["protocol"] = "udp"

        if event["dst_port"] == 443 or event["src_port"] == 443:
            event["protocol"] = "quic"

    service, category = guess_service(
        event.get("src_port"),
        event.get("dst_port"),
        event.get("transport")
    )

    event["service"] = service
    event["category"] = category

    if ICMP in pkt:
        event["protocol"] = "icmp"
        event["service"] = "icmp"
        event["category"] = "diagnostic"
    elif DNS in pkt:
        event["protocol"] = "dns"
        event["service"] = "dns"
        event["category"] = "name_resolution"
    elif service:
        event["protocol"] = service

    port_text = ""
    if event.get("dst_port"):
        port_text = f":{event['dst_port']}"

    try:
        if NBNSQueryRequest in pkt or NBNSQueryResponse in pkt:
            event["protocol"] = "netbios"

            name = None

            if hasattr(pkt.lastlayer(), "QUESTION_NAME"):
                name = pkt.lastlayer().QUESTION_NAME

            if name:
                event["hostname"] = str(name).strip().replace("\x00", "")
    except Exception:
        pass

    event["summary"] = (
        f"{event.get('src_ip')} -> {event.get('dst_ip')}{port_text} "
        f"{event.get('protocol')}"
    )

    if event.get("domain"):
        event["summary"] += f" {event['domain']}"

    if event.get("tcp_flags"):
        event["summary"] += f" [{event['tcp_flags']}]"
        
    return event