import time
from scapy.all import IP, IPv6, Ether, TCP, UDP, DNS, DNSQR, ARP, ICMP
from scapy.all import Dot3, LLC, SNAP
from scapy.layers.l2 import STP
from scapy.all import DNSRR, NBNSQueryRequest, NBNSQueryResponse

SERVICE_PORTS = {
    20: ("ftp-data", "file_transfer"),
    21: ("ftp", "file_transfer"),
    22: ("ssh", "management"),
    23: ("telnet", "management"),
    25: ("smtp", "mail"),
    53: ("dns", "name_resolution"),
    67: ("dhcp", "network_infra"),
    68: ("dhcp", "network_infra"),
    69: ("tftp", "file_transfer"),
    80: ("http", "web"),
    110: ("pop3", "mail"),
    123: ("ntp", "time"),
    135: ("msrpc", "windows"),
    137: ("netbios-ns", "windows"),
    138: ("netbios-dgm", "windows"),
    139: ("netbios-ssn", "windows"),
    143: ("imap", "mail"),
    161: ("snmp", "management"),
    162: ("snmptrap", "management"),
    389: ("ldap", "directory"),
    443: ("tls", "web"),
    445: ("smb", "windows"),
    465: ("smtps", "mail"),
    500: ("ike", "vpn"),
    514: ("syslog", "logging"),
    515: ("lpd", "printer"),
    554: ("rtsp", "camera"),
    587: ("smtp-submission", "mail"),
    631: ("ipp", "printer"),
    636: ("ldaps", "directory"),
    993: ("imaps", "mail"),
    995: ("pop3s", "mail"),
    1433: ("mssql", "database"),
    1521: ("oracle", "database"),
    1723: ("pptp", "vpn"),
    1883: ("mqtt", "iot"),
    2049: ("nfs", "file_share"),
    3306: ("mysql", "database"),
    3389: ("rdp", "remote_access"),
    5432: ("postgres", "database"),
    5900: ("vnc", "remote_access"),
    5985: ("winrm", "windows"),
    5986: ("winrm-ssl", "windows"),
    8080: ("http-alt", "web"),
    8443: ("https-alt", "web"),
    9100: ("jetdirect", "printer"),

    # OT / ICS
    102: ("s7comm", "ot"),
    502: ("modbus", "ot"),
    20000: ("dnp3", "ot"),
    44818: ("ethernet-ip", "ot"),
    2222: ("ethernet-ip-implicit", "ot"),
    47808: ("bacnet", "ot"),
    4840: ("opc-ua", "ot"),
    9600: ("omron-fins", "ot"),
    2404: ("iec-104", "ot"),
    1962: ("pcworx", "ot"),
    34962: ("profinet", "ot"),
    34963: ("profinet", "ot"),
    34964: ("profinet", "ot"),
}


L2_PROTOCOL_MACS = {
    "01:00:0c:cc:cc:cc": "cdp",
    "01:00:0c:cc:cc:cd": "vtp",
    "01:80:c2:00:00:00": "stp",
    "01:80:c2:00:00:0e": "lldp",
    "01:00:0c:00:00:00": "cisco_l2",
}

def get_l2_macs(pkt):
    if Ether in pkt:
        return pkt[Ether].src, pkt[Ether].dst

    if Dot3 in pkt:
        return pkt[Dot3].src, pkt[Dot3].dst

    return None, None


def clean_l2_name(value):
    if not value:
        return None

    value = str(value).strip().replace("\x00", "")

    # Keep only readable names
    if len(value) < 3:
        return None

    if not any(c.isalpha() for c in value):
        return None

    if not all((c.isalnum() or c in "-_./") for c in value):
        return None

    bad = {"cisco", "version", "port", "platform", "capabilities"}
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

        bad = ("cisco", "version", "port", "platform", "capabilities")
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
        "l2_kind": "switch",
        "service": proto,
        "category": "layer2",
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


def payload_len(pkt):
    try:
        return len(bytes(pkt.payload.payload.payload))
    except Exception:
        return 0


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
        "transport": None
    }

    src_mac, dst_mac = get_l2_macs(pkt)

    if src_mac:
        event["src_mac"] = src_mac

    if dst_mac:
        event["dst_mac"] = dst_mac

    l2_event = detect_l2_control(pkt)

    if l2_event:
        event.update(l2_event)
        event["category"] = "layer2"
        event["service"] = l2_event["protocol"]
        event["transport"] = "l2"
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