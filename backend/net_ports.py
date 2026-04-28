# net_ports.py

WINDOWS_PORTS = {135, 137, 138, 139, 445, 3389}
LINUX_PORTS = {22, 111, 2049}
PRINTER_PORTS = {515, 631, 9100}
CAMERA_PORTS = {554, 8000, 8080}

VPN_PROXY_PORTS = {1080, 1194, 1701, 1723, 3128, 500, 4500, 51820, 8080, 8443}

# REMOTE_ACCESS_PORTS = “interactive remote access risk”
REMOTE_ACCESS_PORTS = {
    22, 23, 3389, 5900, 5901, 5985, 5986
}

CRYPTO_PORTS = {
    8333,   # Bitcoin P2P
    8332,   # Bitcoin RPC
    18333,  # Bitcoin testnet
    30303,  # Ethereum P2P
    8545,   # Ethereum JSON-RPC
    8546,   # Ethereum WebSocket RPC
    3333, 4444, 5555,  # Stratum/mining common
    14444, 14433,      # mining pool variants
}

TOR_COMMON_PORTS = {
    9001,  # common relay ORPort
    9030,  # common directory port
    9040,  # transparent proxy
    9050,  # SOCKS
    9051,  # control
    9150,  # Tor Browser SOCKS
    443,   # common ORPort choice, weak signal only
}

# ADMIN_PORTS = “ports that are useful for lateral/security detection”
ADMIN_PORTS = {
    22,      # SSH
    23,      # Telnet
    135,     # MSRPC
    137, 138, 139,  # NetBIOS
    389,     # LDAP
    445,     # SMB
    636,     # LDAPS
    88,      # Kerberos
    3389,    # RDP
    5985, 5986,  # WinRM
    5900, 5901,  # VNC
    161, 162,    # SNMP
    514,         # Syslog
    623,         # IPMI
    2049,        # NFS
    3306, 5432, 1433, 1521, 27017, 6379, 9200,  # DB/admin targets
}

DNS_SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "stream",
    "quest", "cfd", "icu", "cyou", "sbs", "monster", "gq", "tk", "ml", "ga", "cf"
}

WIRED_NAME_HINTS = {
    "desktop", "pc", "workstation", "server", "nas", "proxmox",
    "esxi", "ubuntu", "debian", "windows"
}

MOBILE_NAME_HINTS = {
    "iphone", "ipad", "android", "galaxy", "samsung",
    "a05", "a05s", "redmi", "xiaomi", "huawei", "honor",
    "oppo", "vivo", "pixel", "phone"
}

# WIRED_SERVICE_PORTS = “ports that imply this endpoint is probably wired/server-ish”
WIRED_SERVICE_PORTS = {
    22,    # ssh
    53,    # dns
    67,    # dhcp
    80,    # http
    443,   # tls
    445,   # smb
    3389,  # rdp
    8080,  # http-alt
    8443,  # https-alt
}

SENSITIVE_PORT_LABELS = {
    22: "ssh",
    23: "telnet",
    88: "kerberos",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    445: "smb",
    514: "syslog",
    623: "ipmi",
    636: "ldaps",
    1080: "socks-proxy",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3128: "http-proxy",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    5901: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    9200: "elasticsearch",
    27017: "mongodb",
}

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

        # Discovery / local network
    1900: ("ssdp", "discovery"),
    3702: ("ws-discovery", "discovery"),
    5353: ("mdns", "name_resolution"),
    5355: ("llmnr", "name_resolution"),

    # Common infra / auth / voice
    88: ("kerberos", "directory"),
    1812: ("radius", "auth"),
    1813: ("radius-acct", "auth"),
    4500: ("ipsec-nat-t", "vpn"),
    5060: ("sip", "voip"),
    5061: ("sips", "voip"),

    # More databases / platforms
    6379: ("redis", "database"),
    9200: ("elasticsearch", "database"),
    27017: ("mongodb", "database"),

    # More remote/admin
    1080: ("socks-proxy", "proxy"),
    3128: ("http-proxy", "proxy"),
    5901: ("vnc", "remote_access"),

    # OT / ICS 
    789: ("redlion-crimson", "ot"),
    1911: ("fox", "ot"),
    2455: ("codesys", "ot"),
    18245: ("ge-srtp", "ot"),
    20547: ("proconos", "ot"),
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

PORT_ROLE_HINTS = {
    53: "DNS server",
    67: "DHCP server",
    80: "Web device",
    443: "Web device",
    445: "Windows/SMB device",
    139: "Windows/NetBIOS device",
    3389: "Windows/RDP device",
    9100: "Printer",
    515: "Printer",
    631: "Printer",
    22: "SSH device",
    23: "Telnet device",
    554: "Camera/RTSP device",
    1900: "UPnP device",
}


