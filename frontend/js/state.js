let graph = { nodes: [], edges: [], stats: {} };
let edgeCache = {};
let nodeMap = {};
let selectedNode = null;
let selectedEdge = null;
let selectedEdgeKey = null;
let hoverNode = null;
let enabledProtocolCache = new Set();
let filterDirty = true;
let visibleEdgesCache = [];
let visibleEdgesDirty = true;
let physicsPausedUntil = 0;
let selectedConnection = null;
let isEditingGateway = false;

const TCP_SERVICES = new Set([
    "tcp",
    "http",
    "tls",
    "ssh",
    "ftp",
    "ftp-data",
    "telnet",
    "smtp",
    "pop3",
    "imap",
    "smb",
    "msrpc",
    "ldap",
    "ldaps",
    "rdp",
    "vnc",
    "winrm",
    "winrm-ssl",
    "mssql",
    "mysql",
    "postgres",
    "oracle",
    "nfs",
    "rtsp",
    "socks-proxy",
    "http-proxy",
    "redis",
    "elasticsearch",
    "mongodb"
]);

const UDP_SERVICES = new Set([
    "udp",
    "dns",
    "dhcp",
    "ntp",
    "tftp",
    "snmp",
    "snmptrap",
    "syslog",
    "ike",
    "quic",
    "ssdp",
    "mdns",
    "llmnr",
    "netbios-ns",
    "netbios-dgm",
    "bacnet",
    "omron-fins",
    "ethernet-ip-implicit",
    "ws-discovery",
    "mdns",
    "radius",
    "radius-acct",
    "sip",
    "sips",
    "ike",
    "ipsec-nat-t"
]);

let camera = JSON.parse(localStorage.getItem("nm:camera") || JSON.stringify({
    x: 0,
    y: 0,
    zoom: 1
}));

let pinnedNodePositions = JSON.parse(localStorage.getItem("nm:pinnedNodePositions") || "{}");

let draggingNode = null;
let isPanning = false;
let pointerMoved = false;
let panStart = { x: 0, y: 0 };
let dragOffset = { x: 0, y: 0 };

const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
