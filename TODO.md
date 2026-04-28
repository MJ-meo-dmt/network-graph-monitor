# Network Graph Monitor — Master TODO

> This is NOT a packet analyzer like Wireshark.

The system should answer:

* What is talking?
* What role does it have?
* What changed?
* What looks unusual?
* What behaviour pattern is forming?

**Detection and intelligence are first-class features.**

---

**Focus: Topology + Detection + Intelligence**

## 1. Core Sanity Checks

* [x] Switch identity stable (name, role, OS, confidence)
* [x] Gateway detection + override working
* [x] DNS routing behaves correctly
* [x] Full path highlighting works (multi-hop tracing)
* [x] Graph rendering stable
* [x] Session/state system working

---

## 2. Identity & Device Intelligence

* [ ] Persist device identity across sessions

  * [ ] MAC → name mapping
  * [ ] Manual rename support
* [ ] Improve confidence scoring tuning
* [ ] Improve naming fallback logic (reduce generic names)

---

## 3. Layer 2 / Switch Intelligence

### Current

* [x] Detect switch / Layer 2 devices
* [x] L2 protocol detection (STP, CDP, LLDP, etc.)
* [x] OUI vendor lookup for switches
* [x] CDP metadata parsing:

  * [x] Hostname
  * [x] Platform
  * [x] Capabilities
  * [x] Port ID
* [x] Display switch metadata in UI

### Improvements

* [ ] Improve L2 protocol formatting (spacing, readability)
* [ ] Validate LLDP parsing (ensure not CDP-only)

#### CDP Expansion

* [ ] Extract CDP Device ID (true hostname)
* [ ] Use Device ID as primary switch name
* [ ] Extract management IP
* [ ] Extract software version
* [ ] Extract VTP domain
* [ ] Extract duplex
* [ ] Keep VTP domain separate from Device ID

#### LLDP Expansion

* [ ] Extract chassis ID
* [ ] Extract system name
* [ ] Extract system description
* [ ] Extract management address
* [ ] Extract capabilities

#### Port-Level Topology

* [ ] Map `MAC → switch port`
* [ ] Track `IP → MAC`
* [ ] Infer device → switch port
* [ ] Show devices behind switch ports
* [ ] Add neighbor awareness (CDP/LLDP relationships)

---

## 4. Routing / Control-Plane Detection

### OSPF

* [ ] Detect OSPFv2 (IP proto 89)
* [ ] Detect OSPFv3 (IPv6)
* [ ] Parse packet types (Hello, DBD, LSR, LSU, LSAck)
* [ ] Extract router ID and area
* [ ] Tag `category = routing`
* [ ] Add badge + filter
* [ ] Style as control-plane

### EIGRP

* [ ] Detect (IP proto 88)
* [ ] Parse opcode (Hello, Update, Query, Reply)
* [ ] Add badge + filter

### RIP

* [ ] Detect UDP 520
* [ ] Detect multicast `224.0.0.9`
* [ ] Add badge + filter

### VRRP / HSRP / GLBP

* [ ] VRRP (IP proto 112)
* [ ] HSRP (UDP 1985)
* [ ] GLBP (UDP 3222)
* [ ] Extract group/state
* [ ] Tag as gateway redundancy
* [ ] Add badges + filters

### Multicast / Infra

* [ ] IGMP detection
* [ ] PIM (IP proto 103)
* [ ] Tag multicast control-plane

### Deferred

* [ ] BGP (ignore for now — WAN side)

---

## 5. Behaviour & Traffic Analysis

### Current

* [x] Traffic-based node heat coloring
* [x] Top talker filtering:

  * [x] Top 5
  * [x] Top 10
  * [x] Top 20
  * [ ] Add Local / External / Both

### Improvements

* [ ] Refine suspicious/risk scoring
* [ ] Detect sudden traffic spikes
* [ ] Detect unusual protocol mixes

---

## 6. Detection & Intelligence Engine

### Foundation

* [ ] Create `heuristics.py`
* [ ] Run on graph state (not packets)
* [ ] Output:

  * node flags
  * edge flags
  * suspicion scores
  * reasons
  * confidence

### Categories

* [ ] normal
* [ ] routing
* [ ] switching
* [ ] dns
* [ ] crypto
* [ ] anonymity
* [ ] remote_access
* [ ] lateral_movement
* [ ] possible_c2
* [ ] possible_exfil
* [ ] suspicious

---

## 7. Behaviour Detection

### Beaconing / C2

* [ ] Detect repeated connections to same destination
* [ ] Detect consistent intervals
* [ ] Detect low-volume periodic traffic
* [ ] Flag `possible_c2`

### DNS Anomalies

* [ ] Domain entropy calculation
* [ ] Detect long/random subdomains
* [ ] Detect NXDOMAIN bursts
* [ ] Flag:

  * `dns_anomaly`
  * `dns_tunnel`
  * `dns_exfil`

### Lateral Movement

* [ ] Detect internal fan-out
* [ ] Detect SMB/RDP/WinRM bursts
* [ ] Flag `lateral_movement`

### Exfiltration

* [ ] Detect large outbound transfers
* [ ] Detect new external destinations
* [ ] Flag `possible_exfil`

### Scanning

* [ ] Detect port scanning
* [ ] Detect host sweeps
* [ ] Flag `scan_like`

---

## 8. TOR / Anonymity Detection

* [ ] Optional Tor relay list
* [ ] Detect long-lived TLS connections
* [ ] Detect no-DNS encrypted traffic
* [ ] Detect multiple external peers
* [ ] Tag `anonymity`
* [ ] Flag `tor_like`
* [ ] Add badge + filter

---

## 9. Crypto / Mining Detection

### Ports

* [ ] 8333 (Bitcoin)
* [ ] 30303 (Ethereum)
* [ ] 3333 / 4444 / 5555 (Stratum)

### Behaviour

* [ ] Persistent peer connections
* [ ] Distributed external peers
* [ ] High-frequency small packets
* [ ] Flag `crypto_like`
* [ ] Flag `possible_mining`
* [ ] Add badge + filter

---

## 10. Malware / Attacker Patterns

### Remote Access

* [ ] Monitor RDP, SSH, WinRM, VNC, Telnet
* [ ] Flag unusual access

### Windows Lateral Movement

* [ ] SMB, NetBIOS, LDAP, Kerberos
* [ ] Flag admin fan-out

### Suspicious Web / C2

* [ ] HTTPS to rare domains
* [ ] HTTP to IP
* [ ] WebSocket-like persistence
* [ ] Flag suspicious beaconing

### Covert Channels

* [ ] ICMP anomaly detection
* [ ] Flag `icmp_tunnel_like`

---

## 11. Graph Pattern Intelligence

* [ ] Detect star (C2)
* [ ] Detect mesh (crypto/P2P)
* [ ] Detect fan-out (lateral)
* [ ] Detect persistent edges
* [ ] Detect topology shifts

---

## 12. Scoring System

### Node

* [ ] `node.suspicion_score`
* [ ] flags + reasons

### Edge

* [ ] `edge.suspicion_score`
* [ ] flags + reasons

### Confidence

* [ ] low / medium / high
* [ ] Prefer “possible_*” labels

---

## 13. UI / UX Improvements

### Current

* [x] Panel collapse / minimize
* [x] Layout export / import
* [x] Improved arrow visibility

### Improvements

* [ ] Improve node labeling clarity
* [ ] Reduce visual clutter
* [ ] Smarter label visibility
* [ ] Zoom-based rendering adjustments
* [ ] Improve edge highlighting

### Intelligence UI

* [ ] Add badges:

  * Routing / TOR / CRYPTO / C2 / EXFIL / SCAN / LATERAL
* [ ] Add node/edge intelligence panel:

  * score
  * flags
  * reasons
  * confidence
* [ ] Suspicious node/edge styling

---

## 14. Filtering & Exploration

### Existing

* [x] Protocol filtering
* [x] Service filtering
* [x] Edge visibility toggles

### New

#### Free-form Protocol Filter

* [ ] Input box for protocol/service search
* [ ] Combine with existing filters

#### Wireshark-style (Lite)

* [ ] Add advanced filter input
* [ ] Support:

  * `ip == x`
  * `port == x`
  * `protocol == x`
  * `domain contains x`
  * `flag == possible_c2`
  * `score > 70`

> ⚠ Keep lightweight — no full parser

---

## 15. Data & Persistence

* [ ] Persist UI state:

  * filters
  * gateway override
  * layout
* [ ] Persist learned device identity

---

## 16. Backend Improvements

* [ ] Optional `AsyncSniffer`
* [ ] Improve logging/error handling
* [ ] Optimize large graph performance

---

## 17. Data Enrichment (Later)

* [ ] Tor relay list
* [ ] Mining pool list
* [ ] ASN tagging
* [ ] Allowlist / blocklist
* [ ] Known asset tagging

---

## 18. Performance & Safety

* [ ] Keep capture loop lightweight
* [ ] Run heuristics async
* [ ] Cache entropy/lookups
* [ ] Limit history window
* [ ] Config toggles for heavy checks

---

## 19. Nice-to-Have

* [ ] Export graph snapshot (JSON)
* [ ] API endpoints
* [ ] Theme toggle

---

## 20. Priority Roadmap

### Immediate

1. CDP expansion
2. OSPF detection
3. EIGRP + HSRP/VRRP
4. Free-form filter
5. Wireshark-lite filter
6. `heuristics.py` foundation
7. DNS entropy
8. Beaconing detection

### Next

9. Scoring system
10. UI badges + intelligence panel
11. Category/flag filters

### Later

12. Crypto + TOR detection
13. Lateral movement
14. Exfiltration
15. External intel feeds

---
