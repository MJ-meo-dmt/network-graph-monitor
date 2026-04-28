# Network Graph Monitor — Master TODO

> This is NOT a packet analyzer like Wireshark.

The system should answer:

- What is talking?
- What role does it have?
- What changed?
- What looks unusual?
- What behaviour pattern is forming?

**Detection and intelligence are first-class features.**

---

# Focus
Topology + Detection + Intelligence

---

## 1. Core System

- [x] Packet capture working
- [x] Graph rendering stable
- [x] Session/state system working
- [x] Gateway detection + override
- [x] DNS routing behaviour correct
- [x] Multi-hop path highlighting

---

## 2. Identity & Device Intelligence

- [ ] Persist identity across sessions
  - [ ] MAC → name mapping
  - [ ] Manual rename support
- [ ] Improve confidence scoring
- [ ] Improve naming fallback logic

---

## 3. Layer 2 / Switch Intelligence

### Current

- [x] Switch detection
- [x] STP / CDP / LLDP detection
- [x] OUI vendor lookup
- [x] Switch metadata UI

### CDP Expansion

- [x] Device ID (true hostname)
- [x] Use as primary name
- [x] Management IP
- [x] Software version
- [x] VTP domain
- [x] Duplex
- [x] Clean separation of fields

### LLDP (Next)

- [ ] Chassis ID
- [ ] System name
- [ ] System description
- [ ] Management address
- [ ] Capabilities

### Topology

- [ ] MAC → switch port mapping
- [ ] IP → MAC tracking
- [ ] Device → port inference
- [ ] Devices behind switch ports
- [ ] CDP/LLDP neighbor graph

---

## 4. Routing / Control-Plane Detection

### Implemented

- [x] OSPF (v2/v3)
- [x] EIGRP
- [x] RIP
- [x] VRRP / HSRP / GLBP
- [x] IGMP / PIM
- [x] Routing category tagging
- [x] Control-plane classification

### Improvements

- [ ] Extract protocol-specific fields (state, group, etc.)
- [ ] Add UI badges
- [ ] Add filtering

### Deferred

- [ ] BGP
- [ ] IS-IS

---

## 5. Behaviour & Traffic Analysis

### Current

- [x] Node heat coloring
- [x] Top talker filtering

### Improvements

- [ ] Traffic spike detection
- [ ] Protocol anomaly detection
- [ ] Improve scoring quality

---

## 6. Detection & Intelligence Engine

### Heuristics Engine

- [x] `heuristics.py` implemented
- [x] Runs on graph state
- [x] Node + edge scoring
- [x] Confidence levels
- [x] Structured findings (flags, reasons, evidence)

### Implemented Detections

- [x] Beaconing / C2
- [x] DNS anomaly
- [x] Fan-out / scanning
- [x] Lateral movement
- [x] Exfil-like behaviour
- [x] Tor / anonymity hints
- [x] Crypto/mining hints
- [x] Routing-aware suppression

### Improvements

- [ ] Role-aware scoring (gateway, DNS, admin box)
- [ ] Signal correlation boosts
- [ ] Allowlist / watchlist
- [ ] Configurable thresholds

---

## 7. Behaviour Detection

### Beaconing

- [x] Interval detection
- [x] Jitter calculation
- [x] Repeated destination detection
- [ ] Add duration tracking
- [ ] Add volume context

### DNS

- [x] Entropy detection
- [x] Suspicious TLDs
- [x] Long/high-entropy labels
- [ ] NXDOMAIN tracking
- [ ] Burst detection

### Lateral Movement

- [x] Internal fan-out
- [x] Admin protocol spread

### Exfiltration

- [ ] Detect large outbound flows
- [ ] Detect rare destinations
- [ ] Detect upload-heavy ratios

### Scanning

- [x] Port scanning
- [x] Host sweep detection

---

## 8. TOR / Anonymity

- [x] Tor ports
- [x] Weak TLS 443 detection
- [x] Multi-peer encrypted traffic
- [ ] Long-lived TLS detection
- [ ] No-DNS encrypted detection
- [ ] Optional Tor relay dataset

---

## 9. Crypto / Mining

- [x] Known crypto ports
- [x] Multi-peer detection
- [ ] Persistent peer analysis
- [ ] Mining pattern detection

---

## 10. Attacker Behaviour Patterns

- [x] Remote access detection
- [x] Windows lateral movement
- [ ] Suspicious HTTPS patterns
- [ ] HTTP-to-IP detection
- [ ] WebSocket persistence
- [ ] ICMP covert channels

---

## 11. Graph Intelligence

- [ ] Star pattern (C2)
- [ ] Mesh (crypto/P2P)
- [ ] Fan-out patterns
- [ ] Persistent edges
- [ ] Topology shifts

---

## 12. Scoring System

- [x] Node scoring
- [x] Edge scoring
- [x] Confidence levels

### Improvements

- [ ] Combine signals
- [ ] Reduce noise
- [ ] Dynamic baselines

---

## 13. UI / UX

### Current

- [x] Panels working
- [x] Layout system
- [x] Node info panel
- [x] Intelligence display
- [x] Clean L2 node handling

### Improvements

- [ ] Visual clutter reduction
- [ ] Zoom-based detail
- [ ] Better label control

### Intelligence UI

- [ ] Add badges:
  - Routing
  - C2
  - DNS anomaly
  - Lateral movement
  - Crypto
  - Tor

---

## 14. Filtering

### Current

- [x] Protocol filtering
- [x] Port filtering
- [x] Path-aware filtering
- [x] Edge visibility logic

### Next

- [ ] Wireshark-lite filters:
  - `ip == x`
  - `port == x`
  - `protocol == x`
  - `flag == x`
  - `score > x`

---

## 15. Data & Persistence

- [ ] Persist UI state
- [ ] Persist identity learning

---

## 16. Backend Improvements

- [ ] Async capture option
- [ ] Logging improvements
- [ ] Performance optimization

---

## 17. Data Enrichment

- [ ] ASN tagging
- [ ] Tor / mining datasets
- [ ] Allowlist / blocklist
- [ ] Asset tagging

---

## 18. Performance & Safety

- [x] Lightweight capture loop
- [x] Cached lookups
- [ ] Async heuristics
- [ ] History window limits
- [ ] Config toggles

---

## 19. Nice-to-Have

- [ ] Export graph JSON
- [ ] API endpoints
- [ ] Theme toggle

---

## 20. Architecture & Code Structure

### State

- [x] Central schema (`state_schema.py`)
- [x] Consistent normalization

### Network Utilities (`net_utils.py`)

- [x] IP classification
- [x] DNS helpers
- [x] Reverse DNS
- [x] String cleanup
- [x] Flow keys
- [x] Domain/hostname handling

### Ports (`net_ports.py`)

- [x] Centralized definitions
- [x] Role-based grouping
- [x] Detection reuse

### Graph Builder

- [x] Clean separation (logic vs UI)
- [x] Shared utility usage

### Intelligence Integration

- [x] Heuristics injected
- [x] Node/edge intelligence attached
- [x] UI consumes intelligence

---

## 21. Recent Fixes

- [x] Removed service dropdown
- [x] Fixed stats panel
- [x] Fixed filtering path logic
- [x] Fixed missing nodes in filtered view
- [x] Improved switch node UI
- [x] Cleaned risk evidence display