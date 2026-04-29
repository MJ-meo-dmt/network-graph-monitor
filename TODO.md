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

# Focus

Topology + Detection + Intelligence

---

## 1. Core System

* [x] Packet capture working
* [x] Graph rendering stable
* [x] Session/state system working
* [x] Gateway detection + override
* [x] DNS routing behaviour correct
* [x] Multi-hop path highlighting
* [x] Async capture control (start/pause/stop via API)
* [x] Capture lifecycle tied to session/UI

---

## 2. Identity & Device Intelligence

* [ ] Persist identity across sessions

  * [ ] MAC → name mapping
  * [ ] Manual rename support
* [ ] Improve confidence scoring
* [ ] Improve naming fallback logic

---

## 3. Layer 2 / Switch Intelligence

### Current

* [x] Switch detection
* [x] STP / CDP / LLDP detection
* [x] OUI vendor lookup
* [x] Switch metadata UI

### CDP Expansion

* [x] Device ID (true hostname)
* [x] Use as primary name
* [x] Management IP
* [x] Software version
* [x] VTP domain
* [x] Duplex
* [x] Clean separation of fields

### LLDP (Next)

* [ ] Chassis ID
* [ ] System name
* [ ] System description
* [ ] Management address
* [ ] Capabilities

### Topology

* [ ] MAC → switch port mapping
* [x] IP → MAC tracking
* [x] IPv4 ↔ IPv6 linking via MAC
* [ ] Device → port inference
* [ ] Devices behind switch ports
* [ ] CDP/LLDP neighbor graph

---

## 4. Routing / Control-Plane Detection

### Implemented

* [x] OSPF (v2/v3)
* [x] EIGRP
* [x] RIP
* [x] VRRP / HSRP / GLBP
* [x] IGMP / PIM
* [x] Routing category tagging
* [x] Control-plane classification

### Improvements

* [ ] Extract protocol-specific fields
* [ ] Add UI badges
* [ ] Add filtering

### Deferred

* [ ] BGP
* [ ] IS-IS

---

## 5. Behaviour & Traffic Analysis

### Current

* [x] Node heat coloring (gradient improved)
* [x] Edge heat coloring (continuous gradient)
* [x] Local vs external color separation
* [x] Top talker filtering

### Improvements

* [ ] Traffic spike detection
* [ ] Protocol anomaly detection
* [ ] Improve scoring quality

---

## 6. Detection & Intelligence Engine

### Heuristics Engine

* [x] `heuristics.py` implemented
* [x] Runs on graph state
* [x] Node + edge scoring
* [x] Confidence levels
* [x] Structured findings

### Implemented Detections

* [x] Beaconing / C2
* [x] DNS anomaly
* [x] Fan-out / scanning
* [x] Lateral movement
* [x] Exfil-like behaviour
* [x] Tor / anonymity hints
* [x] Crypto/mining hints
* [x] Routing-aware suppression

### Improvements

* [ ] Role-aware scoring
* [ ] Signal correlation boosts
* [ ] Allowlist / watchlist
* [ ] Configurable thresholds

---

## 7. Behaviour Detection

### Beaconing

* [x] Interval detection
* [x] Jitter calculation
* [x] Repeated destination detection
* [ ] Duration tracking
* [ ] Volume context

### DNS

* [x] Entropy detection
* [x] Suspicious TLDs
* [x] Long/high-entropy labels
* [ ] NXDOMAIN tracking
* [ ] Burst detection

### Lateral Movement

* [x] Internal fan-out
* [x] Admin protocol spread

### Exfiltration

* [ ] Large outbound flows
* [ ] Rare destinations
* [ ] Upload-heavy ratios

### Scanning

* [x] Port scanning
* [x] Host sweep detection

---

## 8. TOR / Anonymity

* [x] Tor ports
* [x] Weak TLS detection
* [x] Multi-peer encrypted traffic
* [ ] Long-lived TLS detection
* [ ] No-DNS encrypted detection
* [ ] Tor relay dataset

---

## 9. Crypto / Mining

* [x] Known crypto ports
* [x] Multi-peer detection
* [ ] Persistent peer analysis
* [ ] Mining pattern detection

---

## 10. Attacker Behaviour Patterns

* [x] Remote access detection
* [x] Windows lateral movement
* [ ] Suspicious HTTPS patterns
* [ ] HTTP-to-IP detection
* [ ] WebSocket persistence
* [ ] ICMP covert channels

---

## 11. Graph Intelligence

* [ ] Star pattern (C2)
* [ ] Mesh (P2P/crypto)
* [ ] Fan-out patterns
* [ ] Persistent edges
* [ ] Topology shifts

---

## 12. Scoring System

* [x] Node scoring
* [x] Edge scoring
* [x] Confidence levels

### Improvements

* [ ] Combine signals
* [ ] Reduce noise
* [ ] Dynamic baselines

---

## 13. UI / UX

### Current

* [x] Panels working
* [x] Layout system
* [x] Node info panel
* [x] Intelligence display
* [x] Clean L2 node handling
* [x] Capture stats panel (NEW)

### Improvements

* [ ] Visual clutter reduction
* [ ] Zoom-based detail
* [ ] Better label control

### Intelligence UI

* [ ] Add badges:

  * Routing
  * C2
  * DNS anomaly
  * Lateral movement
  * Crypto
  * Tor

---

## 14. Filtering

### Current

* [x] Protocol filtering (expanded)
* [x] Added:

  * [x] IGMP
  * [x] SSDP
  * [x] DHCP
  * [x] NetBIOS
* [x] Port filtering
* [x] Path-aware filtering
* [x] Edge visibility logic

### Next

* [ ] Wireshark-lite filters

---

## 15. Data & Persistence

* [ ] Persist UI state
* [ ] Persist identity learning

---

## 16. Backend Improvements

* [x] Async capture (AsyncSniffer)
* [x] Capture stats tracking
* [x] Capture stats exposed to frontend
* [ ] Queue-based packet processing (next step)
* [ ] Logging improvements
* [ ] Performance optimization

---

## 17. Data Enrichment

* [ ] ASN tagging
* [ ] Tor datasets
* [ ] Allowlist / blocklist
* [ ] Asset tagging

---

## 18. Performance & Safety

* [x] Lightweight capture loop
* [x] Cached lookups
* [ ] Async heuristics
* [ ] History window limits
* [ ] Config toggles

---

## 19. Nice-to-Have

* [ ] Export graph JSON
* [ ] API endpoints
* [ ] Theme toggle

---

## 20. Architecture & Code Structure

### State

* [x] Central schema
* [x] Normalization
* [x] IPv6 filter flag
* [x] IP ↔ MAC linking

### Network Utilities

* [x] IPv6 detection helpers
* [x] DNS helpers
* [x] Reverse DNS
* [x] Flow keys

### Graph Builder

* [x] Clean separation
* [x] IPv6-aware node handling
* [x] IPv6 anchor integration
* [x] App hints integrated into flows + edges

### Intelligence Integration

* [x] Heuristics injected
* [x] Node/edge intelligence attached
* [x] UI consumes intelligence

---

## 21. App / Software Hints

### Core

* [x] `app_fingerprints.py`
* [x] Matching engine
* [x] Flow-level hints
* [x] Edge-level hints
* [x] Hint propagation into connections

### Remaining

* [ ] Local fingerprint database

  * [ ] Domain suffix DB
  * [ ] IP/domain mapping DB
  * [ ] Manual overrides
* [ ] Match by:

  * [ ] Domain suffix (expand)
  * [ ] Protocol/service/port (expand)
  * [ ] DNS-learned mappings (expand)
* [ ] UI:

  * [ ] Show hints in edge panel
  * [ ] Confidence scoring
  * [ ] Evidence display

---

## 22. Persist / Visibility Mode

* [ ] Session visibility settings
* [ ] Track `last_changed`
* [ ] Keep learned devices
* [ ] Persist DNS/app hints
* [ ] Hide inactive nodes
* [ ] Always keep:

  * pinned
  * suspicious
  * selected-linked nodes
* [ ] Add frontend time slider

---

## 23. IPv6 Support (NEW)

* [x] IPv6 detection in backend
* [x] IPv6 node rendering
* [x] IPv6 anchor
* [x] IPv6 physics attraction
* [x] IPv6 filtering toggle
* [x] IPv6 ↔ IPv4 linking via MAC

### Improvements

* [ ] Fix UI toggle persistence bug (still flipping)
* [ ] Improve IPv6 clustering

---

## 24. Capture & Visibility Issues (Investigate Later)

* [ ] ICMP under-capture / OS-level packet drop
* [ ] WiFi adapter capture limitations (Windows)
* [ ] Consider Npcap tuning / monitor mode
* [ ] Move processing to queue (important)

---

## 25. Recent Fixes

* [x] Fixed missing connection breakdown on WiFi
* [x] Fixed edge connection listing (multi-connection)
* [x] Improved edge merging logic
* [x] Fixed IPv6 disappearing issue (partially)
* [x] Fixed capture stop responsiveness
* [x] Fixed filter resets (partially)
* [x] Added capture stats panel
* [x] Expanded protocol support
* [x] Improved node + edge gradients
* [x] Added app hint pipeline (flow → edge)

---
