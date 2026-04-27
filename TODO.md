# Network Graph Monitor — Task List

## Core Sanity Checks

- [x] Switch identity stable (name, role, OS, confidence)
- [x] Gateway detection + override working
- [x] DNS routing behaves correctly
- [x] Full path highlighting works (multi-hop tracing)

---

## Identity & Device Intelligence

- [ ] Persist device identity across sessions
  - [ ] MAC → name mapping
  - [ ] Manual rename support
- [ ] Improve confidence scoring tuning
- [ ] Improve naming fallback logic (reduce generic names)

---

## Switch / L2 Intelligence

- [x] Detect switch / Layer 2 devices
- [x] L2 protocol detection (STP, CDP, LLDP, etc.)
- [x] OUI vendor lookup for switches
- [x] CDP metadata parsing:
  - [x] Hostname
  - [x] Platform
  - [x] Capabilities
  - [x] Port ID
- [x] Display switch metadata in UI

### Improvements
- [ ] Improve L2 protocol formatting (spacing, readability)
- [ ] Validate LLDP parsing (ensure not CDP-only)
- [ ] Expand CDP metadata extraction:
  - [ ] Management IP
  - [ ] Software version
  - [ ] VTP management domain
  - [ ] Duplex
- [ ] Build port-level topology hints:
  - [ ] Map `MAC → switch port`
  - [ ] Show devices behind switch ports
- [ ] Add neighbor awareness (CDP/LLDP relationships)
---

## Behavior & Traffic Analysis

- [x] Traffic-based node heat coloring (external nodes)
- [x] Top talker filtering:
  - [x] Top 5
  - [x] Top 10
  - [x] Top 20
  - [ ] Add Local/External/Both selections

### Improvements
- [ ] Refine suspicious/risk scoring
- [ ] Add anomaly detection:
  - [ ] Sudden traffic spikes
  - [ ] Unusual protocol mixes

---

## Filtering & Exploration

### Existing
- [x] Protocol filtering (checkboxes)
- [x] Service filtering
- [x] Edge visibility toggles

### New — Free-form protocol filter
- [ ] Add input box for protocol/service search
  - [ ] Match against:
    - Edge protocols
    - Services
  - [ ] Combine with existing filters (AND logic)

### New — Wireshark-style filtering (lite)
- [ ] Add advanced filter input
- [ ] Support basic syntax:
  - [ ] `ip == 192.168.8.10`
  - [ ] `port == 443`
  - [ ] `protocol == dns`
  - [ ] `domain contains google`
- [ ] Apply filter to:
  - [ ] Nodes
  - [ ] Edges
  - [ ] Events (optional later)

> ⚠ Keep this simple — do not implement full Wireshark/BPF parser.

---

## UI / UX Improvements

- [x] Panel collapse / minimize
- [x] Layout export / import
- [x] Improved arrow visibility and sizing

### Improvements
- [ ] Improve node labeling clarity:
  - [ ] Example: `xxxx-Lab [Switch]`
- [ ] Reduce visual clutter:
  - [ ] Smarter label visibility
  - [ ] Zoom-based rendering adjustments
- [ ] Improve edge highlight clarity

---

## Data & Persistence

- [ ] Persist UI state:
  - [ ] Filters
  - [ ] Gateway override
  - [ ] Layout state
- [ ] Persist learned device identity (future)

---

## Backend Improvements

- [ ] Optional: migrate to `AsyncSniffer` (true start/stop capture)
- [ ] Improve error handling/logging
- [ ] Optimize performance for larger graphs

---

## Nice-to-Have

- [ ] Export graph snapshot (JSON)
- [ ] API endpoints for external integration
- [ ] Theme toggle (dark/light mode)

---

## Suggested Next Steps (Priority)

1. Free-form protocol filter input  
2. Wireshark-style filtering (lite version)  
3. Port-level topology mapping (MAC → switch port)