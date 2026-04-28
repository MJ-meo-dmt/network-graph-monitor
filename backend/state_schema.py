# state_schema.py

def empty_state():
    return {
        "devices": {},
        "flows": {},
        "events": [],
        "scanner_map": {},
        "external_map": {},
        "dns_map": {},
        "dns_names": {},
        "hostnames": {},
        "domains": {},
        "ip_name_map": {},
        "gateway": None,
        "rdns_checked": {},
        "services": {},
        "categories": {},
        "gateway_override": None,
        "l2_devices": {},
        "l2_links": {},
        "access_paths": {},
        "default_switch": None,
        "intelligence": {
            "nodes": {},
            "edges": {},
            "summary": {}
        },
        "filters": {
            "show_ipv6": False
        }
    }
    

def normalize_state(state):
    if not isinstance(state, dict):
        state = empty_state()

    base = empty_state()

    for key, value in base.items():
        state.setdefault(key, value)

    state.setdefault("intelligence", {})
    state["intelligence"].setdefault("nodes", {})
    state["intelligence"].setdefault("edges", {})
    state["intelligence"].setdefault("summary", {})

    state.setdefault("filters", {})
    state["filters"].setdefault("show_ipv6", False)

    return state