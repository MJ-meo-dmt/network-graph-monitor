// filters.js

function getTextFilter(id) {
    return (document.getElementById(id)?.value || "").trim().toLowerCase();
}

function isTcpLikeProtocol(p) {
    return TCP_SERVICES.has(String(p || "").toLowerCase());
}

function isUdpLikeProtocol(p) {
    return UDP_SERVICES.has(String(p || "").toLowerCase());
}

function isIPv6NodeId(id) {
    // Keep virtual anchors and L2 MAC nodes
    if (!id || id.startsWith("__") || id.startsWith("l2:")) return false;

    return id.includes(":");
}

function getEnabledProtocols() {
    if (!filterDirty) return enabledProtocolCache;

    enabledProtocolCache = new Set();

    document.querySelectorAll("[data-protocol]").forEach(cb => {
        if (cb.checked) enabledProtocolCache.add(cb.dataset.protocol);
    });

    filterDirty = false;
    return enabledProtocolCache;
}

function edgeVisible(e) {
    const enabled = getEnabledProtocols();
    const protocols = e.data?.protocols || {};
    const protocolKeys = Object.keys(protocols);
    const showLogical = document.getElementById("show-logical-edges")?.checked ?? true;
    const showGatewayToExternal = document.getElementById("show-gateway-to-external")?.checked ?? true;
    const showExternalToGateway = document.getElementById("show-external-to-gateway")?.checked ?? true;
    const vr = e.data?.visual_route;

    if (!showLogical && vr === "logical_direct") {
        return false;
    }

    if (!showGatewayToExternal && vr === "gateway_to_external") {
        return false;
    }

    if (!showExternalToGateway && vr === "external_to_gateway") {
        return false;
    }

    function protocolAllowed(p) {
        p = String(p || "unknown").toLowerCase();

        // Transport gates
        if (isTcpLikeProtocol(p) && !enabled.has("tcp")) return false;
        if (isUdpLikeProtocol(p) && !enabled.has("udp")) return false;

        // Specific protocol/service checkbox wins
        if (document.querySelector(`[data-protocol="${p}"]`)) {
            return enabled.has(p);
        }

        // Unknown/unlisted protocols fall under Other
        return enabled.has("unknown");
    }

    // Aggregated edges: visible if ANY contained protocol is allowed
    if (protocolKeys.length > 0) {
        return protocolKeys.some(protocolAllowed) && edgeMatchesFilters(e);
    }

    // Simple edge fallback
    const type = e.type || "unknown";
    return protocolAllowed(type) && edgeMatchesFilters(e);
}

function edgeMatchesFilters(e) {
    const ipFilter = getTextFilter("filter-ip");
    const portFilter = getTextFilter("filter-port");
    const serviceFilter = document.getElementById("filter-service")?.value || "";

    if (ipFilter) {
        const hay = `${e.from} ${e.to}`.toLowerCase();
        if (!hay.includes(ipFilter)) return false;
    }

    if (portFilter) {
        const ports = e.data?.ports || [];
        if (!ports.map(String).includes(portFilter)) return false;
    }

    if (serviceFilter) {
        const services = e.data?.services || {};
        if (!Object.keys(services).some(s => s.toLowerCase().includes(serviceFilter))) {
            return false;
        }
    }

    return true;
}

function nodeVisible(n) {
    const ipFilter = getTextFilter("filter-ip");
    const serviceFilter = document.getElementById("filter-service")?.value || "";

    if (n.virtual) return true;

    if (ipFilter && !(n.id || "").toLowerCase().includes(ipFilter)) {
        return false;
    }

    if (serviceFilter) {
        const services = n.data?.services || {};
        if (!Object.keys(services).some(s => s.toLowerCase().includes(serviceFilter))) {
            return false;
        }
    }

    return true;
}

function showEdgeLabelsEnabled() {
    return document.getElementById("show-edge-labels")?.checked ?? true;
}

function rebuildVisibleEdges() {
    visibleEdgesCache = graph.edges.filter(edgeVisible);
    visibleEdgesDirty = false;
}

function getVisibleEdges() {
    if (visibleEdgesDirty) rebuildVisibleEdges();
    return visibleEdgesCache;
}

function markVisualFilterDirty() {
    filterDirty = true;
    visibleEdgesDirty = true;
    physicsPausedUntil = Date.now() + 120;
}

function connectionKey(c) {
    return `${c.actual_src || ""}|${c.actual_dst || ""}|${c.type || ""}`;
}

function edgeContainsSelectedConnection(e) {
    if (!selectedConnection) return false;

    const wantedSrc = selectedConnection.actual_src;
    const wantedDst = selectedConnection.actual_dst;
    const wantedType = selectedConnection.type;

    const data = e.data || {};

    // 1. Check expanded connection list
    if ((data.connections || []).some(c =>
        c.actual_src === wantedSrc &&
        c.actual_dst === wantedDst &&
        c.type === wantedType
    )) {
        return true;
    }

    // 2. Check direct actual fields, with route-aware fallback
    const actualSrc = data.actual_src || e.from;
    const actualDst = data.actual_dst || e.to;

    if (
        actualSrc === wantedSrc &&
        actualDst === wantedDst &&
        (e.type === wantedType || e.type === "mixed")
    ) {
        return true;
    }

    return false;
}

function selectConnectionFromEdge(src, dst, type) {
    selectedConnection = {
        actual_src: src,
        actual_dst: dst,
        type
    };
}

function collectServicesFromGraph() {
    const services = new Set();

    for (const n of graph.nodes || []) {
        for (const s of Object.keys(n.data?.services || {})) {
            services.add(s);
        }
    }

    for (const e of graph.edges || []) {
        for (const s of Object.keys(e.data?.services || {})) {
            services.add(s);
        }

        if (e.data?.service) {
            services.add(e.data.service);
        }
    }

    return Array.from(services).sort();
}

function updateServiceFilterOptions() {
    const sel = document.getElementById("filter-service");
    if (!sel) return;

    const current = sel.value;
    const services = collectServicesFromGraph();

    sel.innerHTML = `<option value="">All services</option>`;

    for (const service of services) {
        const opt = document.createElement("option");
        opt.value = service;
        opt.textContent = service;
        sel.appendChild(opt);
    }

    if (services.includes(current)) {
        sel.value = current;
    }
}

/*------------------------------------*/
/*              LISTENERS             */
/*------------------------------------*/

document.getElementById("filter-service")?.addEventListener("change", () => {
    // No backend call needed, this is frontend-only filtering
});

document.getElementById("show-logical-edges")?.addEventListener("change", () => {
    markVisualFilterDirty();
});

document.getElementById("show-gateway-to-external")?.addEventListener("change", () => {
    markVisualFilterDirty();
});

document.getElementById("show-external-to-gateway")?.addEventListener("change", () => {
    markVisualFilterDirty();
});

document.getElementById("show-edge-labels")?.addEventListener("change", () => {
    markVisualFilterDirty();
});

document.querySelectorAll("[data-protocol]").forEach(cb => {
    cb.addEventListener("change", () => {
        markVisualFilterDirty();
        selectedEdge = null;
        selectedEdgeKey = null;
    });
});

document.getElementById("edge-display-mode")?.addEventListener("change", () => {
    markVisualFilterDirty();
});

document.getElementById("toggle-ipv6").addEventListener("change", async (e) => {
    const show = e.target.checked;
    const savedPositions = {};

    await fetch("/filters/set", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            show_ipv6: show
        })
    });

    for (const id in nodeMap) {
        if (!isIPv6NodeId(id)) {
            savedPositions[id] = nodeMap[id];
        }
    }
    edgeCache = {};

    nodeMap = {
        "__external_anchor__": nodeMap["__external_anchor__"],
        "__local_anchor__": nodeMap["__local_anchor__"],
        "__multicast_anchor__": nodeMap["__multicast_anchor__"],
        ...savedPositions
    };

    selectedNode = null;
    selectedEdge = null;

    await fetchGraph(); // force immediate refresh
});