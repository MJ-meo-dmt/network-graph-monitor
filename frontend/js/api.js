// api.js

async function fetchGraph() {
    try {
        const res = await fetch("/graph");
        const newGraph = await res.json();

        // Prevent visual blink when backend briefly returns empty/stale graph
        if (
            graph.nodes.length > 0 &&
            (!newGraph.nodes || newGraph.nodes.length === 0)
        ) {
            console.warn("Ignoring empty graph refresh");
            return;
        }

        graph = newGraph;
        const ipv6Toggle = document.getElementById("toggle-ipv6");
        const topologyKey = `${newGraph.stats.gateway || ""}|${newGraph.stats.default_switch || ""}`;

        if (ipv6Toggle && newGraph.stats?.filters?.hasOwnProperty("show_ipv6")) {
            ipv6Toggle.checked = Boolean(newGraph.stats.filters.show_ipv6);
        }

        if (window.lastTopologyKey && window.lastTopologyKey !== topologyKey) {
            edgeCache = {};
        }

        window.lastTopologyKey = topologyKey;
        syncEdges(newGraph.edges || []);
        visibleEdgesDirty = true;
        syncNodes();

        document.getElementById("status").innerText =
            `Live | Nodes: ${graph.stats.total_nodes} | Edges: ${graph.stats.total_edges} | Gateway: ${graph.stats.gateway || "unknown"}`;

        updateStatsPanel();

    } catch (err) {
        console.error(err);
        document.getElementById("status").innerText = "Disconnected";
    }
}

async function fetchEvents() {
    try {
        const res = await fetch("/events");
        const data = await res.json();

        renderEvents(data.items || []);

    } catch (err) {
        console.error(err);
    }
}

async function setAccessPathForSelected(path) {
    if (!selectedNode) return;

    await fetch("/access-path/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            ip: selectedNode.id,
            path
        })
    });

    await fetchGraph();
}

async function setGateway() {
    const ip = document.getElementById("gateway-input").value.trim();

    await fetch("/gateway/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
    });

    await fetchGraph();
}

async function clearGateway() {
    document.getElementById("gateway-input").value = "";

    await fetch("/gateway/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: null })
    });

    await fetchGraph();
}

async function newSession() {
    const withKnownNodes =
        document.getElementById("start-with-known-nodes")?.checked ?? false;

    await postJson("/sessions/new", {
        with_known_nodes: withKnownNodes,
        start_capture: true
    });

    graph = { nodes: [], edges: [], stats: {} };
    nodeMap = {};
    edgeCache = {};

    selectedNode = null;
    selectedEdge = null;
    selectedEdgeKey = null;
    selectedConnection = null;

    await refreshSessions();
    await fetchGraph();
    await fetchEvents();
    await refreshCaptureStatus();
}
``

async function refreshSessions() {
    const res = await fetch("/sessions");
    const data = await res.json();

    const sel = document.getElementById("session-select");
    sel.innerHTML = "";

    for (const item of data.items || []) {
        const opt = document.createElement("option");
        opt.value = item.filename;
        opt.textContent = item.filename;

        if (item.filename === data.current) {
            opt.selected = true;
        }

        sel.appendChild(opt);
    }

    document.getElementById("session-status").innerText =
        `Session: ${data.current || "none"}`;
}

async function loadSelectedSession() {
    const filename = document.getElementById("session-select").value;
    if (!filename) return;

    await fetch("/sessions/load", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename })
    });

    graph = { nodes: [], edges: [], stats: {} };
    nodeMap = {};
    edgeCache = {};

    selectedNode = null;
    selectedEdge = null;
    selectedEdgeKey = null;
    selectedConnection = null;

    await refreshSessions();
    await fetchGraph();
    await fetchEvents();
    await refreshCaptureStatus();
}

async function startCapture() {
    flashButton("btn-start");
    await fetch("/capture/start", { method: "POST" });
    await refreshCaptureStatus();
}

async function pauseCapture() {
    flashButton("btn-pause");
    await fetch("/capture/pause", { method: "POST" });
    await refreshCaptureStatus();
}

async function stopCapture() {
    flashButton("btn-stop");
    await fetch("/capture/stop", { method: "POST" });
    await refreshCaptureStatus();
}

async function refreshCaptureStatus() {
    try {
        const res = await fetch("/capture/status");
        const data = await res.json();

        captureStats = data.stats || {};

        setCaptureStatusVisual(data.capture);
        updateStatsPanel();
    } catch {
        setCaptureStatusVisual("unknown");
    }
}

async function postJson(url, payload = {}) {
    const res = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    if (!res.ok) {
        throw new Error(`${url} failed with HTTP ${res.status}`);
    }

    return await res.json();
}

async function refreshNodeCache() {
    try {
        await postJson("/nodes/cache/refresh");
        console.log("Node cache refreshed");
    } catch (err) {
        console.error("Failed to refresh node cache", err);
        alert("Failed to refresh")
    }
}