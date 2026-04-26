function syncEdges(newEdges) {
    const incoming = new Set();

    for (const e of newEdges || []) {
        const key = edgeKey(e);
        incoming.add(key);

        edgeCache[key] = {
            ...e,
            missingCount: 0,
            lastSeen: Date.now(),
            stale: false
        };
    }

    for (const key of Object.keys(edgeCache)) {
        if (!incoming.has(key)) {
            edgeCache[key].missingCount = (edgeCache[key].missingCount || 0) + 1;
            edgeCache[key].stale = true;

            // Remove stale visual edges quickly so old wrong routes disappear.
            if (edgeCache[key].missingCount >= 2) {
                delete edgeCache[key];
            }
        }
    }

    graph.edges = Object.values(edgeCache);
    if (selectedEdgeKey && edgeCache[selectedEdgeKey]) {
        selectedEdge = edgeCache[selectedEdgeKey];
    } else if (selectedEdgeKey) {
        selectedEdge = null;
        selectedEdgeKey = null;
    }
}

function syncNodes() {
    const incoming = new Set();
    const savedAnchor = pinnedNodePositions["__external_anchor__"];
    const savedLocalAnchor = pinnedNodePositions["__local_anchor__"];
    const savedMulticastAnchor = pinnedNodePositions["__multicast_anchor__"];

    for (const node of graph.nodes) {
        incoming.add(node.id);

        if (!nodeMap[node.id]) {
            const seeded = seededPosition(node.id);

            nodeMap[node.id] = {
                id: node.id,
                x: seeded.x,
                y: seeded.y,
                vx: 0,
                vy: 0,
                pulse: 0,
                pinned: false
            };
        }

        const n = nodeMap[node.id];

        n.label = node.label;
        n.group = node.group;
        n.data = node.data || {};

        if (pinnedNodePositions[node.id]) {
            n.x = pinnedNodePositions[node.id].x;
            n.y = pinnedNodePositions[node.id].y;
            n.pinned = true;
        }
    }

    if (!nodeMap["__external_anchor__"]) {
        nodeMap["__external_anchor__"] = {
            id: "__external_anchor__",
            label: "External",
            x: savedAnchor?.x ?? 720,
            y: savedAnchor?.y ?? 0,
            vx: 0,
            vy: 0,
            pulse: 0,
            pinned: true,
            virtual: true,
            group: "external_anchor",
            data: {
                ip: "__external_anchor__",
                identity: {
                    label_line_1: "External",
                    label_line_2: "gravity anchor"
                }
            }
        };
    }

    if (!nodeMap["__local_anchor__"]) {
        nodeMap["__local_anchor__"] = {
            id: "__local_anchor__",
            label: "Local",
            x: savedLocalAnchor?.x ?? -520,
            y: savedLocalAnchor?.y ?? 0,
            vx: 0,
            vy: 0,
            pulse: 0,
            pinned: true,
            virtual: true,
            group: "local_anchor",
            data: {
                ip: "__local_anchor__",
                identity: {
                    label_line_1: "Local Network",
                    label_line_2: "LAN summary"
                },
                summary_node: true
            }
        };
    }

    if (!nodeMap["__multicast_anchor__"]) {
        nodeMap["__multicast_anchor__"] = {
            id: "__multicast_anchor__",
            label: "Multicast",
            x: savedMulticastAnchor?.x ?? 0,
            y: savedMulticastAnchor?.y ?? 520,
            vx: 0,
            vy: 0,
            pulse: 0,
            pinned: true,
            virtual: true,
            group: "multicast_anchor",
            data: {
                ip: "__multicast_anchor__",
                identity: {
                    label_line_1: "Multicast",
                    label_line_2: "multicast gravity anchor"
                }
            }
        };
    }

    for (const id of Object.keys(nodeMap)) {
        if (
            id === "__external_anchor__" ||
            id === "__local_anchor__" ||
            id === "__multicast_anchor__"
        ) continue;

        if (!incoming.has(id)) {
            nodeMap[id].missingCount = (nodeMap[id].missingCount || 0) + 1;
            nodeMap[id].stale = true;

            // remove nodes that backend no longer sends
            if (nodeMap[id].missingCount >= 2) {
                delete nodeMap[id];

                if (selectedNode?.id === id) selectedNode = null;
            }
        } else {
            nodeMap[id].missingCount = 0;
            nodeMap[id].stale = false;
        }
    }
}

function updateStatsPanel() {
    const existingInput = document.getElementById("gateway-input");
    const gatewayDraft = existingInput ? existingInput.value : "";
    const gatewayFocused = existingInput === document.activeElement;

    const suspicious = graph.nodes.filter(n => n.group === "suspicious").length;
    const external = graph.nodes.filter(n => n.group === "external_host").length;
    const local = graph.nodes.filter(n => n.group === "local_device").length;
    const gatewayLoad = graph.stats.gateway_load || {};
    const nat = graph.stats.nat || {};
    const tunnels = graph.stats.tunnels || [];

    document.getElementById("stats-content").innerHTML = `
        <div class="kv"><div class="k">Nodes</div><div>${graph.stats.total_nodes}</div></div>
        <div class="kv"><div class="k">Edges</div><div>${graph.stats.total_edges}</div></div>
        <div class="kv"><div class="k">Events</div><div>${graph.stats.total_events}</div></div>
        <hr>
        <input id="gateway-input" placeholder="Gateway IP e.g. 192.168.8.1">
        <button onclick="setGateway()">Set Gateway</button>
        <button onclick="clearGateway()">Auto Gateway</button>
        <div class="kv"><div class="k">Gateway</div><div>${graph.stats.gateway || "unknown"}</div></div>
        <div class="kv"><div class="k">GW packets</div><div>${gatewayLoad.packets || 0}</div></div>
        <div class="kv"><div class="k">GW bytes</div><div>${gatewayLoad.bytes || 0}</div></div>
        <div class="kv"><div class="k">GW ext edges</div><div>${gatewayLoad.external_edges || 0}</div></div>
        <div class="kv"><div class="k">NAT</div><div>${nat.likely_nat ? "likely" : "unknown"}</div></div>
        <div class="kv"><div class="k">NAT clients</div><div>${nat.local_clients || 0}</div></div>
        <div class="kv"><div class="k">Ext targets</div><div>${nat.external_targets || 0}</div></div>
        <div class="kv"><div class="k">VPN/proxy hints</div><div>${tunnels.length}</div></div>
        <hr>
        <div class="kv"><div class="k">Window</div><div>${graph.stats.recent_flow_window_seconds || "-"}s</div></div>
        <div class="kv"><div class="k">Local</div><div>${local}</div></div>
        <div class="kv"><div class="k">External</div><div>${external}</div></div>
        <div class="kv"><div class="k">Suspicious</div><div>${suspicious}</div></div>
    `;

    const newInput = document.getElementById("gateway-input");

    if (newInput) {
        newInput.value = gatewayFocused ? gatewayDraft : "";

        if (gatewayFocused) {
            newInput.focus();
            newInput.setSelectionRange(newInput.value.length, newInput.value.length);
        }

        newInput.addEventListener("keydown", e => {
            if (e.key === "Enter") {
                setGateway();
            }
        });
    }
}

function renderEvents(events) {
    const el = document.getElementById("events-content");
    document.getElementById("events-count").innerText = events.length;

    if (!events.length) {
        el.innerHTML = "Waiting for events...";
        return;
    }

    el.innerHTML = events.slice().reverse().map(e => {
        const time = e.timestamp
            ? new Date(e.timestamp * 1000).toLocaleTimeString()
            : "";

        const domain = e.domain ? ` | ${e.domain}` : "";
        const ports = e.dst_port ? `:${e.dst_port}` : "";

        return `
            <div class="event-line">
                <span class="muted">${time}</span>
                ${e.src_ip || "?"} → ${e.dst_ip || "?"}${ports}
                <span class="badge">${e.protocol || "unknown"}</span>
                ${domain}
            </div>
        `;
    }).join("");
}

function showNodeInfo(n) {
    const data = n.data || {};
    const flags = data.flags || [];

    if (n.id === "__local_anchor__") {
        const stats = graph.stats || {};
        const nat = stats.nat || {};
        const gw = stats.gateway || "unknown";
        const vlans = stats.vlans || [];
        const broadcasts = graph.nodes.filter(x => x.group === "broadcast").length;
        const multicasts = graph.nodes.filter(x => x.group === "multicast").length;
        const locals = graph.nodes.filter(x => x.group === "local_device").length;

        document.getElementById("info").innerHTML = `
            <b>Local Network</b><br>
            <span class="muted">LAN summary</span>
            <hr>
            <div class="kv"><div class="k">Gateway</div><div>${gw}</div></div>
            <div class="kv"><div class="k">Local devices</div><div>${locals}</div></div>
            <div class="kv"><div class="k">Broadcast nodes</div><div>${broadcasts}</div></div>
            <div class="kv"><div class="k">Multicast nodes</div><div>${multicasts}</div></div>
            <div class="kv"><div class="k">NAT</div><div>${nat.likely_nat ? "likely" : "unknown"}</div></div>
            <div class="kv"><div class="k">NAT clients</div><div>${nat.local_clients || 0}</div></div>
            <div class="kv"><div class="k">External targets</div><div>${nat.external_targets || 0}</div></div>
            <div class="kv"><div class="k">VLANs</div><div>${vlans.length ? vlans.join(", ") : "none seen"}</div></div>
        `;
        return;
    }

    document.getElementById("info").innerHTML = `
        <b>${n.label}</b><br>
        <span class="muted">${n.group}</span>
        ${n.pinned ? `<span class="badge">pinned</span>` : ""}
        <hr>
        <div class="kv"><div class="k">IP</div><div>${data.ip || n.id}</div></div>
        <div class="kv"><div class="k">Identity</div><div>${data.identity?.label_line_1 || "unknown"}</div></div>
        <div class="kv"><div class="k">Role</div><div>${data.identity?.role || "unknown"}</div></div>
        <div class="kv"><div class="k">OS</div><div>${data.identity?.os || "unknown"}</div></div>
        <div class="kv"><div class="k">Vendor</div><div>${data.identity?.vendor || "unknown"}</div></div>
        <div class="kv"><div class="k">Confidence</div><div>${((data.identity?.confidence || 0) * 100).toFixed(0)}%</div></div>
        <div class="kv"><div class="k">Hostname</div><div>${data.hostname || "unknown"}</div></div>
        <div class="kv"><div class="k">Domain</div><div>${data.domain || "unknown"}</div></div>
        <div class="kv"><div class="k">DNS answer</div><div>${data.dns_answer_name || "none"}</div></div>
        <div class="kv"><div class="k">Name</div><div>${data.display_name || n.label || n.id}</div></div>
        <div class="kv"><div class="k">MAC</div><div>${data.mac || "unknown"}</div></div>
        <div class="kv"><div class="k">Access path</div><div>${data.access_path || "unknown"}</div></div>
        ${["local_device", "gateway"].includes(n.group) ? `
            <div class="row">
                <button onclick="setAccessPathForSelected('switch')">Set Switch Path</button>
                <button onclick="setAccessPathForSelected('gateway')">Set Gateway Path</button>
            </div>
            <button onclick="setAccessPathForSelected(null)">Auto Access Path</button>
        ` : ""}
        <div class="kv"><div class="k">Packets</div><div>${data.packets || 0}</div></div>
        <div class="kv"><div class="k">Bytes</div><div>${data.bytes || 0}</div></div>
        <div class="kv"><div class="k">Importance</div><div>${(data.importance || 0).toFixed(2)}</div></div>
        <div class="kv"><div class="k">Risk</div><div>${(data.risk || 0).toFixed(2)}</div></div>
        ${(data.risk_findings || []).length ? `
        <hr>
        <div class="muted">Risk findings</div>
        <div>
            ${(data.risk_findings || []).map(f => `
                <div class="event-line">
                    <b>${f.kind}</b>
                    <span class="badge">${f.severity || "medium"}</span>
                    <span class="badge">${f.points || 0} pts</span><br>
                    ${f.reason || ""}
                    ${f.evidence ? `<br><span class="muted">${JSON.stringify(f.evidence)}</span>` : ""}
                </div>
            `).join("")}
        </div>
    ` : ""}
        <div class="kv"><div class="k">Targets</div><div>${data.target_count || 0}</div></div>
        <div class="kv"><div class="k">Scan ports</div><div>${data.scan_port_count || 0}</div></div>
        <div class="kv"><div class="k">External</div><div>${data.external_target_count || 0}</div></div>
        <div class="kv"><div class="k">DNS domains</div><div>${data.dns_domain_count || 0}</div></div>
        ${data.interfaces ? `
        <hr>
        <div class="muted">Switch interfaces / L2 MACs</div>
        <div>
            ${Object.values(data.interfaces).map(iface => `
                <div class="event-line">
                    <b>${iface.mac}</b><br>
                    Packets: ${iface.packets || 0} | Bytes: ${iface.bytes || 0}<br>
                    ${Object.entries(iface.protocols || {})
                        .map(([k, v]) => `<span class="badge">${k}: ${v}</span>`)
                        .join("")}
                </div>
            `).join("")}
        </div>
    ` : ""}
        <hr>
        <div class="muted">DNS names seen</div>
        <div>
            ${(data.dns_names || []).map(h => `<span class="badge">${h}</span>`).join("") || `<span class="muted">No DNS names seen</span>`}
        </div>
        
        <hr>

        <div>
            ${(data.ports || []).map(p => `<span class="badge">${p}</span>`).join("") || `<span class="muted">No ports tracked</span>`}
        </div>

        <hr>

        <div>
            ${Object.entries(data.protocols || {})
                .map(([k, v]) => `<span class="badge">${k}: ${v}</span>`)
                .join("")}
        </div>

        ${flags.length ? `
            <hr>
            <div>
                ${flags.map(f => `<span class="badge danger">${f}</span>`).join("")}
            </div>
        ` : ""}
    `;
}

function showEdgeInfo(e) {
    const data = e.data || {};
    const connections = data.connections || [];
    const cleanEdgeDomains = cleanDomains(data.domains);
    const cleanDnsQueries = cleanDomains(data.dns_queries);

    const connectionHtml = connections.slice(0, 40).map((c, index) => {
    const cleanConnectionDomains = cleanDomains(c.domains);
    const src = c.actual_src || "?";
    const dst = c.actual_dst || "?";
    const type = c.type || "unknown";

        return `
            <div class="event-line connection-line"
                onclick="selectConnectionFromEdge('${src}', '${dst}', '${type}')">
                <b>${src} → ${dst}</b>
                <span class="badge">${type}</span><br>
                Packets: ${c.packets || 0} | Bytes: ${c.bytes || 0}
                ${(c.ports || []).length ? `<br>Ports: ${(c.ports || []).join(", ")}` : ""}
                ${cleanConnectionDomains.length ? `<br>Domains: ${cleanConnectionDomains.slice(0, 3).join(", ")}` : ""}
            </div>
        `;
    }).join("");

    document.getElementById("info").innerHTML = `
        <b>${e.from} → ${e.to}</b><br>
        <span class="badge">${e.type}</span>
        ${data.visual_route ? `<span class="badge">${data.visual_route}</span>` : ""}
        <hr>

        <div class="kv"><div class="k">Packets</div><div>${data.packets || 0}</div></div>
        <div class="kv"><div class="k">Bytes</div><div>${data.bytes || 0}</div></div>
        <div class="kv"><div class="k">Weight</div><div>${(e.weight || 0).toFixed(2)}</div></div>
        ${data.actual_src ? `<div class="kv"><div class="k">Actual src</div><div>${data.actual_src}</div></div>` : ""}
        ${data.actual_dst ? `<div class="kv"><div class="k">Actual dst</div><div>${data.actual_dst}</div></div>` : ""}

        ${connections.length ? `
            <hr>
            <div class="muted">Connections on this visual segment</div>
            <div>
                ${connectionHtml}
                ${connections.length > 40 ? `<div class="muted">Showing 40 of ${connections.length}</div>` : ""}
            </div>
        ` : ""}

        <hr>

        <div class="muted">Protocols</div>
        <div>
            ${Object.entries(data.protocols || {})
                .map(([k, v]) => `<span class="badge">${k}: ${v}</span>`)
                .join("") || "none"}
        </div>

        <hr>

        <div class="muted">Ports</div>
        <div>
            ${(data.ports || []).map(p => `<span class="badge">${p}</span>`).join("") || "none"}
        </div>

        <hr>

        <div class="muted">Domains</div>
        <div>
            ${cleanEdgeDomains.length ? cleanEdgeDomains.join("<br>") : "none"}
        </div>
        ${cleanDnsQueries.length ? `
        <hr>
        <div class="muted">DNS queries seen on this edge</div>
        <div>${cleanDnsQueries.join("<br>")}</div>
    ` : ""}
    `;
}