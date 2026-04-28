// canvas.js

function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

function updateHud() {
    document.getElementById("graph-view-state").innerText =
        `zoom ${camera.zoom.toFixed(2)} | pan ${Math.round(camera.x)}, ${Math.round(camera.y)}`;
}

function screenToWorld(x, y) {
    return {
        x: (x - camera.x) / camera.zoom,
        y: (y - camera.y) / camera.zoom
    };
}

function worldToScreen(x, y) {
    return {
        x: x * camera.zoom + camera.x,
        y: y * camera.zoom + camera.y
    };
}

function pickNodeAtWorld(x, y) {
    let best = null;
    let bestDist = Infinity;

    for (const id in nodeMap) {
        const n = nodeMap[id];
        const dx = n.x - x;
        const dy = n.y - y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const radius = getRadius(n) + 6;

        if (dist < radius && dist < bestDist) {
            best = n;
            bestDist = dist;
        }
    }

    return best;
}

function pointToQuadraticDistance(px, py, a, b) {
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;

    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;

    const nx = -dy / len;
    const ny = dx / len;

    const curve = Math.min(60, len * 0.12);

    const cx = mx + nx * curve;
    const cy = my + ny * curve;

    let best = Infinity;
    let prev = { x: a.x, y: a.y };

    for (let i = 1; i <= 24; i++) {
        const t = i / 24;

        const qx =
            (1 - t) * (1 - t) * a.x +
            2 * (1 - t) * t * cx +
            t * t * b.x;

        const qy =
            (1 - t) * (1 - t) * a.y +
            2 * (1 - t) * t * cy +
            t * t * b.y;

        best = Math.min(
            best,
            pointToSegmentDistance(px, py, prev.x, prev.y, qx, qy)
        );

        prev = { x: qx, y: qy };
    }

    return best;
}

function findNearestEdge(x, y) {
    let best = null;
    let bestDist = 34 / camera.zoom;

    for (const e of getVisibleEdges()) {
        if (!edgeVisible(e)) continue;

        const a = nodeMap[e.from];
        const b = nodeMap[e.to];

        if (!a || !b) continue;

        const d = pointToQuadraticDistance(x, y, a, b);

        if (d < bestDist) {
            bestDist = d;
            best = e;
        }
    }

    return best;
}

function pointToSegmentDistance(px, py, x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;

    if (dx === 0 && dy === 0) {
        return Math.hypot(px - x1, py - y1);
    }

    let t = ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy);
    t = Math.max(0, Math.min(1, t));

    const x = x1 + t * dx;
    const y = y1 + t * dy;

    return Math.hypot(px - x, py - y);
}

function pinNode(node, persist = true) {
    if (!node) return;

    node.pinned = true;
    node.vx = 0;
    node.vy = 0;

    pinnedNodePositions[node.id] = {
        x: node.x,
        y: node.y
    };

    if (persist) saveLayoutSoon();
}

function unpinNode(node) {
    if (!node) return;

    node.pinned = false;
    delete pinnedNodePositions[node.id];

    saveLayoutSoon();
}

function togglePinSelected() {
    if (!selectedNode) return;

    if (selectedNode.pinned) {
        unpinNode(selectedNode);
    } else {
        pinNode(selectedNode);
    }

    showNodeInfo(selectedNode);
    syncPinButton();
}

function syncPinButton() {
    const btn = document.getElementById("pin-button");

    if (!selectedNode) {
        btn.innerText = "Pin Selected";
        return;
    }

    btn.innerText = selectedNode.pinned ? "Unpin Selected" : "Pin Selected";
}

function clearSelection() {
    selectedNode = null;
    selectedEdge = null;
    selectedEdgeKey = null;
    selectedConnection = null;
    document.getElementById("info").innerHTML = "Click a node or edge.";
    syncPinButton();
}

function centerOnSelected() {
    if (!selectedNode) return;

    camera.x = canvas.width / 2 - selectedNode.x * camera.zoom;
    camera.y = canvas.height / 2 - selectedNode.y * camera.zoom;

    updateHud();
    saveLayoutSoon();
}

function resetView() {
    camera = { x: canvas.width / 2, y: canvas.height / 2, zoom: 1 };
    updateHud();
    saveLayoutSoon();
}

function fitGraph() {
    const nodes = Object.values(nodeMap);

    if (!nodes.length) return;

    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;

    for (const n of nodes) {
        minX = Math.min(minX, n.x);
        maxX = Math.max(maxX, n.x);
        minY = Math.min(minY, n.y);
        maxY = Math.max(maxY, n.y);
    }

    const width = maxX - minX || 1;
    const height = maxY - minY || 1;

    const scaleX = canvas.width / (width + 260);
    const scaleY = canvas.height / (height + 260);

    camera.zoom = Math.min(scaleX, scaleY, 2.5);
    camera.x = canvas.width / 2 - (minX + width / 2) * camera.zoom;
    camera.y = canvas.height / 2 - (minY + height / 2) * camera.zoom;

    updateHud();
    saveLayoutSoon();
}

function edgeKey(e) {
    const route = e.data?.visual_route || "raw";

    if (["local_to_switch", "switch_to_gateway", "gateway_to_switch", "switch_to_local"].includes(route)) {
        return `${e.from}|${e.to}|${route}`;
    }

    return `${e.from}|${e.to}|${e.type || "unknown"}|${route}|${e.data?.actual_src || ""}|${e.data?.actual_dst || ""}`;
}


/*---------------------------------*/
/*         EVENT LISTENERS         */
/*---------------------------------*/
window.addEventListener("resize", resizeCanvas);

canvas.addEventListener("wheel", e => {
    e.preventDefault();

    const factor = e.deltaY < 0 ? 1.1 : 0.9;

    const before = screenToWorld(e.clientX, e.clientY);

    camera.zoom = Math.max(0.15, Math.min(5, camera.zoom * factor));

    const after = screenToWorld(e.clientX, e.clientY);

    camera.x += (after.x - before.x) * camera.zoom;
    camera.y += (after.y - before.y) * camera.zoom;

    updateHud();
    saveLayoutSoon();
}, { passive: false });

canvas.addEventListener("mousedown", e => {
    pointerMoved = false;

    const p = screenToWorld(e.clientX, e.clientY);
    const hit = pickNodeAtWorld(p.x, p.y);

    if (e.button === 2) {
        isPanning = true;
        panStart.x = e.clientX - camera.x;
        panStart.y = e.clientY - camera.y;
        return;
    }

    if (hit) {
        draggingNode = hit;
        selectedNode = hit;
        selectedEdge = null;
        selectedEdgeKey = null;

        dragOffset.x = p.x - hit.x;
        dragOffset.y = p.y - hit.y;

        showNodeInfo(hit);
        syncPinButton();

        return;
    }

    isPanning = true;
    panStart.x = e.clientX - camera.x;
    panStart.y = e.clientY - camera.y;
});

canvas.addEventListener("mousemove", e => {
    const p = screenToWorld(e.clientX, e.clientY);
    hoverNode = pickNodeAtWorld(p.x, p.y);
    const hoverEdge = !hoverNode ? findNearestEdge(p.x, p.y) : null;
    canvas.style.cursor = hoverNode || hoverEdge ? "pointer" : (isPanning ? "grabbing" : "grab");

    if (hoverNode) {
        hoverNode.pulse = Math.max(hoverNode.pulse || 0, 0.8);
    }

    if (draggingNode) {
        pointerMoved = true;

        draggingNode.x = p.x - dragOffset.x;
        draggingNode.y = p.y - dragOffset.y;
        draggingNode.vx = 0;
        draggingNode.vy = 0;

        pinNode(draggingNode, false);
        syncPinButton();
        saveLayoutSoon();

        return;
    }

    if (isPanning) {
        pointerMoved = true;

        camera.x = e.clientX - panStart.x;
        camera.y = e.clientY - panStart.y;

        updateHud();
        saveLayoutSoon();
    }
});

canvas.addEventListener("mouseup", () => {
    draggingNode = null;
    isPanning = false;
});

canvas.addEventListener("click", e => {
    if (pointerMoved) return;

    const p = screenToWorld(e.clientX, e.clientY);

    selectedNode = null;
    selectedEdge = null;
    selectedEdgeKey = null;
    selectedConnection = null;

    const node = pickNodeAtWorld(p.x, p.y);

    if (node) {
        selectedNode = node;
        node.pulse = 1.5;
        showNodeInfo(node);
        syncPinButton();
        return;
    }

    const edge = findNearestEdge(p.x, p.y);

    if (edge) {
        selectedEdge = edge;
        selectedEdgeKey = edgeKey(edge);
        showEdgeInfo(edge);
        syncPinButton();
    } else {
        clearSelection();
    }
});

canvas.addEventListener("dblclick", e => {
    const p = screenToWorld(e.clientX, e.clientY);
    const node = pickNodeAtWorld(p.x, p.y);

    if (!node) return;

    if (node.pinned) {
        unpinNode(node);
    } else {
        pinNode(node);
    }

    selectedNode = node;
    showNodeInfo(node);
    syncPinButton();
});

canvas.addEventListener("contextmenu", e => e.preventDefault());