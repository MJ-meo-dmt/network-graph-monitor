// utils.js

// Temp for lo
let loggedNodeCount = 0;
const loggedNodes = new Set();

function logOnce(node, msg) {
    // Only log once per unique node
    if (!loggedNodes.has(node.id)) {
        console.log(node.id, msg);
        loggedNodes.add(node.id);
        loggedNodeCount++;
    }  
}

function pointInRect(px, py, rect) {
    if (!rect) return false;

    return (
        px >= rect.x &&
        px <= rect.x + rect.w &&
        py >= rect.y &&
        py <= rect.y + rect.h
    );
}

function getCanvasMousePos(evt) {
    const rect = canvas.getBoundingClientRect();

    return {
        x: evt.clientX - rect.left,
        y: evt.clientY - rect.top
    };
}

function getNodeAtScreenPoint(screenX, screenY) {
    // 1. Check label rectangles first
    // Iterate backwards so visually later-drawn labels win if overlapping
    const nodeList = Object.values(nodeMap);

    for (let i = nodeList.length - 1; i >= 0; i--) {
        const n = nodeList[i];

        if (!nodeVisible(n)) continue;

        if (pointInRect(screenX, screenY, n._labelBounds)) {
            return n;
        }
    }

    // 2. Check node circles
    // Node circles are in world-space, so convert click to world-space
    const worldX = (screenX - camera.x) / camera.zoom;
    const worldY = (screenY - camera.y) / camera.zoom;

    for (let i = nodeList.length - 1; i >= 0; i--) {
        const n = nodeList[i];

        if (!nodeVisible(n)) continue;

        const radius = getRadius(n);
        const dx = worldX - n.x;
        const dy = worldY - n.y;

        if (Math.sqrt(dx * dx + dy * dy) <= radius + 4) {
            return n;
        }
    }

    return null;
}

function lerp(a, b, t) {
    return a + (b - a) * t;
}

function colorLerp(c1, c2, t, alpha = 1) {
    const r = Math.round(lerp(c1[0], c2[0], t));
    const g = Math.round(lerp(c1[1], c2[1], t));
    const b = Math.round(lerp(c1[2], c2[2], t));

    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function short(s, max = 48) {
    return s && s.length > max ? s.slice(0, max) + "…" : s;
}

function isNoiseDomain(d) {
    if (!d) return true;

    d = String(d).toLowerCase();

    return (
        d.endsWith(".in-addr.arpa") ||
        d.endsWith(".ip6.arpa")
    );
}

function cleanDomains(domains) {
    return (domains || [])
        .filter(d => !isNoiseDomain(d))
        .slice(0, 8);
}

function flashButton(id) {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.classList.remove("flash");
    void btn.offsetWidth;
    btn.classList.add("flash");
}

function setCaptureStatusVisual(status) {
    const el = document.getElementById("capture-status");
    if (!el) return;

    el.classList.remove("running", "paused", "stopped", "unknown");
    el.classList.add(status || "unknown");

    const icon =
        status === "running" ? "●" :
        status === "paused" ? "Ⅱ" :
        status === "stopped" ? "■" :
        "?";

    el.innerText = `${icon} ${status || "unknown"}`;
}

function seededAngleFromId(id) {
    let h = 0;

    for (let i = 0; i < String(id).length; i++) {
        h = ((h << 5) - h) + String(id).charCodeAt(i);
        h |= 0;
    }

    return Math.abs(h) % 360;
}

function seededPosition(id) {
    let h = 0;

    for (let i = 0; i < id.length; i++) {
        h = ((h << 5) - h) + id.charCodeAt(i);
        h |= 0;
    }

    const angle = (Math.abs(h) % 360) * Math.PI / 180;
    const radius = 120 + (Math.abs(h) % 320);

    return {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius
    };
}
