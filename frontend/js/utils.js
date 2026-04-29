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
