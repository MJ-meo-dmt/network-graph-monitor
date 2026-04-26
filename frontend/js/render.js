function nodeColor(group) {
    return group === "external_anchor" ? "#cfcecc" :
           group === "local_anchor" ? "#60a5fa" :
           group === "multicast_anchor" ? "#c084fc" :
           group === "gateway" ? "#fbbf24" :
           group === "local_device" ? "#60a5fa" :
           group === "external_host" ? "#94a3b8" :
           group === "broadcast" ? "#a78bfa" :
           group === "multicast" ? "#c084fc" :
           group === "loopback" ? "#2dd4bf" :
           group === "suspicious" ? "#f87171" :
           group === "switch" ? "#38bdf8" :
           "#e5e7eb";
}

function edgeColor(type) {
    return type === "arp" ? "rgba(251,191,36,0.65)" :
           type === "mixed" ? "rgba(226,232,240,0.55)" :
           type === "dns" ? "rgba(52,211,153,0.75)" :
           type === "quic" ? "rgba(45,212,191,0.70)" :
           type === "tcp" ? "rgba(96,165,250,0.58)" :
           type === "udp" ? "rgba(167,139,250,0.58)" :
           type === "icmp" ? "rgba(248,113,113,0.58)" :
           type === "http" ? "rgba(249,115,22,0.78)" :
           type === "tls" ? "rgba(34,197,94,0.60)" :
           type === "scan" ? "rgba(244,63,94,0.86)" :
           "rgba(148,163,184,0.35)";
}

function draw() {
    ctx.setTransform(1, 0, 0, 1, 0, 0);

    ctx.fillStyle = "#05070d";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    drawBackgroundStars();

    if (!graph.nodes.length) {
        ctx.fillStyle = "#e5e7eb";
        ctx.font = "18px monospace";
        ctx.fillText("Waiting for packets...", 40, 80);
    }

    ctx.setTransform(camera.zoom, 0, 0, camera.zoom, camera.x, camera.y);

    drawEdges();
    drawNodes();

    requestAnimationFrame(draw);
}

function drawBackgroundStars() {
    for (let i = 0; i < 70; i++) {
        const x = (i * 137) % Math.max(canvas.width, 1);
        const y = (i * 89) % Math.max(canvas.height, 1);

        ctx.beginPath();
        ctx.fillStyle = i % 5 === 0 ? "rgba(147,197,253,0.12)" : "rgba(255,255,255,0.06)";
        ctx.arc(x, y, (i % 3) + 0.6, 0, Math.PI * 2);
        ctx.fill();
    }
}

function drawArrowHead(x, y, angle, size, color) {
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(angle);

    ctx.beginPath();
    ctx.fillStyle = color;
    ctx.moveTo(0, 0);
    ctx.lineTo(-size, -size * 0.55);
    ctx.lineTo(-size, size * 0.55);
    ctx.closePath();
    ctx.fill();

    ctx.restore();
}

function drawEdges() {
    for (const e of getVisibleEdges()) {
        if (!edgeVisible(e)) continue;

        const a = nodeMap[e.from];
        const b = nodeMap[e.to];

        if (!a || !b) continue;

        if (!nodeVisible(a) || !nodeVisible(b)) continue;

        if (selectedNode && e.from !== selectedNode.id && e.to !== selectedNode.id) {
            continue;
        }

        ctx.beginPath();

        const visualRoute = e.data?.visual_route || null;
        const isLogicalDirect = visualRoute === "logical_direct";

        ctx.strokeStyle = edgeColor(e.type);

        if (visualRoute === "gateway_to_external" || visualRoute === "external_to_gateway") {
            ctx.strokeStyle = "rgba(96,165,250,0.72)";
        }

        if (isLogicalDirect) {
            ctx.setLineDash([]);
            ctx.globalAlpha = 0.28;
            ctx.strokeStyle = edgeColor(e.type);
        } else if (visualRoute) {
            ctx.setLineDash([7, 6]);
            ctx.globalAlpha = 0.72;
        } else {
            ctx.setLineDash([]);
            ctx.globalAlpha = 1;
        }

        const packets = Number(e.data?.packets || 0);
        const bytes = Number(e.data?.bytes || 0);
        const presentation = edgePresentation(e);
        ctx.globalAlpha *= presentation.alpha;

        // traffic volume thickness
        let width = 1;

        // Only start thickening after meaningful volume
        if (packets > 100 || bytes > 250000) {
            const packetWidth = Math.log10(packets / 100) * 1.2;
            const byteWidth = Math.log10(bytes / 250000) * 1.4;

            width += Math.max(0, packetWidth) + Math.max(0, byteWidth);
        }

        // Cap heavy flows
        width = Math.max(1, Math.min(width, 9));
        width += presentation.widthBoost;
        ctx.lineWidth = width;

        if (selectedEdgeKey && edgeKey(e) === selectedEdgeKey) {
            ctx.lineWidth = width + 3;
            ctx.globalAlpha = 1;
        }

        const isSelectedConnectionPath = edgeContainsSelectedConnection(e);

        if (isSelectedConnectionPath) {
            ctx.lineWidth = width + 4;
            ctx.globalAlpha = 1;
            ctx.shadowColor = "#60a5fa";
            ctx.shadowBlur = 18;
        }

        if (width >= 5 || presentation.glow) {
            ctx.shadowColor = edgeColor(e.type);
            ctx.shadowBlur = width * 1.5;
        }

        if (isLogicalDirect) {
            width = Math.min(width, 3.5);
        }

        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;

        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;

        const nx = -dy / len;
        const ny = dx / len;

        const curve = Math.min(60, len * 0.12);

        ctx.moveTo(a.x, a.y);
        ctx.quadraticCurveTo(mx + nx * curve, my + ny * curve, b.x, b.y);
        ctx.stroke();

        const arrowT = 0.72;
        const cx = mx + nx * curve;
        const cy = my + ny * curve;

        const qx =
            (1 - arrowT) * (1 - arrowT) * a.x +
            2 * (1 - arrowT) * arrowT * cx +
            arrowT * arrowT * b.x;

        const qy =
            (1 - arrowT) * (1 - arrowT) * a.y +
            2 * (1 - arrowT) * arrowT * cy +
            arrowT * arrowT * b.y;

        const tx =
            2 * (1 - arrowT) * (cx - a.x) +
            2 * arrowT * (b.x - cx);

        const ty =
            2 * (1 - arrowT) * (cy - a.y) +
            2 * arrowT * (b.y - cy);

        drawArrowHead(qx, qy, Math.atan2(ty, tx), Math.max(7, width + 5), ctx.strokeStyle);
        ctx.shadowBlur = 0;
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;

        const labelDomains = cleanDomains(e.data?.domains || []);

        if (showEdgeLabelsEnabled()) {
            const canShowDomainLabel =
                labelDomains.length &&
                ![
                    "local_to_switch",
                    "switch_to_gateway",
                    "gateway_to_switch",
                    "switch_to_local",
                    "dns_to_switch",
                    "dns_to_gateway"
                ].includes(e.data?.visual_route);

            if (canShowDomainLabel) {
                ctx.save();
                ctx.font = "10px monospace";
                ctx.fillStyle = "#cbd5e1";
                ctx.fillText(labelDomains[0], mx + nx * curve + 6, my + ny * curve - 6);
                ctx.restore();
            }
        }
    }
}

function drawNodes() {
    for (const id in nodeMap) {
        const n = nodeMap[id];
        if (!nodeVisible(n)) continue;

        const radius = getRadius(n);
        const color = nodeColor(n.group);

        ctx.shadowColor = color;
        ctx.shadowBlur = selectedNode === n ? 24 : 10 + (n.pulse || 0) * 10;

        ctx.beginPath();
        ctx.fillStyle = color;
        ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.shadowBlur = 0;

        if (n.pinned) {
            ctx.beginPath();
            ctx.fillStyle = "#ffffff";
            ctx.arc(n.x + radius - 2, n.y - radius + 2, 3.5, 0, Math.PI * 2);
            ctx.fill();
        }

        if (selectedNode === n) {
            ctx.beginPath();
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 2;
            ctx.arc(n.x, n.y, radius + 5, 0, Math.PI * 2);
            ctx.stroke();
        }

        if (n.group === "suspicious") {
            ctx.beginPath();
            ctx.strokeStyle = "#f43f5e";
            ctx.lineWidth = 2;
            ctx.arc(n.x, n.y, radius + 10 + Math.sin(Date.now() / 140) * 2, 0, Math.PI * 2);
            ctx.stroke();
        }

        const identity = n.data?.identity || {};

        const line1 =
            identity.label_line_1 ||
            n.data?.display_name ||
            n.label ||
            n.id;

        const line2 =
            identity.label_line_2 ||
            n.data?.ip ||
            n.id;

        // Line 1 (main identity)
        ctx.font = "11px monospace";
        ctx.fillStyle = "#e5e7eb";
        ctx.fillText(short(line1), n.x + radius + 7, n.y + 4);
        
        // Line 2 (IP)
        ctx.font = "10px monospace";
        ctx.fillStyle = "#94a3b8";
        ctx.fillText(short(line2), n.x + radius + 7, n.y + 16);
    }
}

function getEdgeDisplayMode() {
    return document.getElementById("edge-display-mode")?.value || "normal";
}

function edgeVolumeScore(e) {
    const packets = Number(e.data?.packets || 0);
    const bytes = Number(e.data?.bytes || 0);
    return packets + (bytes / 1500);
}

function topTalkerThreshold() {
    const scores = getVisibleEdges()
        .map(edgeVolumeScore)
        .filter(v => v > 0)
        .sort((a, b) => b - a);

    if (!scores.length) return Infinity;

    return scores[Math.min(9, scores.length - 1)];
}

function edgePresentation(e) {
    const mode = getEdgeDisplayMode();
    const visualRoute = e.data?.visual_route || "";
    const packets = Number(e.data?.packets || 0);
    const bytes = Number(e.data?.bytes || 0);

    let alpha = 1.5;
    let widthBoost = 0;
    let glow = false;

    if (mode === "quiet") {
        const volumeAlpha = Math.min(1, Math.max(0.12, Math.log10(packets + 1) / 4));
        alpha *= volumeAlpha;
    }

    if (mode === "top") {
        const threshold = topTalkerThreshold();
        const isTop = edgeVolumeScore(e) >= threshold;

        if (isTop) {
            alpha = 1;
            widthBoost = 1.3;
            glow = true;
        } else {
            alpha *= 0.18;
        }
    }

    if (mode === "backbone") {
        const isBackbone = [
            "local_to_switch",
            "switch_to_gateway",
            "gateway_to_switch",
            "switch_to_local",
        ].includes(visualRoute);

        if (isBackbone) {
            alpha = 1;
            widthBoost = 0.8;
            glow = true;
        } else {
            alpha *= 0.16;
        }
    }

    return { alpha, widthBoost, glow };
}

function getRadius(n) {
    const importance = Number(n.data?.importance || 0);
    const risk = Number(n.data?.risk || 0);

    if (n.group === "local_anchor") return 22;
    if (n.group === "external_anchor") return 22;
    if (n.group === "multicast_anchor") return 22;
    if (n.group === "gateway") return 18 + importance * 1.1;
    if (n.group === "suspicious") return 12 + importance * 1.1 + risk * 1.4;
    if (n.group === "switch") return 20 + importance * 0.7;

    return 8 + importance * 1.15 + risk * 0.8;
}