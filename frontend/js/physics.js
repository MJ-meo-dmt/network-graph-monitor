function stepPhysics() {
    if (Date.now() < physicsPausedUntil) return;

    const nodes = Object.values(nodeMap);

    // edge springs
    for (const e of getVisibleEdges()) {
        if (!edgeVisible(e)) continue;

        const a = nodeMap[e.from];
        const b = nodeMap[e.to];

        if (!a || !b) continue;

        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;

        const aGroup = a.group;
        const bGroup = b.group;
        const touchesExternal = aGroup === "external_host" || bGroup === "external_host";

        const target =
            e.type === "scan" ? 420 :
            touchesExternal ? 380 :
            e.type === "dns" ? 300 :
            e.type === "arp" ? 220 :
            320;

        const springStrength = touchesExternal ? 0.00020 : 0.00055;
        const force = (dist - target) * springStrength * (e.weight || 1);

        const fx = dx / dist * force;
        const fy = dy / dist * force;

        if (!a.pinned && draggingNode !== a) {
            a.vx += fx;
            a.vy += fy;
        }

        if (!b.pinned && draggingNode !== b) {
            b.vx -= fx;
            b.vy -= fy;
        }
    }

    // repulsion
    for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
            const a = nodes[i];
            const b = nodes[j];

            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;

            const externalPair = a.group === "external_host" || b.group === "external_host";

            const minDist = getRadius(a) + getRadius(b) + (externalPair ? 140 : 75);
            const force = Math.min(4.0, (externalPair ? 3200 : 2200) / (dist * dist));

            const fx = dx / dist * force;
            const fy = dy / dist * force;

            if (!a.pinned && draggingNode !== a) {
                a.vx += fx;
                a.vy += fy;
            }

            if (!b.pinned && draggingNode !== b) {
                b.vx -= fx;
                b.vy -= fy;
            }

            if (dist < minDist) {
                const push = (minDist - dist) * 0.018;

                if (!a.pinned && draggingNode !== a) {
                    a.vx += dx / dist * push;
                    a.vy += dy / dist * push;
                }

                if (!b.pinned && draggingNode !== b) {
                    b.vx -= dx / dist * push;
                    b.vy -= dy / dist * push;
                }
            }
        }
    }

    // semantic zones
    for (const n of nodes) {
        if (n.pinned || draggingNode === n) continue;

        let tx = 0;
        let ty = 0;
        let strength = 0.00035;

        if (n.group === "switch") {
            const gateway = Object.values(nodeMap).find(x => x.group === "gateway");
            const localAnchor = nodeMap["__local_anchor__"];

            if (gateway && localAnchor) {
                // place switch between local anchor and gateway
                tx = (localAnchor.x * 0.45) + (gateway.x * 0.55);
                ty = (localAnchor.y * 0.45) + (gateway.y * 0.55);
                strength = 0.0045;
            } else {
                tx = -150;
                ty = 0;
                strength = 0.0022;
            }
        }

        if (n.group === "gateway") {
            tx = 0;
            ty = 0;
            strength = 0.0025;
        } else if (n.group === "local_device") {
            const localAnchor = nodeMap["__local_anchor__"];

            if (localAnchor) {
                const dx = n.x - localAnchor.x;
                const dy = n.y - localAnchor.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;

                // nice soft orbit like external nodes but tighter
                const importance = Number(n.data?.importance || 0);
                const orbit = 140 + (importance * 40) + (seededAngleFromId(n.id) % 60);
                
                const ringForce = (dist - orbit) * 0.0022;

                n.vx -= (dx / dist) * ringForce;
                n.vy -= (dy / dist) * ringForce;

                // slight rotation so LAN doesn't stack
                const tangentStrength = 0.012;
                n.vx += (-dy / dist) * tangentStrength;
                n.vy += (dx / dist) * tangentStrength;

                continue; // skip default tx/ty logic
            } else {
                // fallback if anchor missing
                tx = -420;
                ty = 0;
                strength = 0.00075;
            }
        } else if (n.group === "external_host") {
            const anchor = nodeMap["__external_anchor__"];

            if (anchor) {
                const dx = n.x - anchor.x;
                const dy = n.y - anchor.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;

                // Desired orbit distance around external anchor
                const orbit = 260 + ((seededAngleFromId(n.id) % 180));

                // Pull/push node toward orbit ring, not directly into anchor
                const ringForce = (dist - orbit) * 0.0022;

                n.vx -= (dx / dist) * ringForce;
                n.vy -= (dy / dist) * ringForce;

                // Small tangential force so the cloud feels orbital
                const tangentStrength = 0.009;
                n.vx += (-dy / dist) * tangentStrength;
                n.vy += (dx / dist) * tangentStrength;

                // Skip normal tx/ty pull
                continue;
            } else {
                tx = 720;
                ty = 0;
                strength = 0.0011;
            }
        } else if (n.group === "suspicious") {
            tx = 0;
            ty = -330;
            strength = 0.0012;
        } else if (n.group === "broadcast" || n.group === "multicast") {
            const multicastAnchor = nodeMap["__multicast_anchor__"];

            if (multicastAnchor) {
                const dx = n.x - multicastAnchor.x;
                const dy = n.y - multicastAnchor.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;

                const orbit = 120 + (seededAngleFromId(n.id) % 90);
                const ringForce = (dist - orbit) * 0.002;

                n.vx -= (dx / dist) * ringForce;
                n.vy -= (dy / dist) * ringForce;

                continue;
            } else {
                tx = 0;
                ty = 420;
                strength = 0.001;
            }
        }

        n.vx += (tx - n.x) * strength;
        n.vy += (ty - n.y) * strength;

        // importance gravity inward, risk pushes upward/outward
        const importance = Number(n.data?.importance || 0);
        const risk = Number(n.data?.risk || 0);

        n.vx += (0 - n.x) * importance * 0.000015;
        n.vy += (0 - n.y) * importance * 0.000015;

        if (risk > 0) {
            n.vy += (-420 - n.y) * risk * 0.000025;
        }
    }

    // integrate
    for (const n of nodes) {
        if (n.virtual || n.pinned || draggingNode === n) {
            n.vx = 0;
            n.vy = 0;
            continue;
        }

        n.x += n.vx;
        n.y += n.vy;

        n.vx *= 0.84;
        n.vy *= 0.84;

        n.pulse = Math.max(0, (n.pulse || 0) * 0.92);
    }
}