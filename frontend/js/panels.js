function captureCurrentLayout() {
    const layout = {};

    document.querySelectorAll(".panel").forEach(p => {
        layout[p.id] = {
            left: p.style.left,
            top: p.style.top,
            right: p.style.right,
            width: p.style.width,
            height: p.style.height
        };
    });

    return layout;
}

function exportLayout() {
    const payload = {
        version: 1,
        exported_at: new Date().toISOString(),
        layout: captureCurrentLayout(),
        camera,
        pinnedNodePositions
    };

    const text = JSON.stringify(payload, null, 2);

    navigator.clipboard.writeText(text)
        .then(() => alert("Layout copied to clipboard"))
        .catch(() => {
            prompt("Copy layout JSON:", text);
        });
}

function importLayout() {
    const text = prompt("Paste layout JSON:");
    if (!text) return;

    let payload;

    try {
        payload = JSON.parse(text);
    } catch {
        alert("Invalid layout JSON");
        return;
    }

    const layout = payload.layout || payload;

    Object.entries(layout).forEach(([id, pos]) => {
        const el = document.getElementById(id);
        if (!el) return;

        if (pos.left) el.style.left = pos.left;
        if (pos.top) el.style.top = pos.top;
        if (pos.right) el.style.right = pos.right;
        if (pos.width) el.style.width = pos.width;
        if (pos.height) el.style.height = pos.height;

        localStorage.setItem(`nm:${id}:pos`, JSON.stringify({
            left: el.style.left,
            top: el.style.top
        }));

        localStorage.setItem(`nm:${id}:size`, JSON.stringify({
            width: el.style.width,
            height: el.style.height
        }));
    });

    if (payload.camera) {
        camera = payload.camera;
        localStorage.setItem("nm:camera", JSON.stringify(camera));
        updateHud();
    }

    if (payload.pinnedNodePositions) {
        pinnedNodePositions = payload.pinnedNodePositions;
        localStorage.setItem("nm:pinnedNodePositions", JSON.stringify(pinnedNodePositions));
    }

    alert("Layout imported");
}

function saveCurrentLayoutAsDefault() {
    const panels = document.querySelectorAll(".panel");
    const layout = {};

    panels.forEach(p => {
        layout[p.id] = {
            left: p.style.left,
            top: p.style.top,
            width: p.style.width,
            height: p.style.height
        };
    });

    localStorage.setItem("nm:layout:default", JSON.stringify(layout));
    alert("Layout saved as default");
}

function saveLayoutSoon() {
    localStorage.setItem("nm:camera", JSON.stringify(camera));
    localStorage.setItem("nm:pinnedNodePositions", JSON.stringify(pinnedNodePositions));
}

function togglePanelCollapse(event, panelId) {
    event.stopPropagation();

    const panel = document.getElementById(panelId);
    if (!panel) return;

    const btn = panel.querySelector(".panel-collapse");
    const collapsed = panel.classList.toggle("collapsed");

    if (btn) {
        btn.innerText = collapsed ? "+" : "−";
    }

    localStorage.setItem(`nm:${panelId}:collapsed`, collapsed ? "1" : "0");
}

function setupPanels() {
    document.querySelectorAll(".panel").forEach(panel => {
        const id = panel.id;

        const savedPos = JSON.parse(localStorage.getItem(`nm:${id}:pos`) || "null");
        const savedSize = JSON.parse(localStorage.getItem(`nm:${id}:size`) || "null");

        if (savedPos) {
            panel.style.left = savedPos.left;
            panel.style.top = savedPos.top;
            panel.style.right = "auto";
        }

        if (savedSize) {
            panel.style.width = savedSize.width;
            panel.style.height = savedSize.height;
        }

        const savedCollapsed = localStorage.getItem(`nm:${id}:collapsed`) === "1";

        if (savedCollapsed) {
            panel.classList.add("collapsed");

            const btn = panel.querySelector(".panel-collapse");
            if (btn) btn.innerText = "+";
        }

        const header = panel.querySelector(".panel-header");
        const handle = panel.querySelector(".resize-handle");

        let moving = false;
        let resizing = false;
        let ox = 0;
        let oy = 0;

        header.addEventListener("mousedown", e => {
            if (e.button !== 0) return;

            moving = true;
            const rect = panel.getBoundingClientRect();

            ox = e.clientX - rect.left;
            oy = e.clientY - rect.top;

            panel.style.zIndex = Date.now();
        });

        handle.addEventListener("mousedown", e => {
            e.stopPropagation();
            resizing = true;
            panel.style.zIndex = Date.now();
        });

        window.addEventListener("mousemove", e => {
            if (moving) {
                panel.style.left = `${e.clientX - ox}px`;
                panel.style.top = `${e.clientY - oy}px`;
                panel.style.right = "auto";
            }

            if (resizing) {
                const rect = panel.getBoundingClientRect();

                const w = Math.max(180, e.clientX - rect.left);
                const h = Math.max(130, e.clientY - rect.top);

                panel.style.width = `${w}px`;
                panel.style.height = `${h}px`;
            }
        });

        window.addEventListener("mouseup", () => {
            if (moving) {
                moving = false;

                localStorage.setItem(`nm:${id}:pos`, JSON.stringify({
                    left: panel.style.left,
                    top: panel.style.top
                }));
            }

            if (resizing) {
                resizing = false;

                localStorage.setItem(`nm:${id}:size`, JSON.stringify({
                    width: panel.style.width,
                    height: panel.style.height
                }));
            }
        });
    });
}

function applyDefaultLayout() {
    const raw = localStorage.getItem("nm:layout:default");
    if (!raw) return;

    const layout = JSON.parse(raw);

    Object.entries(layout).forEach(([id, pos]) => {
        const el = document.getElementById(id);
        if (!el) return;

        // Only apply if no saved user override exists
        const existing = localStorage.getItem(`nm:${id}:pos`);
        if (existing) return;

        el.style.left = pos.left;
        el.style.top = pos.top;
        el.style.width = pos.width;
        el.style.height = pos.height;
    });
}
