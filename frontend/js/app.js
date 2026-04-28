// app.js

/* -----------------------------
   Init
------------------------------ */

function initApp() {
    resizeCanvas();
    setupPanels();
    applyDefaultLayout();
    updateHud();

    refreshSessions();
    refreshCaptureStatus();
    fetchGraph();
    fetchEvents();

    draw();

    setTimeout(() => setInterval(fetchGraph, 3000), 500);
    setTimeout(() => setInterval(fetchEvents, 5000), 1000);
    setTimeout(() => setInterval(refreshCaptureStatus, 10000), 1500);
    setTimeout(() => setInterval(refreshSessions, 30000), 2000);

    setInterval(stepPhysics, 33);
}

initApp();