import json
import os, sys
import threading
import http.server
import socketserver
from urllib.parse import urlparse
from capture import start_capture, set_capture_enabled, get_capture_enabled
from graph_builder import build_graph, load_state
from session_manager import new_session, list_sessions, set_current_session

PORT = 8000

def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)

    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), relative_path)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = resource_path("frontend")

class ThreadingHTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def log_message(self, format, *args):
        # Silence normal GET/POST spam from the frontend polling
        return

    def json_response(self, payload, status=200):
        raw = json.dumps(payload, default=str).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/graph":
            state = load_state()
            graph = build_graph(state)
            self.json_response(graph)
            return

        if parsed.path == "/state":
            state = load_state()
            self.json_response(state)
            return

        if parsed.path == "/events":
            state = load_state()
            events = state.get("events", [])[-100:]
            self.json_response({
                "items": events,
                "count": len(events)
            })
            return
        
        if parsed.path == "/capture/status":
            self.json_response({
                "capture": "running" if get_capture_enabled() else "paused"
            })
            return
        
        if parsed.path == "/sessions":
            self.json_response(list_sessions())
            return

        if parsed.path == "/":
            self.path = "/index.html"

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/capture/start":
            set_capture_enabled(True)
            self.json_response({"capture": "running"})
            return

        if parsed.path == "/capture/pause":
            set_capture_enabled(False)
            self.json_response({"capture": "paused"})
            return

        if parsed.path == "/capture/status":
            self.json_response({
                "capture": "running" if get_capture_enabled() else "paused"
            })
            return

        if parsed.path == "/capture/stop":
            set_capture_enabled(False)
            self.json_response({"capture": "stopped"})
            return

        if parsed.path == "/sessions/new":
            set_capture_enabled(False)
            session = new_session()
            self.json_response({
                "ok": True,
                "session": session["filename"],
                "capture": "paused"
            })
            return

        if parsed.path == "/gateway/set":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body or "{}")

            ip = payload.get("ip")

            state = load_state()
            state["gateway_override"] = ip or None
            state["gateway"] = ip or None

            from graph_builder import save_state
            save_state(state)

            self.json_response({"ok": True, "gateway": ip})
            return

        if parsed.path == "/sessions/load":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body or "{}")

            filename = payload.get("filename")
            if not filename:
                self.json_response({"error": "filename required"}, status=400)
                return

            set_capture_enabled(False)
            set_current_session(filename)

            self.json_response({
                "ok": True,
                "session": filename,
                "capture": "paused"
            })
            return
        
        if parsed.path == "/filters/set":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body or "{}")

            state = load_state()

            filters = state.setdefault("filters", {})
            filters["show_ipv6"] = bool(payload.get("show_ipv6"))

            from graph_builder import save_state
            save_state(state)

            self.json_response({"ok": True, "filters": filters})
            return

        self.json_response({"error": "not found"}, status=404)


def run_server():
    with ThreadingHTTPServer(("", PORT), Handler) as httpd:
        print(f"Network Map running on http://localhost:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()

    print("Frontend dir:", FRONTEND_DIR)
    print("Index exists:", os.path.exists(os.path.join(FRONTEND_DIR, "index.html")))
    run_server()