# server.py

import json
import os
import threading
import http.server
import socketserver
from urllib.parse import urlparse
from config import APP_PORT, frontend_path
from capture import (
    start_capture,
    pause_capture,
    stop_capture,
    get_capture_enabled,
    get_capture_running,
    capture_stats
)

from graph_builder import build_graph, load_state
from session_manager import new_session, list_sessions, set_current_session
from node_cache import refresh_node_cache_from_state, load_node_cache

FRONTEND_DIR = frontend_path()

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

        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return {}

            body = self.rfile.read(length).decode("utf-8")
            return json.loads(body or "{}")
        except Exception:
            return {}

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
                "capture": "running" if get_capture_enabled() else "paused",
                "sniffer": "running" if get_capture_running() else "stopped",
                "stats": capture_stats
            })
            return
        
        if parsed.path == "/sessions":
            self.json_response(list_sessions())
            return

        if parsed.path == "/nodes/cache":
            cache = load_node_cache()

            self.json_response({
                "ok": True,
                "enabled": True,
                "count": len(cache.get("nodes_by_ip", {})),
                "updated_at": cache.get("updated_at"),
                "cache": cache
            })
            return

        if parsed.path == "/":
            self.path = "/index.html"

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/capture/start":
            ok = start_capture()
            self.json_response({
                "ok": ok,
                "capture": "running" if ok else "error",
                "sniffer": "running" if get_capture_running() else "stopped"
            })
            return

        if parsed.path == "/capture/pause":
            pause_capture()
            self.json_response({
                "capture": "paused",
                "sniffer": "running" if get_capture_running() else "stopped"
            })
            return

        if parsed.path == "/capture/status":
            self.json_response({
                "capture": "running" if get_capture_enabled() else "paused",
                "sniffer": "running" if get_capture_running() else "stopped",
                "stats": capture_stats
            })
            return

        if parsed.path == "/capture/stop":
            stop_capture()
            self.json_response({
                "capture": "stopped",
                "sniffer": "stopped"
            })
            return

        if parsed.path == "/sessions/new":
            payload = self.read_json_body()

            with_known_nodes = bool(payload.get("with_known_nodes", False))
            auto_start_capture = bool(payload.get("start_capture", True))

            stop_capture()

            session = new_session(with_known_nodes=with_known_nodes)

            ok = False

            if auto_start_capture:
                ok = start_capture()

            self.json_response({
                "ok": True,
                "session": session["filename"],
                "with_known_nodes": session.get("with_known_nodes", False),
                "known_nodes_loaded": session.get("known_nodes_loaded", 0),
                "capture": "running" if ok else "paused",
                "sniffer": "running" if get_capture_running() else "stopped"
            })
            return

        if parsed.path == "/gateway/set":
            #length = int(self.headers.get("Content-Length", 0))
            #body = self.rfile.read(length).decode("utf-8")
            payload = self.read_json_body()

            ip = payload.get("ip")

            state = load_state()
            state["gateway_override"] = ip or None
            state["gateway"] = ip or None

            from graph_builder import save_state
            save_state(state)

            self.json_response({"ok": True, "gateway": ip})
            return

        if parsed.path == "/sessions/load":
            #length = int(self.headers.get("Content-Length", 0))
            #body = self.rfile.read(length).decode("utf-8")
            payload = self.read_json_body()

            filename = payload.get("filename")
            if not filename:
                self.json_response({"error": "filename required"}, status=400)
                return

            stop_capture()
            set_current_session(filename)

            self.json_response({
                "ok": True,
                "session": filename,
                "capture": "paused"
            })
            return
        
        if parsed.path == "/filters/set":
            #length = int(self.headers.get("Content-Length", 0))
            #body = self.rfile.read(length).decode("utf-8")
            payload = self.read_json_body()

            state = load_state()

            filters = state.setdefault("filters", {})
            filters["show_ipv6"] = bool(payload.get("show_ipv6"))

            from graph_builder import save_state
            save_state(state)

            self.json_response({"ok": True, "filters": filters})
            return
        
        if parsed.path == "/access-path/set":
            #length = int(self.headers.get("Content-Length", 0))
            #body = self.rfile.read(length).decode("utf-8")
            payload = self.read_json_body()

            ip = payload.get("ip")
            path_value = payload.get("path")

            if not ip:
                self.json_response({"error": "ip required"}, status=400)
                return

            if path_value not in {"switch", "gateway", None, ""}:
                self.json_response({"error": "path must be switch, gateway, or empty"}, status=400)
                return

            state = load_state()
            access_paths = state.setdefault("access_paths", {})

            if path_value:
                access_paths[ip] = path_value
            else:
                access_paths.pop(ip, None)

            from graph_builder import save_state
            save_state(state)

            self.json_response({"ok": True, "ip": ip, "path": path_value or None})
            return
        
        if parsed.path == "/nodes/cache/refresh":
            state = load_state()
            result = refresh_node_cache_from_state(state)

            self.json_response({
                "ok": True,
                "result": result
            })
            return

        self.json_response({"error": "not found"}, status=404)


def run_server():
    with ThreadingHTTPServer(("", APP_PORT), Handler) as httpd:
        print(f"Network Map running on http://localhost:{APP_PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    run_server()