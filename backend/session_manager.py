# session_manager.py

import json
import os
from datetime import datetime
from config import SESSIONS_DIR, CURRENT_SESSION_PATH, START_SESSION_WITH_KNOWN_NODES_DEFAULT
from node_cache import preload_known_nodes_into_state
from state_schema import empty_state

def ensure_sessions_dir():
    os.makedirs(SESSIONS_DIR, exist_ok=True)


def make_session_name():
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"session_state_{stamp}.json"


def get_current_state_path():
    ensure_sessions_dir()

    if os.path.exists(CURRENT_SESSION_PATH):
        with open(CURRENT_SESSION_PATH, "r", encoding="utf-8") as f:
            name = f.read().strip()

        if name:
            return os.path.join(SESSIONS_DIR, name)

    return new_session(with_known_nodes=False)["path"]


def set_current_session(filename):
    ensure_sessions_dir()

    path = os.path.join(SESSIONS_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(filename)

    with open(CURRENT_SESSION_PATH, "w", encoding="utf-8") as f:
        f.write(filename)

    return path


def new_session(with_known_nodes=None):
    ensure_sessions_dir()

    if with_known_nodes is None:
        with_known_nodes = START_SESSION_WITH_KNOWN_NODES_DEFAULT

    filename = make_session_name()
    path = os.path.join(SESSIONS_DIR, filename)

    state = empty_state()

    if with_known_nodes:
        preload_known_nodes_into_state(state)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    with open(CURRENT_SESSION_PATH, "w", encoding="utf-8") as f:
        f.write(filename)

    return {
        "filename": filename,
        "path": path,
        "with_known_nodes": bool(with_known_nodes),
        "known_nodes_loaded": len(state.get("devices", {})) if with_known_nodes else 0
    }


def list_sessions():
    ensure_sessions_dir()

    items = []

    for name in sorted(os.listdir(SESSIONS_DIR), reverse=True):
        if not name.endswith(".json"):
            continue

        path = os.path.join(SESSIONS_DIR, name)
        stat = os.stat(path)

        items.append({
            "filename": name,
            "size": stat.st_size,
            "modified": stat.st_mtime
        })

    current = None

    if os.path.exists(CURRENT_SESSION_PATH):
        with open(CURRENT_SESSION_PATH, "r", encoding="utf-8") as f:
            current = f.read().strip()

    return {
        "current": current,
        "items": items
    }