# session_manager.py

import json
import os
from datetime import datetime
from config import SESSIONS_DIR, CURRENT_SESSION_PATH
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

    return new_session()["path"]


def set_current_session(filename):
    ensure_sessions_dir()

    path = os.path.join(SESSIONS_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(filename)

    with open(CURRENT_SESSION_PATH, "w", encoding="utf-8") as f:
        f.write(filename)

    return path


def new_session():
    ensure_sessions_dir()

    filename = make_session_name()
    path = os.path.join(SESSIONS_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(empty_state(), f, indent=2)

    with open(CURRENT_SESSION_PATH, "w", encoding="utf-8") as f:
        f.write(filename)

    return {
        "filename": filename,
        "path": path
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