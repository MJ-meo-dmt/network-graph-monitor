# config.py

import os
import sys

APP_PORT = 8000

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(BACKEND_DIR)

SESSIONS_DIR = os.path.join(BACKEND_DIR, "sessions")
CURRENT_SESSION_PATH = os.path.join(SESSIONS_DIR, "current_session.txt")

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
OUI_CSV_PATH = os.path.join(BASE_DIR, "data", "oui", "oui.csv")

APP_INTEL_DIR = os.path.join(BASE_DIR, "data", "app_intel")
APP_INTEL_CACHE_PATH = os.path.join(APP_INTEL_DIR, "app_intel_cache.json")
APP_FINGERPRINT_OVERRIDES_PATH = os.path.join(APP_INTEL_DIR, "app_fingerprint_overrides.json")


def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)

    return os.path.join(BASE_DIR, relative_path)


def frontend_path():
    return resource_path("frontend")


def oui_csv_path():
    return resource_path("data/oui/oui.csv")

def app_intel_cache_path():
    return resource_path("data/app_intel/app_intel_cache.json")


def app_fingerprint_overrides_path():
    return resource_path("data/app_intel/app_fingerprint_overrides.json")