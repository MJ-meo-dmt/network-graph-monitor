# capture.py

from scapy.all import sniff
from analyzer import analyze_packet
from graph_builder import update_state

capture_enabled = False


def set_capture_enabled(value: bool):
    global capture_enabled
    capture_enabled = bool(value)


def get_capture_enabled():
    return capture_enabled


def handle_packet(packet):
    if not capture_enabled:
        return

    try:
        event = analyze_packet(packet)

        if event:
            update_state(event)

    except Exception as e:
        print("Packet handling error:", e)


def start_capture(interface=None):
    print("Packet capture loop started")

    try:
        sniff(
            iface=interface,
            prn=handle_packet,
            store=False
        )
    except PermissionError:
        print("Capture permission error. Run as Administrator/root.")
    except Exception as e:
        print("Capture failed:", e)