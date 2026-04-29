# capture.py

from scapy.all import AsyncSniffer
from analyzer import analyze_packet
from graph_builder import update_state

capture_enabled = False
sniffer = None
capture_interface = None

capture_stats = {
    "raw_packets": 0,
    "analyzed_events": 0,
    "stored_events": 0,
    "errors": 0,
    "protocols": {}
}

def set_capture_enabled(value: bool):
    global capture_enabled
    capture_enabled = bool(value)


def get_capture_enabled():
    return capture_enabled


def get_capture_running():
    global sniffer

    try:
        return sniffer is not None and bool(getattr(sniffer, "running", False))
    except Exception:
        return False


def handle_packet(packet):
    capture_stats["raw_packets"] += 1

    if not capture_enabled:
        return

    try:
        event = analyze_packet(packet)

        if event:
            capture_stats["analyzed_events"] += 1
            update_state(event)
            capture_stats["stored_events"] += 1
            proto = event.get("protocol", "unknown")
            capture_stats["protocols"][proto] = capture_stats["protocols"].get(proto, 0) + 1

    except Exception as e:
        capture_stats["errors"] += 1
        print("Packet handling error:", e)


def start_capture(interface=None):
    global sniffer, capture_interface

    if get_capture_running():
        set_capture_enabled(True)
        return True

    capture_interface = interface

    try:
        sniffer = AsyncSniffer(
            iface=interface,
            prn=handle_packet,
            store=False
        )

        sniffer.start()
        set_capture_enabled(True)

        print("Packet capture started")
        return True

    except PermissionError:
        print("Capture permission error. Run as Administrator/root.")
        set_capture_enabled(False)
        sniffer = None
        return False

    except Exception as e:
        print("Capture failed:", e)
        set_capture_enabled(False)
        sniffer = None
        return False


def pause_capture():
    set_capture_enabled(False)
    return True


def stop_capture():
    global sniffer

    set_capture_enabled(False)

    current = sniffer
    sniffer = None

    if current is not None:
        try:
            if getattr(current, "running", False):
                current.stop(join=False)
        except Exception as e:
            print("Capture stop error:", e)

    print("Packet capture stopped")
    return True