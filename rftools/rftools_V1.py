# host/interface.py
# -----------------
# Requirements:
#   pip install dearpygui pyserial python-dateutil
#
# Usage:
#   python host/interface.py

import serial
import serial.tools.list_ports
import threading
import json
import time
import re
from datetime import datetime
from dateutil import tz
import dearpygui.dearpygui as dpg

# ---------- Config ----------
BAUD = 115200
READ_TIMEOUT = 0.1
LOG_MAX_LINES = 20000

# ---------- State ----------
ser = None
reader_thread = None
reader_running = False
logs_list = []   # store strings for export/search


# ---------- Helpers ----------
def now_iso():
    return datetime.now(tz=tz.tzlocal()).isoformat()


def find_candidate_ports():
    ports = serial.tools.list_ports.comports()
    candidates = []

    for p in ports:
        desc = (p.description or "").upper()
        hwid = (p.hwid or "").upper()

        if any(x in desc for x in ("USB", "UART", "CP210", "FTDI", "CH340")) \
           or any(x in hwid for x in ("USB", "CP210", "FTDI", "CH340")):
            candidates.append(p.device)

    return candidates


def append_log(s):
    global logs_list

    t = now_iso()
    line = f"[{t}] {s}"
    logs_list.append(line)

    if len(logs_list) > LOG_MAX_LINES:
        logs_list.pop(0)

    dpg.set_value("log_text", "\n".join(logs_list[-1000:]))
    dpg.set_y_scroll("logbox", 999999)


def send_cmd_json(obj):
    global ser

    if not ser or not ser.is_open:
        append_log("[TX-ERR] Not connected")
        return False

    s = json.dumps(obj) + "\n"

    try:
        ser.write(s.encode("utf-8"))
        append_log(f"[TX] {s.strip()}")
        return True

    except Exception as e:
        append_log(f"[TX-ERR] {e}")
        return False


# ---------- Serial reader thread ----------
def serial_reader_loop():
    global ser, reader_running
    buffer = ""

    while reader_running:
        try:
            if ser and ser.in_waiting:
                chunk = ser.read(1024)
                if not chunk:
                    time.sleep(0.01)
                    continue

                try:
                    text = chunk.decode("utf-8", errors="ignore")
                except Exception:
                    text = str(chunk)

                buffer += text

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    # Try JSON parsing
                    try:
                        obj = json.loads(line)

                        if obj.get("type") == "wifi_result":
                            append_log(f"[RX WIFI] count={obj.get('count')}")
                            for i, e in enumerate(obj.get("data", [])):
                                append_log(
                                    f" WIFI[{i}] "
                                    f"ssid={e.get('ssid')} "
                                    f"rssi={e.get('rssi')} "
                                    f"bssid={e.get('bssid')} "
                                    f"ch={e.get('channel')}"
                                )

                        elif obj.get("type") == "ble_result":
                            append_log(f"[RX BLE] count={obj.get('count')}")
                            for i, e in enumerate(obj.get("data", [])):
                                append_log(
                                    f" BLE[{i}] "
                                    f"addr={e.get('addr')} "
                                    f"rssi={e.get('rssi')} "
                                    f"name={e.get('name')}"
                                )

                        elif obj.get("type") == "logs":
                            append_log(f"[RX LOGS] count={len(obj.get('data', []))}")
                            for x in obj.get("data", []):
                                append_log(str(x))

                        else:
                            append_log(f"[RX] {json.dumps(obj)}")

                    except Exception:
                        append_log(f"[RAW] {line}")

            else:
                time.sleep(0.02)

        except Exception as e:
            append_log(f"[ReaderErr] {e}")
            time.sleep(0.1)


# ---------- UI callbacks ----------
def cb_refresh_ports(sender, app_data, user_data):
    ports = find_candidate_ports()
    dpg.configure_item("port_combo", items=ports)
    append_log(f"[UI] Found ports: {ports}")


def cb_connect(sender, app_data, user_data):
    global ser, reader_thread, reader_running

    port = dpg.get_value("port_combo")
    if not port:
        append_log("[UI] No port selected")
        return

    # Disconnect if already connected
    if ser and ser.is_open:
        reader_running = False
        time.sleep(0.2)

        try:
            ser.close()
        except:
            pass

        ser = None
        dpg.set_value("connect_btn", "Connect")
        append_log("[UI] Disconnected")
        return

    # Connect
    try:
        ser = serial.Serial(port, BAUD, timeout=READ_TIMEOUT)
        append_log(f"[UI] Connected to {port} @ {BAUD}")
        dpg.set_value("connect_btn", "Disconnect")

        reader_running = True
        reader_thread = threading.Thread(target=serial_reader_loop, daemon=True)
        reader_thread.start()

    except Exception as e:
        append_log(f"[UI] Connect error: {e}")
        ser = None


def cb_set_mode(sender, app_data, user_data):
    mode = dpg.get_value("mode_combo")
    if mode:
        send_cmd_json({"cmd": "SET_MODE", "mode": mode})
        append_log(f"[UI] Set mode -> {mode}")


def cb_scan_once(sender, app_data, user_data):
    send_cmd_json({"cmd": "SCAN_ONCE"})


def cb_get_logs(sender, app_data, user_data):
    send_cmd_json({"cmd": "GET_LOGS"})


def cb_clear_logs(sender, app_data, user_data):
    send_cmd_json({"cmd": "CLEAR_LOGS"})
    append_log("[UI] Requested clear logs on device")


def cb_export(sender, app_data, user_data):
    path = dpg.get_value("export_path")
    if not path:
        append_log("[UI] No export path set")
        return

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(logs_list, f, ensure_ascii=False, indent=2)
        append_log(f"[UI] Exported logs to {path}")

    except Exception as e:
        append_log(f"[UI] Export error: {e}")


# ---------- Flag search ----------
FLAG_PATTERNS = [
    r"FLAG\{[^\}]+\}",
    r"CTF\{[^\}]+\}",
    r"[A-Za-z0-9]{32}",
]


def cb_search_flags(sender, app_data, user_data):
    content = "\n".join(logs_list)
    found = set()

    for p in FLAG_PATTERNS:
        for m in re.findall(p, content):
            found.add(m)

    if found:
        append_log("[FLAG] Found flags:")
        for f in found:
            append_log(" " + f)
    else:
        append_log("[FLAG] No flag found")


# ---------- Build UI ----------
def build_ui():
    with dpg.window(label="ESP32 CTF Tool", width=1000, height=700):

        dpg.add_text("ESP32 Controller (MicroPython) — DearPyGui interface")
        dpg.add_separator()

        # Serial controls
        dpg.add_text("Serial Port:")
        dpg.add_combo(tag="port_combo", items=find_candidate_ports(), width=300)
        dpg.add_button(label="Refresh Ports", callback=cb_refresh_ports)
        dpg.add_button(label="Connect", tag="connect_btn", callback=cb_connect)

        dpg.add_separator()

        # Mode / Actions
        dpg.add_text("Mode / Action_
