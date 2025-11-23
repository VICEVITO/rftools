# host/interface.py
# DearPyGui host for ESP32 CTF Tool
# Requirements: dearpygui, pyserial, python-dateutil

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
logs_list = []  # store strings for export and search

# ---------- Helpers ----------
def now_iso():
    return datetime.now(tz=tz.tzlocal()).isoformat()

def find_candidate_ports():
    ports = serial.tools.list_ports.comports()
    candidates = []
    for p in ports:
        desc = (p.description or "").upper()
        hwid = (p.hwid or "").upper()
        if any(x in desc for x in ("USB","UART","CP210","FTDI","CH340")) or any(x in hwid for x in ("USB","CP210","FTDI","CH340")):
            candidates.append(p.device)
    return candidates

def append_log(s):
    global logs_list
    t = now_iso()
    line = f"[{t}] {s}"
    logs_list.append(line)
    if len(logs_list) > LOG_MAX_LINES:
        logs_list.pop(0)
    # update UI (show last 1000 lines)
    dpg.set_value("log_text", "\n".join(logs_list[-1000:]))
    try:
        dpg.set_y_scroll("logbox", 999999)
    except Exception:
        pass

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
                except:
                    text = str(chunk)
                buffer += text
                while "\n" in buffer:
                    line, buffer = buffer.split("\n",1)
                    line = line.strip()
                    if not line:
                        continue
                    # try parse JSON
                    try:
                        obj = json.loads(line)
                        t = obj.get("type")
                        if t == "wifi_result":
                            append_log(f"[RX WIFI] count={obj.get('count')}")
                            for i, e in enumerate(obj.get("data", [])):
                                append_log(f"  WIFI[{i}] ssid={e.get('ssid')} rssi={e.get('rssi')} bssid={e.get('bssid')} ch={e.get('channel')}")
                        elif t == "ble_result":
                            append_log(f"[RX BLE] count={obj.get('count')}")
                            for i, e in enumerate(obj.get("data", [])):
                                append_log(f"  BLE[{i}] addr={e.get('addr')} rssi={e.get('rssi')} name={e.get('name')}")
                        elif t == "wifi_connect":
                            append_log(f"[RX WIFI_CONNECT] ok={obj.get('ok')} ifconfig={obj.get('ifconfig')}")
                        elif t == "tcp_recv":
                            append_log(f"[RX TCP_RECV] {obj.get('data')}")
                        elif t == "logs":
                            append_log(f"[RX LOGS] count={len(obj.get('data',[]))}")
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
    if ser and ser.is_open:
        reader_running = False
        time.sleep(0.2)
        try:
            ser.close()
        except:
            pass
        ser = None
        dpg.set_value("connect_btn","Connect")
        append_log("[UI] Disconnected")
        return
    try:
        ser = serial.Serial(port, BAUD, timeout=READ_TIMEOUT)
        append_log(f"[UI] Connected to {port} @ {BAUD}")
        dpg.set_value("connect_btn","Disconnect")
        reader_running = True
        reader_thread = threading.Thread(target=serial_reader_loop, daemon=True)
        reader_thread.start()
    except Exception as e:
        append_log(f"[UI] Connect error: {e}")
        ser = None

def cb_set_mode(sender, app_data, user_data):
    mode = dpg.get_value("mode_combo")
    if mode:
        send_cmd_json({"cmd":"SET_MODE","mode":mode})
        append_log(f"[UI] Set mode -> {mode}")

def cb_scan_once(sender, app_data, user_data):
    # legacy compatibility: triggers SCAN_ONCE which uses current mode on device
    send_cmd_json({"cmd":"SCAN_ONCE"})

# WiFi
def cb_wifi_connect(sender, app_data, user_data):
    ssid=dpg.get_value("wifi_ssid")
    pwd=dpg.get_value("wifi_pwd")
    send_cmd_json({"cmd":"WIFI_CONNECT","ssid":ssid,"pwd":pwd})

def cb_wifi_disconnect(sender, app_data, user_data):
    send_cmd_json({"cmd":"WIFI_DISCONNECT"})

def cb_wifi_status(sender, app_data, user_data):
    send_cmd_json({"cmd":"WIFI_STATUS"})

# BLE
def cb_ble_scan(sender, app_data, user_data):
    duration=dpg.get_value("ble_duration")
    send_cmd_json({"cmd":"SCAN_ONCE"})


def cb_tcp_connect(sender, app_data, user_data):
    host = dpg.get_value("tcp_host")
    port = dpg.get_value("tcp_port")
    if not host or not port:
        append_log("[UI] TCP host/port required")
        return
    send_cmd_json({"cmd":"TCP_CONNECT","host":host,"port":int(port)})

def cb_tcp_send(sender, app_data, user_data):
    data = dpg.get_value("tcp_send_data")
    send_cmd_json({"cmd":"TCP_SEND","data":data})

def cb_tcp_recv(sender, app_data, user_data):
    send_cmd_json({"cmd":"TCP_RECV"})

def cb_tcp_close(sender, app_data, user_data):
    send_cmd_json({"cmd":"TCP_CLOSE"})

def cb_udp_send(sender, app_data, user_data):
    host = dpg.get_value("udp_host")
    port = dpg.get_value("udp_port")
    data = dpg.get_value("udp_send_data")
    if not host or not port:
        append_log("[UI] UDP host/port required")
        return
    send_cmd_json({"cmd":"UDP_SEND","host":host,"port":int(port),"data":data})

def cb_ble_scan(sender, app_data, user_data):
    dur = int(dpg.get_value("ble_duration"))
    send_cmd_json({"cmd":"BLE_SCAN","duration_ms":dur})

def cb_get_logs(sender, app_data, user_data):
    send_cmd_json({"cmd":"GET_LOGS"})

def cb_clear_logs(sender, app_data, user_data):
    send_cmd_json({"cmd":"CLEAR_LOGS"})
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
            append_log("  " + f)
    else:
        append_log("[FLAG] No flag found")

# ---------- Build UI ----------
def build_ui():
    with dpg.window(label="ESP32 CTF Tool", width=1000, height=750):
        dpg.add_text("ESP32 Controller (MicroPython) — DearPyGui")
        dpg.add_separator()

        # --- Serial Port ---
        dpg.add_text("Serial Port:")
        with dpg.group(horizontal=True):
            dpg.add_combo(tag="port_combo", items=find_candidate_ports(), width=300)
            dpg.add_button(label="Refresh", callback=cb_refresh_ports)
            dpg.add_button(label="Connect", tag="connect_btn", callback=cb_connect)

        dpg.add_separator()
        # --- Device Mode ---
        dpg.add_text("Mode (device-side):")
        with dpg.group(horizontal=True):
            dpg.add_combo(tag="mode_combo", items=["IDLE","WIFI","BLE"], default_value="IDLE", width=150)
            dpg.add_button(label="Set Mode", callback=cb_set_mode)
            dpg.add_button(label="Scan (mode)", callback=cb_scan_once)

        dpg.add_separator()
        # --- WiFi Controls ---
        dpg.add_text("WiFi Controls:")
        with dpg.group(horizontal=True):
            dpg.add_input_text(tag="wifi_ssid", label="SSID", width=300)
            dpg.add_input_text(tag="wifi_pwd", label="Password", width=300, password=True)
            dpg.add_button(label="Connect WiFi", callback=cb_wifi_connect)
            dpg.add_button(label="WiFi Status", callback=cb_wifi_status)
            dpg.add_button(label="Disconnect WiFi", callback=cb_wifi_disconnect)

        dpg.add_separator()
        # --- TCP Client ---
        dpg.add_text("TCP Client:")
        with dpg.group(horizontal=True):
            dpg.add_input_text(tag="tcp_host", label="Host", width=200)
            dpg.add_input_int(tag="tcp_port", label="Port", default_value=4444, width=120)
            dpg.add_button(label="Connect TCP", callback=cb_tcp_connect)
        with dpg.group(horizontal=True):
            dpg.add_input_text(tag="tcp_send_data", label="Send Data", width=400)
            dpg.add_button(label="TCP Send", callback=cb_tcp_send)
            dpg.add_button(label="TCP Recv", callback=cb_tcp_recv)
            dpg.add_button(label="TCP Close", callback=cb_tcp_close)

        dpg.add_separator()
        # --- UDP ---
        dpg.add_text("UDP:")
        with dpg.group(horizontal=True):
            dpg.add_input_text(tag="udp_host", label="UDP Host", width=200)
            dpg.add_input_int(tag="udp_port", label="UDP Port", default_value=9999, width=120)
            dpg.add_input_text(tag="udp_send_data", label="UDP Send", width=300)
            dpg.add_button(label="UDP Send", callback=cb_udp_send)

        dpg.add_separator()
        # --- BLE Scan ---
        dpg.add_text("BLE Scan:")
        with dpg.group(horizontal=True):
            dpg.add_input_int(tag="ble_duration", label="Duration ms", default_value=5000, width=150)
            dpg.add_button(label="BLE Scan", callback=cb_ble_scan)

        dpg.add_separator()
        # --- Quick Tools ---
        dpg.add_text("Quick Tools:")
        with dpg.group(horizontal=True):
            dpg.add_button(label="Search Flags (auto regex)", callback=cb_search_flags)
            dpg.add_input_text(tag="export_path", default_value="esp_logs.json", width=300)
            dpg.add_button(label="Export Logs", callback=cb_export)

        dpg.add_separator()
        # --- Device logs ---
        dpg.add_text("Device logs (real-time):")
        with dpg.child_window(tag="logbox", width=960, height=350, horizontal_scrollbar=True):
            dpg.add_text("", tag="log_text")

# ---------- Main ----------
if __name__ == "__main__":
    dpg.create_context()
    dpg.create_viewport(title="ESP32 CTF Tool", width=1100, height=800)
    build_ui()
    dpg.setup_dearpygui()
    dpg.show_viewport()
    append_log("[APP] Starting UI")
    dpg.start_dearpygui()
    # when GUI exits:
    reader_running = False
    append_log("[APP] Exiting")
    dpg.destroy_context()
