# firmware/main.py
# ----------------
# MicroPython for ESP32
# Protocol: JSON per line on USB serial (REPL)
#
# Commands accepted (JSON):
# - {"cmd":"SET_MODE","mode":"WIFI"|"BLE"|"IDLE"}
# - {"cmd":"SCAN_ONCE"}
# - {"cmd":"GET_LOGS"}
# - {"cmd":"CLEAR_LOGS"}
#
# Device replies with newline-separated JSON objects, ex:
# {"type":"status","msg":"BOOT"}
# {"type":"wifi_result","data": [ ... ] }
#
# IMPORTANT: usage limited to lab/CTF. No active attacks (deauth) implemented.

import sys
import ujson as json
import time
import machine
from ubinascii import hexlify

# Try imports
try:
    import network
except Exception:
    network = None

try:
    from bluetooth import BLE
except Exception:
    BLE = None

# --------------------------------------------------------------------
# Logging circular buffer
# --------------------------------------------------------------------

LOG_CAPACITY = 1024
logs = [None] * LOG_CAPACITY
_log_head = 0
_log_count = 0


def add_log(obj):
    """Add a Python object (string or dict) to circular buffer with timestamp."""
    global _log_head, _log_count

    entry = {
        "ts": time.ticks_ms(),
        "entry": obj
    }

    logs[_log_head] = entry
    _log_head = (_log_head + 1) % LOG_CAPACITY

    if _log_count < LOG_CAPACITY:
        _log_count += 1


def clear_logs():
    global _log_head, _log_count
    _log_head = 0
    _log_count = 0


def get_logs_list():
    arr = []
    idx = (_log_head - _log_count) % LOG_CAPACITY
    for i in range(_log_count):
        arr.append(logs[(idx + i) % LOG_CAPACITY])
    return arr

# --------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------

MODE_IDLE = 0
MODE_WIFI = 1
MODE_BLE = 2

_current_mode = MODE_IDLE


def set_mode(mode_str):
    global _current_mode

    if mode_str == "WIFI":
        _current_mode = MODE_WIFI
        add_log({"event": "MODE", "mode": "WIFI"})

    elif mode_str == "BLE":
        _current_mode = MODE_BLE
        add_log({"event": "MODE", "mode": "BLE"})

    else:
        _current_mode = MODE_IDLE
        add_log({"event": "MODE", "mode": "IDLE"})

# --------------------------------------------------------------------
# WiFi scan
# --------------------------------------------------------------------


def wifi_scan_once():
    if not network:
        add_log({"error": "WIFI_NOT_SUPPORTED"})
        return None

    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    add_log({"event": "WIFI_SCAN_START"})

    try:
        res = wlan.scan()
    except Exception as e:
        add_log({"event": "WIFI_SCAN_ERROR", "error": str(e)})
        return None

    out = []
    for r in res:
        ssid = r[0].decode() if isinstance(r[0], (bytes, bytearray)) else str(r[0])
        bssid = hexlify(r[1]).decode() if isinstance(r[1], (bytes, bytearray)) else str(r[1])
        channel = int(r[2])
        rssi = int(r[3])
        auth = int(r[4])
        hidden = bool(r[5])

        out.append({
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "rssi": rssi,
            "auth": auth,
            "hidden": hidden
        })

    add_log({"event": "WIFI_SCAN_RESULT", "count": len(out)})
    return out

# --------------------------------------------------------------------
# BLE scan (ubluetooth)
# --------------------------------------------------------------------

_ble = None
_ble_results = []

_IRQ_SCAN_RESULT = 5
_IRQ_SCAN_DONE = 6


def _ble_irq(event, data):
    global _ble_results

    try:
        if event == _IRQ_SCAN_RESULT:
            addr_type, addr, adv_type, rssi, adv_data = data
            addr_str = ":".join("{:02X}".format(b) for b in addr)

            name = None
            try:
                i = 0
                b = adv_data
                while i + 1 < len(b):
                    length = b[i]
                    if length == 0:
                        break
                    type_ = b[i + 1]
                    if type_ in (0x08, 0x09):
                        name = b[i + 2:i + 1 + length].decode("utf-8", "ignore")
                        break
                    i += 1 + length
            except Exception:
                name = None

            _ble_results.append({
                "addr": addr_str,
                "rssi": int(rssi),
                "name": name,
                "adv_type": int(adv_type)
            })

        elif event == _IRQ_SCAN_DONE:
            add_log({"event": "BLE_SCAN_DONE", "count": len(_ble_results)})

    except Exception as e:
        add_log({"event": "BLE_IRQ_ERR", "err": str(e)})


def ble_scan_once(duration_ms=5000):
    global _ble, _ble_results

    if BLE is None:
        add_log({"error": "BLE_NOT_SUPPORTED"})
        return None

    _ble_results = []

    try:
        if _ble is None:
            _ble = BLE()
            _ble.active(True)
            _ble.irq(_ble_irq)

        add_log({"event": "BLE_SCAN_START", "duration_ms": duration_ms})

        _ble.gap_scan(duration_ms, 30000, 30000)

        time.sleep_ms(duration_ms + 200)

        add_log({"event": "BLE_SCAN_RESULT", "count": len(_ble_results)})

        try:
            _ble.active(False)
        except:
            pass

        return list(_ble_results)

    except Exception as e:
        add_log({"event": "BLE_SCAN_ERROR", "err": str(e)})
        try:
            if _ble:
                _ble.active(False)
        except:
            pass
        return None

# --------------------------------------------------------------------
# Serial helper
# --------------------------------------------------------------------


def send(obj):
    try:
        s = json.dumps(obj)
        sys.stdout.write(s + "\n")
        sys.stdout.flush()
    except Exception as e:
        add_log({"event": "SEND_ERR", "err": str(e)})

# --------------------------------------------------------------------
# Handle incoming JSON commands
# --------------------------------------------------------------------


def handle_cmd(line):
    try:
        obj = json.loads(line)
    except Exception as e:
        add_log({"event": "PARSE_ERR", "raw": line, "err": str(e)})
        return

    cmd = obj.get("cmd", "").upper()

    if cmd == "SET_MODE":
        mode = obj.get("mode", "IDLE").upper()
        set_mode(mode)
        send({"type": "status", "msg": "MODE_SET", "mode": mode})

    elif cmd == "SCAN_ONCE":
        if _current_mode == MODE_WIFI:
            res = wifi_scan_once()
            send({
                "type": "wifi_result",
                "count": len(res) if res else 0,
                "data": res
            })

        elif _current_mode == MODE_BLE:
            res = ble_scan_once()
            send({
                "type": "ble_result",
                "count": len(res) if res else 0,
                "data": res
            })

        else:
            send({"type": "status", "msg": "SCAN_IGNORED_NOT_IN_MODE"})

    elif cmd == "GET_LOGS":
        send({"type": "logs", "data": get_logs_list()})

    elif cmd == "CLEAR_LOGS":
        clear_logs()
        send({"type": "status", "msg": "LOGS_CLEARED"})

    else:
        send({"type": "unknown_cmd", "cmd": cmd})

# --------------------------------------------------------------------
# Boot events
# --------------------------------------------------------------------

add_log({"event": "BOOT", "fw": "micropython_main_py"})
send({"type": "status", "msg": "BOOT"})

# --------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------

while True:
    try:
        line = sys.stdin.readline()
        if line:
            line = line.strip()
            if line:
                handle_cmd(line)

    except Exception as e:
        add_log({"event": "LOOP_ERR", "err": str(e)})
        time.sleep_ms(100)

    time.sleep_ms(10)
