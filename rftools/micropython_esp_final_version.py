# main.py - MicroPython ESP32 (STABILISÉ contre le plantage mémoire BLE)
import sys
import ujson as json
import time
import machine
from ubinascii import hexlify

# --- Import network and BLE if available ---
try:
    import network
except:
    network = None

try:
    from bluetooth import BLE
except:
    BLE = None

import usocket

# --- Logging circular buffer ---
LOG_CAPACITY = 1024
logs = [None] * LOG_CAPACITY
_log_head = 0
_log_count = 0

def add_log(obj):
    global _log_head, _log_count
    entry = {"ts": time.ticks_ms(), "entry": obj}
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

# --- Modes ---
MODE_IDLE = 0
MODE_WIFI = 1
MODE_BLE = 2
_current_mode = MODE_IDLE

def set_mode(mode_str):
    global _current_mode
    mode_str = mode_str.upper()
    if mode_str == "WIFI":
        _current_mode = MODE_WIFI
    elif mode_str == "BLE":
        _current_mode = MODE_BLE
    else:
        _current_mode = MODE_IDLE
    add_log({"event": "MODE_SET", "mode": mode_str})

# --- WiFi functions ---
def wifi_scan_once():
    if not network:
        add_log({"error": "WIFI_NOT_SUPPORTED"})
        return []
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    add_log({"event": "WIFI_SCAN_START"})
    try:
        res = wlan.scan()
    except Exception as e:
        add_log({"event": "WIFI_SCAN_ERROR", "err": str(e)})
        return []
    out = []
    for r in res:
        ssid = r[0].decode() if isinstance(r[0], (bytes, bytearray)) else str(r[0])
        bssid = hexlify(r[1]).decode() if isinstance(r[1], (bytes, bytearray)) else str(r[1])
        out.append({
            "ssid": ssid,
            "bssid": bssid,
            "channel": int(r[2]),
            "rssi": int(r[3]),
            "auth": int(r[4]),
            "hidden": bool(r[5])
        })
    add_log({"event": "WIFI_SCAN_RESULT", "count": len(out)})
    return out

def wifi_connect(ssid, pwd):
    if not network:
        add_log({"error": "WIFI_NOT_SUPPORTED"})
        return {"status": "error"}
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(ssid, pwd)
    timeout = 10
    for _ in range(timeout * 10):
        if wlan.isconnected():
            add_log({"event": "WIFI_CONNECTED", "ssid": ssid, "ip": wlan.ifconfig()[0]})
            return {"status": "ok", "ip": wlan.ifconfig()[0]}
        time.sleep(0.1)
    add_log({"event": "WIFI_CONN_FAIL", "ssid": ssid})
    return {"status": "fail"}

def wifi_disconnect():
    if not network:
        return {"status": "error"}
    wlan = network.WLAN(network.STA_IF)
    wlan.active(False)
    add_log({"event": "WIFI_DISCONNECTED"})
    return {"status": "ok"}

def wifi_status():
    if not network:
        return {"status": "error"}
    wlan = network.WLAN(network.STA_IF)
    return {"status": "ok", "connected": wlan.isconnected(), "ip": wlan.ifconfig()[0] if wlan.isconnected() else None}

# --- BLE functions (STABILISÉ) ---
_ble = None
_ble_results = {} # FIX: Dictionnaire pour la déduplication et la stabilité
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
                while i + 1 < len(adv_data):
                    length = b[i]
                    if length == 0: break
                    type_ = adv_data[i + 1]
                    if type_ in (0x08, 0x09):
                        name = adv_data[i + 2:i + 1 + length].decode('utf-8', 'ignore')
                        break
                    i += 1 + length
            except:
                name = None
            
            # FIX: Utiliser le dictionnaire (clé = adresse MAC) pour la déduplication
            if addr_str not in _ble_results:
                 _ble_results[addr_str] = {"addr": addr_str, "rssi": int(rssi), "name": name}
            else:
                 _ble_results[addr_str]['rssi'] = int(rssi)
                 if name:
                     _ble_results[addr_str]['name'] = name
                 
        elif event == _IRQ_SCAN_DONE:
            add_log({"event": "BLE_SCAN_DONE", "count": len(_ble_results)})
    except Exception as e:
        add_log({"event": "BLE_IRQ_ERR", "err": str(e)})

def ble_scan_once(duration_ms=5000):
    global _ble, _ble_results
    if BLE is None:
        add_log({"error": "BLE_NOT_SUPPORTED"})
        return []
    
    # FIX: Vider le dictionnaire de résultats
    _ble_results.clear()
    
    try:
        # Reset explicite pour la stabilité
        if _ble is not None:
            try:
                _ble.active(False)
            except:
                pass
        _ble = BLE()
        _ble.active(True)
        _ble.irq(_ble_irq)
        
        # Le mode par défaut sans active=True est passif (le mode stable)
        add_log({"event": "BLE_SCAN_START", "duration_ms": duration_ms})
        
        # FIX: Retrait des arguments 30000, 30000 qui causaient des erreurs de compatibilité
        _ble.gap_scan(duration_ms) 
        
        time.sleep_ms(duration_ms + 200)
        
        try:
            _ble.active(False)
        except:
            pass
            
        # FIX: Convertir les valeurs du dictionnaire en liste pour la sortie
        out_list = list(_ble_results.values())
        add_log({"event": "BLE_SCAN_RESULT", "count": len(out_list)})
        return out_list
        
    except Exception as e:
        add_log({"event": "BLE_SCAN_ERROR", "err": str(e)})
        try:
            if _ble: _ble.active(False)
        except:
            pass
        return []

# --- TCP/UDP automatic reception ---
_tcp_socket = None
_udp_socket = None
_udp_addr = None

def tcp_connect(host, port):
    global _tcp_socket
    try:
        s = usocket.socket(usocket.AF_INET, usocket.SOCK_STREAM)
        s.connect((host, port))
        s.setblocking(False)
        _tcp_socket = s
        add_log({"event": "TCP_CONNECTED", "host": host, "port": port})
        return {"status": "ok"}
    except Exception as e:
        add_log({"event": "TCP_CONN_FAIL", "err": str(e)})
        return {"status": "fail"}

def tcp_send(data):
    global _tcp_socket
    if not _tcp_socket:
        return {"status": "error", "msg": "not connected"}
    try:
        _tcp_socket.write(data.encode())
        add_log({"event": "TCP_SEND", "data": data})
        return {"status": "ok"}
    except Exception as e:
        add_log({"event": "TCP_SEND_ERR", "err": str(e)})
        return {"status": "fail"}

def tcp_close():
    global _tcp_socket
    if _tcp_socket:
        try:
            _tcp_socket.close()
        except:
            pass
        _tcp_socket = None
        add_log({"event": "TCP_CLOSED"})
        return {"status": "ok"}
    return {"status": "error"}

def udp_setup(host, port):
    global _udp_socket, _udp_addr
    try:
        s = usocket.socket(usocket.AF_INET, usocket.SOCK_DGRAM)
        s.setblocking(False)
        _udp_socket = s
        _udp_addr = (host, port)
        add_log({"event": "UDP_READY", "host": host, "port": port})
        return {"status": "ok"}
    except Exception as e:
        add_log({"event": "UDP_SETUP_FAIL", "err": str(e)})
        return {"status": "fail"}

def udp_send(data):
    global _udp_socket, _udp_addr
    if not _udp_socket or not _udp_addr:
        return {"status": "error", "msg": "not connected"}
    try:
        _udp_socket.sendto(data.encode(), _udp_addr)
        add_log({"event": "UDP_SEND", "data": data})
        return {"status": "ok"}
    except Exception as e:
        add_log({"event": "UDP_SEND_ERR", "err": str(e)})
        return {"status": "fail"}

def recv_loop():
    global _tcp_socket, _udp_socket
    try:
        if _tcp_socket:
            try:
                data = _tcp_socket.read(1024)
                if data:
                    add_log({"event": "TCP_RECV", "data": data.decode(errors="ignore")})
            except:
                pass
        if _udp_socket:
            try:
                while True:
                    data, addr = _udp_socket.recvfrom(1024)
                    add_log({"event": "UDP_RECV", "from": addr, "data": data.decode(errors="ignore")})
            except:
                pass
    except Exception as e:
        add_log({"event": "RECV_LOOP_ERR", "err": str(e)})

# --- Serial helper ---
def send(obj):
    try:
        s = json.dumps(obj)
        sys.stdout.write(s + "\n")
        sys.stdout.flush()
    except:
        pass

# --- Handle incoming commands ---
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
            send({"type": "wifi_result", "count": len(res), "data": res})
        elif _current_mode == MODE_BLE:
            res = ble_scan_once()
            send({"type": "ble_result", "count": len(res), "data": res})
        else:
            send({"type": "status", "msg": "SCAN_IGNORED_NOT_IN_MODE"})
    elif cmd == "GET_LOGS":
        send({"type": "logs", "data": get_logs_list()})
    elif cmd == "CLEAR_LOGS":
        clear_logs()
        send({"type": "status", "msg": "LOGS_CLEARED"})
    elif cmd == "WIFI_CONNECT":
        ssid = obj.get("ssid")
        pwd = obj.get("pwd")
        res = wifi_connect(ssid, pwd)
        d = {"type": "wifi_connect_result"}
        d.update(res)
        send(d)
    elif cmd == "WIFI_DISCONNECT":
        res = wifi_disconnect()
        d = {"type": "wifi_disconnect_result"}
        d.update(res)
        send(d)
    elif cmd == "WIFI_STATUS":
        res = wifi_status()
        d = {"type": "wifi_status_result"}
        d.update(res)
        send(d)
    elif cmd == "TCP_CONNECT":
        host = obj.get("host")
        port = obj.get("port")
        res = tcp_connect(host, port)
        d = {"type": "tcp_connect_result"}
        d.update(res)
        send(d)
    elif cmd == "TCP_SEND":
        data = obj.get("data","")
        res = tcp_send(data)
        d = {"type": "tcp_send_result"}
        d.update(res)
        send(d)
    elif cmd == "TCP_CLOSE":
        res = tcp_close()
        d = {"type": "tcp_close_result"}
        d.update(res)
        send(d)
    elif cmd == "UDP_SETUP":
        host = obj.get("host")
        port = obj.get("port")
        res = udp_setup(host, port)
        d = {"type": "udp_setup_result"}
        d.update(res)
        send(d)
    elif cmd == "UDP_SEND":
        data = obj.get("data","")
        res = udp_send(data)
        d = {"type": "udp_send_result"}
        d.update(res)
        send(d)
    else:
        send({"type": "unknown_cmd", "cmd": cmd})

# --- Boot log ---
add_log({"event": "BOOT"})
send({"type": "status", "msg": "BOOT"})

# --- Main loop ---
while True:
    try:
        line = sys.stdin.readline()
        if line:
            handle_cmd(line.strip())
        recv_loop()
    except Exception as e:
        add_log({"event": "LOOP_ERR", "err": str(e)})
    time.sleep_ms(10)
