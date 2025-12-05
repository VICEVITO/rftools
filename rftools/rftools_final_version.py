# esp32_ctf_tool_pyqt6_v2.py
import sys, json, threading, time, re
from datetime import datetime
from dateutil import tz
import serial
import serial.tools.list_ports
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QComboBox, QLabel, QLineEdit,
    QGroupBox, QSpinBox, QFileDialog, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt

# ---------- Config ----------
BAUD = 115200
READ_TIMEOUT = 0.1
LOG_MAX_LINES = 20000

# ---------- State ----------
ser = None
reader_thread = None
reader_running = False
logs_list = []

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

# ---------- Serial / Command ----------
def send_cmd_json(obj):
    global ser
    if not ser or not ser.is_open:
        return False
    s = json.dumps(obj) + "\n"
    try:
        ser.write(s.encode("utf-8"))
        return True
    except:
        return False

def serial_reader_loop(gui):
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
                    try:
                        obj = json.loads(line)
                        gui.process_rx(obj)
                    except:
                        gui.append_log(f"<span style='color:gray'>[RAW]</span> {line}")
            else:
                time.sleep(0.02)
        except Exception as e:
            gui.append_log(f"<span style='color:red'>[ReaderErr]</span> {e}")
            time.sleep(0.1)

# ---------- GUI ----------
class ESP32CTF(QWidget):
    FLAG_PATTERNS = [
        r"FLAG\{[^\}]+\}",
        r"CTF\{[^\}]+\}",
        r"[A-Za-z0-9]{32}",
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ESP32 CTF Tool")
        self.resize(1200, 820)
        self.init_ui()
        self.update_ports()

    def init_ui(self):
        main_layout = QHBoxLayout(self)

        # Scrollable left menu
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        scroll.setWidget(left_widget)
        main_layout.addWidget(scroll, 0)

        # ---------------- Sections ----------------
        # Helper to create collapsible group
        def make_group(title, default_open=True):
            g = QGroupBox(title)
            g.setCheckable(True)
            g.setChecked(default_open)
            layout = QVBoxLayout()
            g.setLayout(layout)
            return g, layout

        # ---------- Connection ----------
        group_conn, v_conn = make_group("Connection", True)
        self.port_combo = QComboBox()
        btn_refresh = QPushButton("Refresh Ports")
        btn_connect = QPushButton("Connect")
        self.conn_status = QLabel("Not connected")
        v_conn.addWidget(self.port_combo)
        h1 = QHBoxLayout()
        h1.addWidget(btn_refresh)
        h1.addWidget(btn_connect)
        v_conn.addLayout(h1)
        v_conn.addWidget(self.conn_status)
        left_layout.addWidget(group_conn)

        btn_refresh.clicked.connect(self.update_ports)
        btn_connect.clicked.connect(self.connect_serial)

        # ---------- Mode ----------
        group_mode, v_mode = make_group("Mode", True)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["IDLE","WIFI","BLE"])
        btn_set_mode = QPushButton("Set Mode")
        btn_scan = QPushButton("Scan Mode")
        h_mode = QHBoxLayout()
        h_mode.addWidget(btn_set_mode)
        h_mode.addWidget(btn_scan)
        v_mode.addWidget(self.mode_combo)
        v_mode.addLayout(h_mode)
        left_layout.addWidget(group_mode)
        btn_set_mode.clicked.connect(self.set_mode)
        btn_scan.clicked.connect(self.scan_once)

        # ---------- WiFi ----------
        group_wifi, v_wifi = make_group("WiFi Controls", False)
        self.wifi_ssid = QLineEdit()
        self.wifi_ssid.setPlaceholderText("SSID")
        self.wifi_pwd = QLineEdit()
        self.wifi_pwd.setPlaceholderText("Password")
        self.wifi_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        btn_wifi_connect = QPushButton("Connect WiFi")
        btn_wifi_status = QPushButton("WiFi Status")
        btn_wifi_disconnect = QPushButton("Disconnect WiFi")
        v_wifi.addWidget(self.wifi_ssid)
        v_wifi.addWidget(self.wifi_pwd)
        h_wifi = QHBoxLayout()
        h_wifi.addWidget(btn_wifi_connect)
        h_wifi.addWidget(btn_wifi_status)
        h_wifi.addWidget(btn_wifi_disconnect)
        v_wifi.addLayout(h_wifi)
        left_layout.addWidget(group_wifi)
        btn_wifi_connect.clicked.connect(self.wifi_connect)
        btn_wifi_status.clicked.connect(self.wifi_status)
        btn_wifi_disconnect.clicked.connect(self.wifi_disconnect)

        # ---------- BLE ----------
        group_ble, v_ble = make_group("BLE Controls", False)
        self.ble_duration = QSpinBox()
        self.ble_duration.setRange(1000, 60000)
        self.ble_duration.setValue(5000)
        self.ble_addr = QLineEdit()
        self.ble_addr.setPlaceholderText("BLE Address")
        btn_ble_scan = QPushButton("BLE Scan")
        btn_ble_connect = QPushButton("Connect BLE")
        btn_ble_disconnect = QPushButton("Disconnect BLE")
        v_ble.addWidget(QLabel("Scan Duration (ms)"))
        v_ble.addWidget(self.ble_duration)
        v_ble.addWidget(btn_ble_scan)
        v_ble.addWidget(self.ble_addr)
        h_ble = QHBoxLayout()
        h_ble.addWidget(btn_ble_connect)
        h_ble.addWidget(btn_ble_disconnect)
        v_ble.addLayout(h_ble)
        left_layout.addWidget(group_ble)
        btn_ble_scan.clicked.connect(self.ble_scan)
        btn_ble_connect.clicked.connect(self.ble_connect)
        btn_ble_disconnect.clicked.connect(self.ble_disconnect)

        # ---------- TCP / UDP ----------
        group_net, v_net = make_group("TCP / UDP Tools", False)
        self.tcp_host = QLineEdit()
        self.tcp_host.setPlaceholderText("TCP Host")
        self.tcp_port = QSpinBox()
        self.tcp_port.setRange(1,65535)
        self.tcp_port.setValue(1234)
        btn_tcp_connect = QPushButton("TCP Connect")
        btn_tcp_send = QPushButton("TCP Send")
        self.tcp_send_data = QLineEdit()
        self.tcp_send_data.setPlaceholderText("Data")
        btn_tcp_close = QPushButton("TCP Close")
        v_net.addWidget(self.tcp_host)
        v_net.addWidget(self.tcp_port)
        v_net.addWidget(self.tcp_send_data)
        h_tcp = QHBoxLayout()
        h_tcp.addWidget(btn_tcp_connect)
        h_tcp.addWidget(btn_tcp_send)
        h_tcp.addWidget(btn_tcp_close)
        v_net.addLayout(h_tcp)
        left_layout.addWidget(group_net)
        btn_tcp_connect.clicked.connect(self.tcp_connect)
        btn_tcp_send.clicked.connect(self.tcp_send)
        btn_tcp_close.clicked.connect(self.tcp_close)

        # ---------- Quick Tools ----------
        group_tools, v_tools = make_group("Quick Tools", False)
        btn_get_logs = QPushButton("Get Logs")
        btn_clear_logs = QPushButton("Clear Logs")
        btn_export_logs = QPushButton("Export Logs")
        btn_search_flags = QPushButton("Search Flags")
        self.export_path = QLineEdit("esp_logs.json")
        v_tools.addWidget(btn_get_logs)
        v_tools.addWidget(btn_clear_logs)
        h_export = QHBoxLayout()
        h_export.addWidget(self.export_path)
        h_export.addWidget(btn_export_logs)
        v_tools.addLayout(h_export)
        v_tools.addWidget(btn_search_flags)
        left_layout.addWidget(group_tools)
        btn_get_logs.clicked.connect(self.get_logs)
        btn_clear_logs.clicked.connect(self.clear_logs)
        btn_export_logs.clicked.connect(self.export_logs)
        btn_search_flags.clicked.connect(self.search_flags)

        left_layout.addStretch(1)

        # ---------- Right panel logs ----------
        right_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("background-color:#101014;color:#ccffff;font-family:Courier;font-size:12pt;")
        right_layout.addWidget(QLabel("Device Logs"))
        right_layout.addWidget(self.log_text)
        main_layout.addLayout(right_layout, 1)

    # ---------- Logging ----------
    def append_log(self, s):
        global logs_list
        t = now_iso()
        line = f"[{t}] {s}"
        logs_list.append(line)
        if len(logs_list) > LOG_MAX_LINES:
            logs_list.pop(0)
        html_line = s.replace("\n","<br>").replace("  ","&nbsp;&nbsp;")
        self.log_text.append(html_line)
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())

    # ---------- RX Processing ----------
    def process_rx(self, obj):
        t = obj.get("type")
        if t == "wifi_result":
            count = obj.get("count")
            self.append_log(f"<b>[RX WIFI] Found {count} networks</b>")
            for e in obj.get("data", []):
                self.append_log(f"<b>{e.get('ssid')}</b><br>&nbsp;&nbsp;RSSI={e.get('rssi')} BSSID={e.get('bssid')} CH={e.get('channel')}")
        elif t == "ble_result":
            count = obj.get("count")
            self.append_log(f"<b>[RX BLE] Found {count} devices</b>")
            for e in obj.get("data", []):
                self.append_log(f"<b>{e.get('name') or e.get('addr')}</b><br>&nbsp;&nbsp;RSSI={e.get('rssi')} ADDR={e.get('addr')}")
        else:
            self.append_log(f"<span style='color:cyan'>[RX]</span> {json.dumps(obj)}")

    # ---------- Serial ----------
    def update_ports(self):
        self.port_combo.clear()
        ports = find_candidate_ports()
        self.port_combo.addItems(ports)
        self.append_log(f"<span style='color:yellow'>[UI]</span> Found ports: {ports}")

    def connect_serial(self):
        global ser, reader_thread, reader_running
        port = self.port_combo.currentText()
        if not port:
            self.append_log("<span style='color:red'>[UI]</span> No port selected")
            return
        if ser and ser.is_open:
            reader_running = False
            try: ser.close()
            except: pass
            ser = None
            self.conn_status.setText("Not connected")
            self.append_log("<span style='color:orange'>[UI]</span> Disconnected")
            return
        try:
            ser = serial.Serial(port, BAUD, timeout=READ_TIMEOUT)
            self.conn_status.setText(f"Connected: {port}")
            self.append_log(f"<span style='color:green'>[UI]</span> Connected to {port} @ {BAUD}")
            reader_running = True
            reader_thread = threading.Thread(target=serial_reader_loop, args=(self,), daemon=True)
            reader_thread.start()
        except Exception as e:
            self.append_log(f"<span style='color:red'>[UI]</span> Connect error: {e}")
            ser = None

    # ---------- Commands ----------
    def set_mode(self):
        mode = self.mode_combo.currentText()
        send_cmd_json({"cmd":"SET_MODE","mode":mode})
        self.append_log(f"<span style='color:orange'>[UI]</span> Set mode -> {mode}")

    def scan_once(self):
        send_cmd_json({"cmd":"SCAN_ONCE"})

    def wifi_connect(self):
        ssid = self.wifi_ssid.text()
        pwd = self.wifi_pwd.text()
        send_cmd_json({"cmd":"WIFI_CONNECT","ssid":ssid,"pwd":pwd})

    def wifi_disconnect(self):
        send_cmd_json({"cmd":"WIFI_DISCONNECT"})

    def wifi_status(self):
        send_cmd_json({"cmd":"WIFI_STATUS"})

    def ble_scan(self):
        dur = self.ble_duration.value()
        send_cmd_json({"cmd":"BLE_SCAN","duration_ms":dur})

    def ble_connect(self):
        addr = self.ble_addr.text()
        if not addr:
            self.append_log("<span style='color:red'>[UI]</span> BLE address required")
            return
        send_cmd_json({"cmd":"BLE_CONNECT","addr":addr})

    def ble_disconnect(self):
        send_cmd_json({"cmd":"BLE_DISCONNECT"})

    def tcp_connect(self):
        host = self.tcp_host.text()
        port = self.tcp_port.value()
        send_cmd_json({"cmd":"TCP_CONNECT","host":host,"port":port})

    def tcp_send(self):
        data = self.tcp_send_data.text()
        send_cmd_json({"cmd":"TCP_SEND","data":data})

    def tcp_close(self):
        send_cmd_json({"cmd":"TCP_CLOSE"})

    def get_logs(self):
        send_cmd_json({"cmd":"GET_LOGS"})

    def clear_logs(self):
        send_cmd_json({"cmd":"CLEAR_LOGS"})
        self.append_log("<span style='color:orange'>[UI]</span> Cleared logs on device")

    def export_logs(self):
        path = self.export_path.text()
        if not path:
            self.append_log("<span style='color:red'>[UI]</span> No export path set")
            return
        try:
            with open(path,"w",encoding="utf-8") as f:
                json.dump(logs_list,f,ensure_ascii=False,indent=2)
            self.append_log(f"<span style='color:green'>[UI]</span> Exported logs to {path}")
        except Exception as e:
            self.append_log(f"<span style='color:red'>[UI]</span> Export error: {e}")

    def search_flags(self):
        content = "\n".join(logs_list)
        found = set()
        for p in self.FLAG_PATTERNS:
            for m in re.findall(p, content):
                found.add(m)
        if found:
            self.append_log("<span style='color:lime'><b>[FLAG] Found flags:</b></span>")
            for f in found:
                self.append_log(f"&nbsp;&nbsp;{f}")
        else:
            self.append_log("<span style='color:gray'>[FLAG]</span> No flag found")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ESP32CTF()
    gui.show()
    sys.exit(app.exec())
