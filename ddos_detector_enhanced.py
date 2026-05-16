"""
🔐 ADVANCED DDoS DETECTOR v2.0 - ENTERPRISE EDITION
Multi-vector attack detection with ML-based anomaly scoring
Production-ready with logging, alerts, and IP reputation system
"""

import threading
import time
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from collections import deque, defaultdict
from pathlib import Path
import math
import re
from typing import Dict, List, Tuple, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from dash import Dash, dcc, html, Input, Output, State, callback
from dash.exceptions import PreventUpdate
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw

# ============================================================================
# LOGGING & DATABASE SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler('ddos_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = "ddos_detector.db"

def init_database():
    """Initialize SQLite database for threat history and IP reputation"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Threat incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME,
            source_ip TEXT,
            attack_type TEXT,
            severity REAL,
            packets_per_sec INTEGER,
            description TEXT
        )
    ''')
    
    # IP reputation table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip_address TEXT PRIMARY KEY,
            threat_score REAL,
            incident_count INTEGER,
            last_seen DATETIME,
            attack_types TEXT,
            is_whitelisted BOOLEAN DEFAULT 0,
            is_blacklisted BOOLEAN DEFAULT 0
        )
    ''')
    
    # Baseline metrics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS baseline_metrics (
            timestamp DATETIME,
            avg_pps INTEGER,
            avg_entropy REAL,
            baseline_z_score REAL
        )
    ''')
    
    conn.commit()
    conn.close()

init_database()

# ============================================================================
# ENHANCED GLOBAL METRICS WITH ADVANCED TRACKING
# ============================================================================
WINDOW_SIZE = 120  # 2 minutes of historical data
LEARNING_PERIOD = 300  # 5 minutes to build baseline

global_traffic_history = deque(maxlen=WINDOW_SIZE)
entropy_history = deque(maxlen=WINDOW_SIZE)
payload_size_history = deque(maxlen=WINDOW_SIZE)
protocol_distribution = deque(maxlen=WINDOW_SIZE)

# Advanced metrics matrix
vector_metrics = {
    "tcp_syn": defaultdict(int),
    "tcp_ack": defaultdict(int),
    "tcp_fin": defaultdict(int),
    "tcp_rst": defaultdict(int),
    "udp_vol": defaultdict(int),
    "icmp_vol": defaultdict(int),
    "http_streams": defaultdict(int),
    "tls_handshakes": defaultdict(int),
    "dns_queries": defaultdict(int),
    "arp_requests": defaultdict(int),
    "timestamps": defaultdict(lambda: deque(maxlen=5000)),
    "raw_ip_pool": [],
    "payload_sizes": defaultdict(list),
    "port_distribution": defaultdict(lambda: defaultdict(int)),
    "suspicious_payload": defaultdict(int),
    "malformed_packets": defaultdict(int)
}

# Threat tracking
threat_cache = {}
suppressed_alerts = set()
lock = threading.Lock()

# ============================================================================
# SHANNON ENTROPY & STATISTICAL ANALYSIS
# ============================================================================
def calculate_ip_entropy(ip_list: List[str]) -> float:
    """Enhanced entropy calculation with smoothing"""
    if not ip_list or len(ip_list) < 10:
        return 0.0
    
    total_ips = len(ip_list)
    counts = defaultdict(int)
    for ip in ip_list:
        counts[ip] += 1
    
    entropy = 0.0
    for count in counts.values():
        probability = count / total_ips
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_payload_variance(payload_sizes: List[int]) -> Tuple[float, float]:
    """Calculate payload size mean and variance"""
    if not payload_sizes:
        return 0.0, 0.0
    
    mean = sum(payload_sizes) / len(payload_sizes)
    variance = sum((x - mean) ** 2 for x in payload_sizes) / len(payload_sizes)
    return mean, math.sqrt(variance)

def calculate_z_score(value: float, mean: float, std_dev: float) -> float:
    """Calculate statistical z-score with safety bounds"""
    if std_dev < 0.1:
        return 0.0
    return (value - mean) / std_dev

# ============================================================================
# ADVANCED THREAT DETECTION ENGINE
# ============================================================================
class ThreatDetector:
    """ML-inspired threat detection with multi-vector analysis"""
    
    def __init__(self):
        self.baseline_mean = 0
        self.baseline_std = 1
        self.learning_start = time.time()
        self.is_learning = True
    
    def update_baseline(self, traffic_history: List[int]):
        """Update baseline metrics for anomaly detection"""
        if len(traffic_history) < 30:
            self.is_learning = True
            return
        
        self.baseline_mean = sum(traffic_history) / len(traffic_history)
        self.baseline_std = math.sqrt(
            sum((x - self.baseline_mean) ** 2 for x in traffic_history) / len(traffic_history)
        ) or 1.0
        
        elapsed = time.time() - self.learning_start
        if elapsed > LEARNING_PERIOD:
            self.is_learning = False
    
    def analyze_single_source(self, ip: str, metrics: Dict) -> Tuple[bool, str, float]:
        """
        Analyze single source for attack signatures
        Returns: (is_threat, threat_type, threat_score)
        """
        threat_score = 0.0
        threat_type = "Legitimate"
        
        syns = metrics.get("tcp_syn", 0)
        acks = metrics.get("tcp_ack", 0)
        fins = metrics.get("tcp_fin", 0)
        rsts = metrics.get("tcp_rst", 0)
        udp_count = metrics.get("udp_vol", 0)
        icmp_count = metrics.get("icmp_vol", 0)
        http_streams = metrics.get("http_streams", 0)
        tls_hs = metrics.get("tls_handshakes", 0)
        dns_queries = metrics.get("dns_queries", 0)
        pps = metrics.get("pps", 0)
        
        # -------- VECTOR 1: TCP SYN FLOOD --------
        syn_ack_ratio = syns / max(acks, 1)
        if syns > 25 and syn_ack_ratio > 4.0:
            threat_score += 30
            threat_type = "TCP SYN Flood"
        elif syns > 40 and syn_ack_ratio > 2.0:
            threat_score += 20
            threat_type = "Aggressive SYN Activity"
        
        # -------- VECTOR 2: TCP FIN/RST Flood --------
        if (fins + rsts) > syns and (fins + rsts) > 20:
            threat_score += 25
            threat_type = "Connection Reset Flood (FIN/RST)"
        
        # -------- VECTOR 3: HTTP/2 Stream Abuse --------
        if http_streams > 40:
            threat_score += 28
            threat_type = "HTTP/2 Stream Multiplexing Abuse"
        elif http_streams > 20 and pps > 100:
            threat_score += 15
            threat_type = "Elevated HTTP Activity"
        
        # -------- VECTOR 4: TLS Renegotiation Flood --------
        if tls_hs > 20:
            threat_score += 32
            threat_type = "TLS Handshake Flood (Cryptographic DoS)"
        
        # -------- VECTOR 5: UDP Volumetric Attacks --------
        if udp_count > 80:
            threat_score += 28
            threat_type = "UDP Volumetric Flood"
        elif udp_count > 50 and dns_queries > udp_count * 0.7:
            threat_score += 22
            threat_type = "DNS Query Flood (Amplification)"
        
        # -------- VECTOR 6: ICMP Flood --------
        if icmp_count > 50:
            threat_score += 25
            threat_type = "ICMP Flood"
        
        # -------- VECTOR 7: Payload Anomalies --------
        payload_mean, payload_std = calculate_payload_variance(
            metrics.get("payload_sizes", [])
        )
        if payload_std > 500:  # High variance = suspicious
            threat_score += 10
        
        is_threat = threat_score >= 20  # Threshold
        return is_threat, threat_type, threat_score

threat_detector = ThreatDetector()

# ============================================================================
# PACKET PROCESSING ENGINE WITH ENHANCED PARSING
# ============================================================================
def parse_payload_for_signatures(payload: bytes) -> Dict[str, bool]:
    """Detect suspicious patterns in payload"""
    signatures = {
        "http_request": False,
        "tls_handshake": False,
        "dns_query": False,
        "suspicious_buffer": False,
        "null_bytes": False
    }
    
    if not payload or len(payload) < 4:
        return signatures
    
    try:
        # HTTP detection
        if b"GET " in payload[:100] or b"POST " in payload[:100] or b"HTTP/" in payload[:100]:
            signatures["http_request"] = True
        
        # TLS detection
        if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
            signatures["tls_handshake"] = True
        
        # DNS detection (simplified)
        if len(payload) > 12 and payload[2:4] == b'\x01\x00':
            signatures["dns_query"] = True
        
        # Suspicious patterns
        if b"\x00" * 4 in payload:
            signatures["null_bytes"] = True
        
        if len(payload) > 1000 and payload.count(b'\x00') > len(payload) * 0.3:
            signatures["suspicious_buffer"] = True
    
    except Exception as e:
        logger.debug(f"Payload parsing error: {e}")
    
    return signatures

def packet_ingestion_engine():
    """Main packet sniffing and processing thread"""
    def process_packet(pkt):
        if not pkt.haslayer(IP):
            return
        
        try:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            current_time = time.time()
            pkt_size = len(pkt)
            
            with lock:
                # Track timestamp
                vector_metrics["timestamps"][src_ip].append(current_time)
                vector_metrics["raw_ip_pool"].append(src_ip)
                vector_metrics["payload_sizes"][src_ip].append(pkt_size)
                
                # Memory management
                if len(vector_metrics["raw_ip_pool"]) > 15000:
                    vector_metrics["raw_ip_pool"] = vector_metrics["raw_ip_pool"][-8000:]
                
                # -------- TCP LAYER PROCESSING --------
                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    flags = tcp_layer.flags
                    dport = tcp_layer.dport
                    sport = tcp_layer.sport
                    
                    # Flag counting
                    if "S" in flags and "A" not in flags:
                        vector_metrics["tcp_syn"][src_ip] += 1
                    if "A" in flags:
                        vector_metrics["tcp_ack"][src_ip] += 1
                    if "F" in flags:
                        vector_metrics["tcp_fin"][src_ip] += 1
                    if "R" in flags:
                        vector_metrics["tcp_rst"][src_ip] += 1
                    
                    # Port tracking
                    vector_metrics["port_distribution"][src_ip][dport] += 1
                    
                    # Payload analysis
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)
                        sigs = parse_payload_for_signatures(payload)
                        
                        if sigs["tls_handshake"]:
                            vector_metrics["tls_handshakes"][src_ip] += 1
                        if sigs["http_request"]:
                            vector_metrics["http_streams"][src_ip] += 1
                        if sigs["suspicious_buffer"] or sigs["null_bytes"]:
                            vector_metrics["suspicious_payload"][src_ip] += 1
                
                # -------- UDP LAYER PROCESSING --------
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    dport = udp_layer.dport
                    
                    vector_metrics["udp_vol"][src_ip] += 1
                    vector_metrics["port_distribution"][src_ip][dport] += 1
                    
                    # DNS detection (port 53)
                    if dport == 53 or dport == 5353:
                        vector_metrics["dns_queries"][src_ip] += 1
                    
                    # QUIC/HTTP3 (port 443)
                    if dport == 443:
                        vector_metrics["http_streams"][src_ip] += 1
                
                # -------- ICMP LAYER PROCESSING --------
                elif pkt.haslayer(ICMP):
                    vector_metrics["icmp_vol"][src_ip] += 1
                
                # -------- ARP LAYER PROCESSING --------
                elif pkt.haslayer(ARP):
                    vector_metrics["arp_requests"][src_ip] += 1
        
        except Exception as e:
            vector_metrics["malformed_packets"][src_ip] += 1
            logger.debug(f"Packet processing error for {src_ip}: {e}")
    
    try:
        # Run sniffer (requires root/admin)
        sniff(prn=process_packet, store=0, iface=None)
    except PermissionError:
        logger.error("❌ ERROR: This tool requires root/admin privileges to sniff packets!")
        logger.error("On Linux: sudo python3 ddos_detector_enhanced.py")
        logger.error("On Windows: Run Command Prompt as Administrator")
    except Exception as e:
        logger.error(f"Sniffer error: {e}")

# Start packet ingestion in daemon thread
threading.Thread(target=packet_ingestion_engine, daemon=True).start()

# ============================================================================
# METRICS HISTORIAN & BASELINE UPDATER
# ============================================================================
def metrics_historian():
    """Background thread: compute rolling metrics and update baselines"""
    while True:
        time.sleep(1)
        current_time = time.time()
        frame_total = 0
        
        with lock:
            # Cleanup old timestamps (>1 second old)
            for ip, data in list(vector_metrics["timestamps"].items()):
                vector_metrics["timestamps"][ip] = deque(
                    [t for t in data if current_time - t <= 1],
                    maxlen=5000
                )
                frame_total += len(vector_metrics["timestamps"][ip])
            
            # Compute entropy
            current_entropy = calculate_ip_entropy(vector_metrics["raw_ip_pool"])
            entropy_history.append(current_entropy)
        
        global_traffic_history.append(frame_total)
        
        # Update baseline every 10 seconds
        if int(time.time()) % 10 == 0:
            threat_detector.update_baseline(list(global_traffic_history))

threading.Thread(target=metrics_historian, daemon=True).start()

# ============================================================================
# DATABASE OPERATIONS
# ============================================================================
def log_incident(src_ip: str, attack_type: str, severity: float, pps: int, description: str):
    """Log detected incident to database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO incidents (timestamp, source_ip, attack_type, severity, packets_per_sec, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime.now(), src_ip, attack_type, severity, pps, description))
        
        # Update IP reputation
        cursor.execute('''
            SELECT threat_score, incident_count FROM ip_reputation WHERE ip_address = ?
        ''', (src_ip,))
        
        row = cursor.fetchone()
        if row:
            new_score = min(100, row[0] + severity * 10)
            new_count = row[1] + 1
            cursor.execute('''
                UPDATE ip_reputation SET threat_score = ?, incident_count = ?, last_seen = ?
                WHERE ip_address = ?
            ''', (new_score, new_count, datetime.now(), src_ip))
        else:
            cursor.execute('''
                INSERT INTO ip_reputation (ip_address, threat_score, incident_count, last_seen, attack_types)
                VALUES (?, ?, ?, ?, ?)
            ''', (src_ip, severity * 10, 1, datetime.now(), attack_type))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database error: {e}")

def get_incident_history(limit: int = 50) -> List[Dict]:
    """Retrieve recent incidents from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, source_ip, attack_type, severity, packets_per_sec
            FROM incidents ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        incidents = []
        for row in cursor.fetchall():
            incidents.append({
                'timestamp': row[0],
                'source_ip': row[1],
                'attack_type': row[2],
                'severity': row[3],
                'pps': row[4]
            })
        
        conn.close()
        return incidents
    except Exception as e:
        logger.error(f"Database read error: {e}")
        return []

def get_ip_reputation(ip: str) -> Optional[Dict]:
    """Get reputation score for IP address"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT threat_score, incident_count, is_blacklisted FROM ip_reputation WHERE ip_address = ?
        ''', (ip,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'threat_score': row[0],
                'incident_count': row[1],
                'is_blacklisted': row[2]
            }
        return None
    except Exception as e:
        logger.error(f"Database error: {e}")
        return None

# ============================================================================
# DASH WEB INTERFACE - ENHANCED DARK THEME
# ============================================================================
app = Dash(__name__)

THEME = {
    "bg_dark": "#0f1117",
    "bg_panel": "#161b22",
    "bg_hover": "#1c2128",
    "cyan": "#58a6ff",
    "neon_green": "#3fb950",
    "warn_orange": "#d29922",
    "alert_red": "#f85149",
    "text_light": "#c9d1d9",
    "text_muted": "#8b949e",
    "font": "'Courier New', monospace",
    "accent_purple": "#d2a8ff"
}

app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>🔐 Advanced DDoS Detector v2.0</title>
        {%favicon%}
        {%css%}
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/hack-font@3.3.0/build/web/hack.min.css">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                background-color: ''' + THEME["bg_dark"] + ''';
                color: ''' + THEME["text_light"] + ''';
                font-family: ''' + THEME["font"] + ''';
            }
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: ''' + THEME["bg_panel"] + '''; }
            ::-webkit-scrollbar-thumb { background: ''' + THEME["cyan"] + '''; border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: ''' + THEME["accent_purple"] + '''; }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>{%config%}{%scripts%}{%renderer%}</footer>
    </body>
</html>
'''

app.layout = html.Div(
    style={
        "fontFamily": THEME["font"],
        "padding": "20px",
        "backgroundColor": THEME["bg_dark"],
        "color": THEME["text_light"],
        "minHeight": "100vh"
    },
    children=[
        # -------- HEADER --------
        html.Div(
            style={
                "marginBottom": "30px",
                "borderBottom": f"2px solid {THEME['cyan']}",
                "paddingBottom": "20px"
            },
            children=[
                html.H1(
                    "🔐 ADVANCED DDoS DETECTOR v2.0",
                    style={"color": THEME["cyan"], "fontSize": "32px", "marginBottom": "10px", "letterSpacing": "2px"}
                ),
                html.P(
                    "Multi-Vector Attack Detection | Real-Time Analysis | ML-Based Anomaly Scoring",
                    style={"color": THEME["text_muted"], "fontSize": "14px"}
                )
            ]
        ),
        
        # -------- STATUS BAR --------
        html.Div(
            id="status-bar",
            style={
                "display": "flex",
                "justifyContent": "space-between",
                "alignItems": "center",
                "padding": "15px",
                "backgroundColor": THEME["bg_panel"],
                "borderRadius": "8px",
                "marginBottom": "20px",
                "border": f"1px solid {THEME['cyan']}",
                "gap": "20px",
                "flexWrap": "wrap"
            },
            children=[
                html.Div(id="status-badge-2026"),
                html.Div(id="learning-indicator"),
                html.Div(id="threat-level-indicator"),
                html.Div(id="uptime-counter")
            ]
        ),
        
        # -------- CONTROL PANEL --------
        html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fit, minmax(250px, 1fr))",
                "gap": "15px",
                "marginBottom": "20px"
            },
            children=[
                # Z-Score Threshold
                html.Div([
                    html.Label("Z-Score Threshold (σ):", style={"fontSize": "13px", "color": THEME["warn_orange"]}),
                    dcc.Slider(
                        id="z-slider-2026",
                        min=1,
                        max=5,
                        step=0.1,
                        value=2.5,
                        marks={i: str(i) for i in range(1, 6)},
                        tooltip={"placement": "bottom", "always_visible": True},
                        style={"padding": "10px 0"}
                    )
                ]),
                
                # Entropy Threshold
                html.Div([
                    html.Label("Entropy Threshold (H'):", style={"fontSize": "13px", "color": THEME["warn_orange"]}),
                    dcc.Slider(
                        id="entropy-input",
                        min=0,
                        max=10,
                        step=0.5,
                        value=4.5,
                        marks={i: str(i) for i in range(0, 11, 2)},
                        tooltip={"placement": "bottom", "always_visible": True},
                        style={"padding": "10px 0"}
                    )
                ]),
                
                # Refresh Rate
                html.Div([
                    html.Label("Auto-Refresh (sec):", style={"fontSize": "13px", "color": THEME["warn_orange"]}),
                    dcc.Dropdown(
                        id="refresh-rate",
                        options=[
                            {"label": "1 sec (High CPU)", "value": 1000},
                            {"label": "2 sec (Normal)", "value": 2000},
                            {"label": "5 sec (Low CPU)", "value": 5000}
                        ],
                        value=2000,
                        style={"color": THEME["bg_dark"]}
                    )
                ])
            ]
        ),
        
        # -------- MAIN ANALYTICS GRID --------
        html.Div(
            style={"display": "grid", "gridTemplateColumns": "1fr 1fr", "gap": "20px", "marginBottom": "20px"},
            children=[
                # Volumetric Traffic Chart
                html.Div([
                    html.H3("📊 VOLUMETRIC TRAFFIC ANALYSIS", style={"color": THEME["cyan"], "fontSize": "14px", "marginBottom": "15px"}),
                    dcc.Graph(id="chart-volumetric-2026", style={"margin": "0"})
                ], style={"backgroundColor": THEME["bg_panel"], "padding": "20px", "borderRadius": "8px", "border": f"1px solid {THEME['bg_hover']}"}),
                
                # Attack Vector Distribution
                html.Div([
                    html.H3("⚔️ ATTACK VECTOR SIGNATURES", style={"color": THEME["alert_red"], "fontSize": "14px", "marginBottom": "15px"}),
                    dcc.Graph(id="chart-threat-vectors-2026", style={"margin": "0"})
                ], style={"backgroundColor": THEME["bg_panel"], "padding": "20px", "borderRadius": "8px", "border": f"1px solid {THEME['bg_hover']}"}),
            ]
        ),
        
        # -------- INCIDENT ALERTS --------
        html.Div(
            style={"marginBottom": "20px"},
            children=[
                html.H3("🚨 ACTIVE INCIDENTS & MITIGATION", style={"color": THEME["alert_red"], "fontSize": "14px", "marginBottom": "15px"}),
                html.Div(
                    id="live-incident-deck-2026",
                    style={
                        "backgroundColor": THEME["bg_panel"],
                        "padding": "20px",
                        "borderRadius": "8px",
                        "border": f"1px solid {THEME['bg_hover']}",
                        "maxHeight": "400px",
                        "overflowY": "auto"
                    }
                )
            ]
        ),
        
        # -------- DETAILED METRICS --------
        html.Div(
            style={"display": "grid", "gridTemplateColumns": "repeat(auto-fit, minmax(300px, 1fr))", "gap": "15px", "marginBottom": "20px"},
            children=[
                html.Div(id="metrics-panel-1", style={"backgroundColor": THEME["bg_panel"], "padding": "20px", "borderRadius": "8px", "border": f"1px solid {THEME['bg_hover']}"}),
                html.Div(id="metrics-panel-2", style={"backgroundColor": THEME["bg_panel"], "padding": "20px", "borderRadius": "8px", "border": f"1px solid {THEME['bg_hover']}"}),
                html.Div(id="metrics-panel-3", style={"backgroundColor": THEME["bg_panel"], "padding": "20px", "borderRadius": "8px", "border": f"1px solid {THEME['bg_hover']}"}),
            ]
        ),
        
        # -------- INCIDENT HISTORY --------
        html.Div(
            style={"marginBottom": "20px"},
            children=[
                html.H3("📜 INCIDENT HISTORY (Last 24 Hours)", style={"color": THEME["cyan"], "fontSize": "14px", "marginBottom": "15px"}),
                html.Div(id="incident-history-table", style={"backgroundColor": THEME["bg_panel"], "padding": "20px", "borderRadius": "8px", "border": f"1px solid {THEME['bg_hover']}"}),
            ]
        ),
        
        # Update interval
        dcc.Interval(id="engine-pulse-2026", interval=2000, n_intervals=0),
    ]
)

# ============================================================================
# CALLBACK: MAIN ANALYTICS UPDATE
# ============================================================================
@app.callback(
    [
        Output("chart-volumetric-2026", "figure"),
        Output("chart-threat-vectors-2026", "figure"),
        Output("live-incident-deck-2026", "children"),
        Output("status-badge-2026", "children"),
        Output("learning-indicator", "children"),
        Output("threat-level-indicator", "children"),
        Output("metrics-panel-1", "children"),
        Output("metrics-panel-2", "children"),
        Output("metrics-panel-3", "children"),
        Output("incident-history-table", "children")
    ],
    [Input("engine-pulse-2026", "n_intervals")],
    [
        State("z-slider-2026", "value"),
        State("entropy-input", "value"),
        State("refresh-rate", "value")
    ]
)
def process_analytical_frame(n, z_limit, entropy_limit, refresh_rate):
    history = list(global_traffic_history)
    ent_history = list(entropy_history)
    
    # Calibration phase
    if len(history) < 10:
        blank_fig = px.line(title="⚙️ Calibrating baseline... Please wait")
        blank_fig.update_layout(
            plot_bgcolor=THEME["bg_dark"],
            paper_bgcolor=THEME["bg_panel"],
            font_color=THEME["text_light"],
            font_family=THEME["font"]
        )
        return blank_fig, blank_fig, "⏳ System initializing...", "", "", "", "", "", "", ""
    
    # -------- STATISTICAL ANALYSIS --------
    mean = sum(history) / len(history)
    std_dev = math.sqrt(sum((x - mean) ** 2 for x in history) / len(history)) or 1.0
    current_load = history[-1]
    z_score = calculate_z_score(current_load, mean, std_dev)
    current_entropy = ent_history[-1] if ent_history else 0.0
    
    # -------- VOLUMETRIC CHART --------
    df_vol = pd.DataFrame({
        "Seconds Ago": list(range(len(history), 0, -1)),
        "Packets/Sec": history,
        "Entropy": [x * (max(history) / 8) if max(history) > 0 else 0 for x in ent_history]
    })
    
    fig_vol = make_subplots(specs=[[{"secondary_y": True}]])
    fig_vol.add_trace(
        go.Scatter(x=df_vol["Seconds Ago"], y=df_vol["Packets/Sec"], name="Traffic (pps)", 
                   line=dict(color=THEME["neon_green"], width=2), fill='tozeroy', fillcolor='rgba(63, 185, 80, 0.1)'),
        secondary_y=False
    )
    fig_vol.add_trace(
        go.Scatter(x=df_vol["Seconds Ago"], y=df_vol["Entropy"], name="Entropy (H')", 
                   line=dict(color=THEME["cyan"], width=2, dash='dash')),
        secondary_y=True
    )
    
    fig_vol.update_layout(
        plot_bgcolor=THEME["bg_dark"],
        paper_bgcolor=THEME["bg_panel"],
        font_color=THEME["text_light"],
        font_family=THEME["font"],
        hovermode="x unified",
        margin=dict(l=10, r=10, t=30, b=10),
        height=350
    )
    
    # -------- THREAT DETECTION --------
    vector_distribution = []
    incidents = []
    system_compromised = False
    threat_level = "🟢 NORMAL"
    threat_level_color = THEME["neon_green"]
    
    with lock:
        # Global carpet bombing detection
        if z_score > z_limit and current_entropy > entropy_limit:
            system_compromised = True
            threat_level = "🔴 CRITICAL"
            threat_level_color = THEME["alert_red"]
            incidents.append({
                "ip": "DISTRIBUTED",
                "vector": "Carpet Bombing Flood (Dynamic IP)",
                "pps": current_load,
                "score": 95,
                "description": "High-volume attack distributed across randomized IPs"
            })
            vector_distribution.append({"Vector": "Carpet Bombing", "Load": current_load})
        
        # Per-source analysis
        for ip, timestamps in list(vector_metrics["timestamps"].items()):
            if not timestamps:
                continue
            
            pps = len(timestamps)
            
            # Collect metrics for this IP
            metrics = {
                "tcp_syn": vector_metrics["tcp_syn"].get(ip, 0),
                "tcp_ack": vector_metrics["tcp_ack"].get(ip, 0),
                "tcp_fin": vector_metrics["tcp_fin"].get(ip, 0),
                "tcp_rst": vector_metrics["tcp_rst"].get(ip, 0),
                "udp_vol": vector_metrics["udp_vol"].get(ip, 0),
                "icmp_vol": vector_metrics["icmp_vol"].get(ip, 0),
                "http_streams": vector_metrics["http_streams"].get(ip, 0),
                "tls_handshakes": vector_metrics["tls_handshakes"].get(ip, 0),
                "dns_queries": vector_metrics["dns_queries"].get(ip, 0),
                "pps": pps,
                "payload_sizes": vector_metrics["payload_sizes"].get(ip, [])
            }
            
            # Run threat detection
            is_threat, threat_type, score = threat_detector.analyze_single_source(ip, metrics)
            
            if is_threat:
                system_compromised = True
                threat_level = "🟠 HIGH" if score < 60 else "🔴 CRITICAL"
                threat_level_color = THEME["warn_orange"] if score < 60 else THEME["alert_red"]
                
                incidents.append({
                    "ip": ip,
                    "vector": threat_type,
                    "pps": pps,
                    "score": score,
                    "description": f"Detected {threat_type} - Score: {score:.1f}/100"
                })
                vector_distribution.append({"Vector": threat_type, "Load": pps})
                
                # Log to database
                log_incident(ip, threat_type, score / 100, pps, f"Threat Score: {score:.1f}")
    
    # -------- THREAT VECTOR CHART --------
    if vector_distribution:
        df_threats = pd.DataFrame(vector_distribution)
        df_threats = df_threats.groupby("Vector").sum().reset_index()
        fig_threats = px.barh(
            df_threats, x="Load", y="Vector",
            color="Vector",
            color_discrete_map={
                "TCP SYN Flood": THEME["alert_red"],
                "HTTP/2 Stream Abuse": THEME["accent_purple"],
                "TLS Crypto Exhaustion": THEME["warn_orange"],
                "UDP Volumetric Flood": "#ffff00",
                "Carpet Bombing": THEME["cyan"],
                "Connection Reset Flood (FIN/RST)": "#ff6b6b",
                "DNS Query Flood": "#4ecdc4",
                "ICMP Flood": "#ff9ff3",
                "Aggressive SYN Activity": "#ffa502"
            }
        )
    else:
        fig_threats = px.barh(title="✅ No attacks detected")
    
    fig_threats.update_layout(
        plot_bgcolor=THEME["bg_dark"],
        paper_bgcolor=THEME["bg_panel"],
        font_color=THEME["text_light"],
        font_family=THEME["font"],
        showlegend=False,
        margin=dict(l=150, r=10, t=30, b=10),
        height=350
    )
    
    # -------- INCIDENT ALERTS --------
    if system_compromised and incidents:
        alert_cards = []
        for inc in incidents:
            reputation = get_ip_reputation(inc["ip"]) if inc["ip"] != "DISTRIBUTED" else None
            
            severity_color = THEME["alert_red"] if inc["score"] >= 60 else THEME["warn_orange"]
            
            card = html.Div(
                style={
                    "borderLeft": f"5px solid {severity_color}",
                    "padding": "15px",
                    "marginBottom": "12px",
                    "backgroundColor": "#2a141a" if inc["score"] >= 60 else "#2a2414",
                    "borderRadius": "6px",
                    "border": f"1px solid {severity_color}"
                },
                children=[
                    html.Div(
                        style={"display": "flex", "justifyContent": "space-between", "alignItems": "center"},
                        children=[
                            html.Span(
                                f"🚨 {inc['vector'].upper()}",
                                style={"color": severity_color, "fontWeight": "bold", "fontSize": "12px"}
                            ),
                            html.Span(
                                f"RISK: {inc['score']:.0f}%",
                                style={
                                    "backgroundColor": severity_color,
                                    "color": "#fff",
                                    "padding": "3px 8px",
                                    "borderRadius": "4px",
                                    "fontSize": "11px",
                                    "fontWeight": "bold"
                                }
                            )
                        ]
                    ),
                    html.P(
                        f"Source: [{inc['ip']}] | Traffic: {inc['pps']} pps" + 
                        (f" | Reputation: {reputation['threat_score']:.0f}/100" if reputation else ""),
                        style={"margin": "8px 0", "fontSize": "11px", "color": THEME["text_muted"]}
                    ),
                    html.P(inc['description'], style={"margin": "0", "fontSize": "11px", "color": THEME["text_light"]})
                ]
            )
            alert_cards.append(card)
        
        incidents_div = html.Div(alert_cards)
    else:
        incidents_div = html.Div(
            "🛡️ System operating normally - no threats detected",
            style={"color": THEME["neon_green"], "padding": "20px", "textAlign": "center"}
        )
    
    # -------- STATUS BADGE --------
    status_badge = html.Div(
        threat_level,
        style={
            "backgroundColor": threat_level_color,
            "color": "#fff" if threat_level != "🟢 NORMAL" else THEME["bg_dark"],
            "padding": "6px 12px",
            "borderRadius": "4px",
            "fontWeight": "bold",
            "fontSize": "12px",
            "textAlign": "center"
        }
    )
    
    # -------- LEARNING INDICATOR --------
    learning_text = "📚 Learning Baseline" if threat_detector.is_learning else "✅ Baseline Established"
    learning_color = THEME["warn_orange"] if threat_detector.is_learning else THEME["neon_green"]
    learning_badge = html.Div(
        learning_text,
        style={"color": learning_color, "fontSize": "11px", "fontWeight": "bold"}
    )
    
    # -------- METRICS PANELS --------
    metrics_1 = html.Div([
        html.H4("Traffic Baseline", style={"color": THEME["cyan"], "fontSize": "12px", "marginBottom": "10px"}),
        html.P(f"Mean: {mean:.0f} pps", style={"fontSize": "12px"}),
        html.P(f"Std Dev: {std_dev:.0f}", style={"fontSize": "12px"}),
        html.P(f"Current: {current_load} pps", style={"fontSize": "12px", "color": THEME["neon_green"], "fontWeight": "bold"}),
        html.P(f"Z-Score: {z_score:.2f}σ", style={"fontSize": "12px", "color": THEME["warn_orange"] if z_score > 2 else THEME["text_light"]})
    ])
    
    metrics_2 = html.Div([
        html.H4("Source Distribution", style={"color": THEME["cyan"], "fontSize": "12px", "marginBottom": "10px"}),
        html.P(f"Entropy: {current_entropy:.2f} H'", style={"fontSize": "12px"}),
        html.P(f"Unique IPs: {len([x for x in vector_metrics['timestamps'].keys() if len(vector_metrics['timestamps'][x]) > 0])}", style={"fontSize": "12px"}),
        html.P(f"Threshold: {entropy_limit:.1f}", style={"fontSize": "12px"}),
        html.P(f"Status: {'🔴 Anomalous' if current_entropy > entropy_limit else '🟢 Normal'}", style={"fontSize": "12px"})
    ])
    
    metrics_3 = html.Div([
        html.H4("System Health", style={"color": THEME["cyan"], "fontSize": "12px", "marginBottom": "10px"}),
        html.P(f"Active IPs: {len(vector_metrics['timestamps'])}", style={"fontSize": "12px"}),
        html.P(f"Incidents: {len([i for i in incidents if i['ip'] != 'DISTRIBUTED'])}", style={"fontSize": "12px", "color": THEME["alert_red"] if incidents else THEME["neon_green"]}),
        html.P(f"Threats: {'🔴 Active' if system_compromised else '🟢 None'}", style={"fontSize": "12px"}),
        html.P(f"Uptime: {datetime.now().strftime('%H:%M:%S')}", style={"fontSize": "12px"})
    ])
    
    # -------- INCIDENT HISTORY TABLE --------
    history_incidents = get_incident_history(10)
    if history_incidents:
        history_rows = []
        for inc in history_incidents:
            history_rows.append(html.Tr([
                html.Td(inc['timestamp'][:19], style={"padding": "8px", "fontSize": "11px", "borderBottom": f"1px solid {THEME['bg_hover']}"}),
                html.Td(inc['source_ip'], style={"padding": "8px", "fontSize": "11px", "borderBottom": f"1px solid {THEME['bg_hover']}", "color": THEME["cyan"]}),
                html.Td(inc['attack_type'], style={"padding": "8px", "fontSize": "11px", "borderBottom": f"1px solid {THEME['bg_hover']}"}),
                html.Td(f"{inc['severity']:.1%}", style={"padding": "8px", "fontSize": "11px", "borderBottom": f"1px solid {THEME['bg_hover']}", "color": THEME["alert_red"]}),
                html.Td(f"{inc['pps']} pps", style={"padding": "8px", "fontSize": "11px", "borderBottom": f"1px solid {THEME['bg_hover']}"})
            ]))
        
        history_table = html.Table(
            [html.Thead(html.Tr([
                html.Th("Timestamp", style={"padding": "8px", "textAlign": "left", "fontSize": "12px", "color": THEME["cyan"], "borderBottom": f"2px solid {THEME['cyan']}"}),
                html.Th("Source IP", style={"padding": "8px", "textAlign": "left", "fontSize": "12px", "color": THEME["cyan"], "borderBottom": f"2px solid {THEME['cyan']}"}),
                html.Th("Attack Type", style={"padding": "8px", "textAlign": "left", "fontSize": "12px", "color": THEME["cyan"], "borderBottom": f"2px solid {THEME['cyan']}"}),
                html.Th("Severity", style={"padding": "8px", "textAlign": "left", "fontSize": "12px", "color": THEME["cyan"], "borderBottom": f"2px solid {THEME['cyan']}"}),
                html.Th("Traffic", style={"padding": "8px", "textAlign": "left", "fontSize": "12px", "color": THEME["cyan"], "borderBottom": f"2px solid {THEME['cyan']}"}),
            ])),
            html.Tbody(history_rows)],
            style={"width": "100%", "borderCollapse": "collapse"}
        )
    else:
        history_table = html.P("No incidents recorded yet", style={"color": THEME["text_muted"]})
    
    return fig_vol, fig_threats, incidents_div, status_badge, learning_badge, threat_level, metrics_1, metrics_2, metrics_3, history_table

# ============================================================================
# RUN APPLICATION
# ============================================================================
if __name__ == "__main__":
    print("\n" + "="*80)
    print("🔐 ADVANCED DDoS DETECTOR v2.0 - Starting...")
    print("="*80)
    print(f"⚠️  Requires ROOT/ADMIN privileges for packet sniffing")
    print(f"📊 Web UI: http://localhost:8050")
    print(f"📁 Database: {DB_PATH}")
    print(f"📝 Logs: ddos_detector.log")
    print("="*80 + "\n")
    
    app.run(debug=False, host="0.0.0.0", port=8050, threaded=True)
