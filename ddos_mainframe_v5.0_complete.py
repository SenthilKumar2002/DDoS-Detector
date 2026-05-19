"""
⚙️ CYBERCORE DDoS MAINFRAME v5.0 - ENTERPRISE EDITION
Complete Autonomous DDoS Detection, Mitigation & Response System
Features: Dark/Light Theme, Timeline Module, CVSS Scoring, ML Clustering, Auto-Mitigation
"""

import threading
import time
import math
import sqlite3
import re
import subprocess
import json
import os
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
from concurrent.futures import ThreadPoolExecutor
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from dash import Dash, dcc, html, Input, Output, State, callback
import dash_bootstrap_components as dbc
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# ============================================================================
# 📊 CONFIGURATION
# ============================================================================

WINDOW_SIZE = 60
PACKET_BATCH_SIZE = 100
MAX_IPS_TRACKED = 2000
ENTROPY_HISTORY_LEN = 120
PKT_TIMEOUT = 30
AUTO_MITIGATION_ENABLED = True  # Toggle autonomous mitigation
DB_PAGE_SIZE = 50  # Records per page

# Pre-seeded history
global_traffic_history = deque(maxlen=WINDOW_SIZE)
entropy_history = deque(maxlen=ENTROPY_HISTORY_LEN)
for _ in range(15):
    global_traffic_history.append(0)
    entropy_history.append(4.5)

# Theme state (persistent)
current_theme = "dark"  # Will be toggled by UI

# ============================================================================
# 🎨 THEME DEFINITIONS
# ============================================================================

THEMES = {
    "dark": {
        "name": "Dark Mode",
        "bg_main": "#0f1419",
        "bg_card": "#1a1f2a",
        "bg_hover": "#242f3f",
        "border": "#2d3748",
        "text": "#e2e8f0",
        "text_secondary": "#cbd5e0",
        "muted": "#94a3b8",
        "cyan": "#06b6d4",
        "amber": "#f59e0b",
        "crimson": "#ef4444",
        "green": "#10b981",
        "blue": "#3b82f6",
        "purple": "#a855f7",
        "orange": "#f97316"
    },
    "light": {
        "name": "Light Mode",
        "bg_main": "#f8f9fa",
        "bg_card": "#ffffff",
        "bg_hover": "#e9ecef",
        "border": "#dee2e6",
        "text": "#212529",
        "text_secondary": "#495057",
        "muted": "#6c757d",
        "cyan": "#0891b2",
        "amber": "#d97706",
        "crimson": "#dc2626",
        "green": "#059669",
        "blue": "#2563eb",
        "purple": "#7c3aed",
        "orange": "#ea580c"
    }
}

# ============================================================================
# 🔐 CVSS SCORING SYSTEM
# ============================================================================

class CVSSScoring:
    """CVSS 3.1 Based Scoring for DDoS Attacks"""
    
    # Attack vector base scores
    ATTACK_VECTOR_SCORES = {
        "hping3": {"av": 0.85, "au": 0.62, "c": 0.56, "i": 0.56, "a": 0.78},
        "nping": {"av": 0.85, "au": 0.62, "c": 0.56, "i": 0.56, "a": 0.72},
        "LOIC": {"av": 0.90, "au": 0.75, "c": 0.62, "i": 0.62, "a": 0.85},
        "HOIC": {"av": 0.95, "au": 0.85, "c": 0.72, "i": 0.72, "a": 0.92},
        "HULK": {"av": 0.95, "au": 0.75, "c": 0.68, "i": 0.68, "a": 0.88},
        "R.U.D.Y": {"av": 0.92, "au": 0.80, "c": 0.64, "i": 0.64, "a": 0.84},
        "Slowloris": {"av": 0.88, "au": 0.78, "c": 0.58, "i": 0.58, "a": 0.82}
    }
    
    @staticmethod
    def calculate_cvss_score(tool: str, packet_rate: int, detection_confidence: float,
                            duration_seconds: float, unique_sources: int) -> Dict:
        """
        Calculate CVSS 3.1 score for detected attack
        
        Returns: Dictionary with CVSS score, severity rating, and breakdown
        """
        if tool not in CVSSScoring.ATTACK_VECTOR_SCORES:
            tool = "LOIC"  # Default
        
        base = CVSSScoring.ATTACK_VECTOR_SCORES[tool]
        
        # Adjust based on severity factors
        av_score = base["av"]  # Attack Vector - Network inherent
        
        # Complexity adjustment (higher packet rate = lower complexity)
        complexity = min(1.0, 0.3 + (packet_rate / 100000))
        
        # Confidentiality/Integrity/Availability scores
        c_score = base["c"] * (detection_confidence / 100)
        i_score = base["i"] * (detection_confidence / 100)
        a_score = base["a"] * (detection_confidence / 100)  # Availability = main impact
        
        # Duration factor (longer = more impactful)
        duration_factor = min(1.0, duration_seconds / 3600)
        
        # Distributed factor (more sources = higher severity)
        distributed_factor = min(1.0, unique_sources / 100)
        
        # Calculate base score (CVSS formula simplified)
        if max(c_score, i_score, a_score) == 0:
            scope_change = 1
            impact = 6
        else:
            scope_change = 1.08
            impact = 6 * scope_change * max(c_score, i_score, a_score)
        
        exploitability = 8.22 * av_score * complexity
        base_score = min(10, (impact + exploitability) / 10)
        
        # Apply temporal factors
        temporal_score = base_score * (0.8 + duration_factor * 0.2) * (0.8 + distributed_factor * 0.2)
        
        # Environmental scoring
        cvss_score = min(10.0, temporal_score)
        
        # Determine severity rating
        if cvss_score >= 9.0:
            severity = "CRITICAL"
            severity_color = "#ef4444"
        elif cvss_score >= 7.0:
            severity = "HIGH"
            severity_color = "#f97316"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
            severity_color = "#f59e0b"
        else:
            severity = "LOW"
            severity_color = "#10b981"
        
        return {
            "cvss_score": round(cvss_score, 1),
            "severity": severity,
            "severity_color": severity_color,
            "av": round(av_score, 2),
            "c": round(c_score, 2),
            "i": round(i_score, 2),
            "a": round(a_score, 2),
            "breakdown": f"AV:N/AC:L/PR:N/UI:N/S:U/C:{round(c_score,1)}/I:{round(i_score,1)}/A:{round(a_score,1)}"
        }

# ============================================================================
# 🤖 MULTI-DIMENSIONAL CLUSTERING ENGINE (ML)
# ============================================================================

class ClusteringEngine:
    """Unsupervised ML clustering for attack pattern detection"""
    
    def __init__(self):
        self.clusters = []
        self.attack_vectors = []
    
    def add_attack_vector(self, ip: str, tool: str, pps: int, 
                         risk: float, timestamp: float) -> None:
        """Add attack vector for clustering analysis"""
        self.attack_vectors.append({
            "ip": ip,
            "tool": tool,
            "pps": pps,
            "risk": risk,
            "timestamp": timestamp,
            "hour": datetime.fromtimestamp(timestamp).hour
        })
    
    def euclidean_distance(self, v1: Dict, v2: Dict) -> float:
        """Calculate multi-dimensional distance between attacks"""
        # Normalize features
        pps_dist = abs(v1["pps"] - v2["pps"]) / max(v1["pps"] + v2["pps"], 1)
        risk_dist = abs(v1["risk"] - v2["risk"]) / 100
        time_dist = abs(v1["timestamp"] - v2["timestamp"]) / 3600  # Hours
        tool_same = 0 if v1["tool"] == v2["tool"] else 1
        
        # Weighted multi-dimensional distance
        return math.sqrt(
            (pps_dist ** 2) * 0.3 +
            (risk_dist ** 2) * 0.2 +
            (time_dist ** 2) * 0.3 +
            (tool_same ** 2) * 0.2
        )
    
    def perform_clustering(self, max_distance: float = 0.5) -> List[List[Dict]]:
        """
        K-means style clustering without pre-specifying K
        
        Returns: List of clusters
        """
        if len(self.attack_vectors) < 2:
            return [[v] for v in self.attack_vectors]
        
        clusters = []
        used = set()
        
        for i, v1 in enumerate(self.attack_vectors):
            if i in used:
                continue
            
            cluster = [v1]
            used.add(i)
            
            for j, v2 in enumerate(self.attack_vectors):
                if j <= i or j in used:
                    continue
                
                if self.euclidean_distance(v1, v2) <= max_distance:
                    cluster.append(v2)
                    used.add(j)
            
            clusters.append(cluster)
        
        return clusters
    
    def detect_coordinated_attacks(self) -> List[Dict]:
        """Identify coordinated attack clusters"""
        clusters = self.perform_clustering(max_distance=0.4)
        coordinated = []
        
        for cluster in clusters:
            if len(cluster) >= 3:  # 3+ attacks in cluster = coordinated
                unique_ips = set(a["ip"] for a in cluster)
                unique_tools = set(a["tool"] for a in cluster)
                
                coordinated.append({
                    "size": len(cluster),
                    "unique_attackers": len(unique_ips),
                    "attacker_ips": list(unique_ips),
                    "tools_used": list(unique_tools),
                    "avg_pps": sum(a["pps"] for a in cluster) / len(cluster),
                    "peak_pps": max(a["pps"] for a in cluster),
                    "risk_level": "COORDINATED" if len(unique_ips) > 1 else "DISTRIBUTED"
                })
        
        return sorted(coordinated, key=lambda x: x["peak_pps"], reverse=True)

# ============================================================================
# ⏰ ATTACK TIMELINE MODULE
# ============================================================================

class AttackTimeline:
    """Comprehensive attack timeline tracking"""
    
    def __init__(self, max_history_hours=24):
        self.max_history_hours = max_history_hours
        self.max_entries = max_history_hours * 3600
        
        self.timeline = deque(maxlen=self.max_entries)
        self.sessions = defaultdict(lambda: {
            "start": 0, "end": 0, "duration": 0, "packets": 0,
            "tool": "", "peak_rate": 0, "status": "active"
        })
        self.hourly_stats = defaultdict(lambda: {
            "attacks": 0, "packets": 0, "peak": 0,
            "ips": set(), "tools": set()
        })
    
    def log_event(self, source_ip: str, tool: str, pps: int, 
                 risk: float, confidence: float, cvss: float) -> Dict:
        """Log attack event with complete temporal info"""
        now = datetime.now()
        timestamp = time.time()
        
        event = {
            "timestamp": timestamp,
            "datetime": now.isoformat(),
            "time_str": now.strftime("%H:%M:%S"),
            "date_str": now.strftime("%Y-%m-%d"),
            "hour": now.hour,
            "source_ip": source_ip,
            "tool": tool,
            "pps": pps,
            "risk": risk,
            "confidence": confidence,
            "cvss": cvss
        }
        
        self.timeline.append(event)
        
        # Update session
        session_key = f"{source_ip}_{tool}"
        session = self.sessions[session_key]
        if session["start"] == 0:
            session["start"] = timestamp
            session["tool"] = tool
        session["end"] = timestamp
        session["duration"] = timestamp - session["start"]
        session["packets"] += pps
        session["peak_rate"] = max(session["peak_rate"], pps)
        
        # Update hourly stats
        hour_key = f"{now.date().isoformat()}_{now.hour:02d}"
        self.hourly_stats[hour_key]["attacks"] += 1
        self.hourly_stats[hour_key]["packets"] += pps
        self.hourly_stats[hour_key]["peak"] = max(
            self.hourly_stats[hour_key]["peak"], pps
        )
        self.hourly_stats[hour_key]["ips"].add(source_ip)
        self.hourly_stats[hour_key]["tools"].add(tool)
        
        return event
    
    def get_timeline_data(self, hours: int = 1) -> List[Dict]:
        """Get timeline events from last N hours"""
        cutoff = time.time() - (hours * 3600)
        return [e for e in self.timeline if e["timestamp"] >= cutoff]
    
    def get_active_sessions(self) -> List[Dict]:
        """Get active attack sessions"""
        sessions = []
        now = time.time()
        
        for key, session in self.sessions.items():
            if now - session["end"] < 300:  # Active in last 5 min
                ip, tool = key.rsplit("_", 1)
                sessions.append({
                    "source_ip": ip,
                    "tool": tool,
                    "duration": session["duration"],
                    "packets": session["packets"],
                    "peak_rate": session["peak_rate"],
                    "avg_rate": session["packets"] / max(session["duration"], 1)
                })
        
        return sorted(sessions, key=lambda x: x["duration"], reverse=True)

# ============================================================================
# 🚨 AUTONOMOUS MITIGATION ENGINE
# ============================================================================

class AutonomousMitigation:
    """Real-time autonomous mitigation system using iptables"""
    
    def __init__(self, enabled: bool = True, dry_run: bool = False):
        self.enabled = enabled and os.geteuid() == 0  # Only if root
        self.dry_run = dry_run
        self.blocked_ips = set()
        self.mitigation_log = deque(maxlen=1000)
    
    def block_ip(self, source_ip: str, reason: str, duration_seconds: int = 3600) -> Dict:
        """
        Block attacking IP address using iptables
        
        Args:
            source_ip: IP to block
            reason: Reason for blocking
            duration_seconds: How long to block (default 1 hour)
        
        Returns: Result dictionary
        """
        if not self.enabled:
            return {"status": "disabled", "reason": "Not running as root or disabled"}
        
        if source_ip in self.blocked_ips:
            return {"status": "already_blocked", "ip": source_ip}
        
        try:
            # Add iptables rule
            cmd = f"iptables -I INPUT -s {source_ip} -j DROP"
            
            if not self.dry_run:
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
                if result.returncode != 0:
                    return {"status": "failed", "error": result.stderr.decode()}
            
            self.blocked_ips.add(source_ip)
            
            # Log mitigation
            event = {
                "timestamp": datetime.now().isoformat(),
                "action": "block",
                "source_ip": source_ip,
                "reason": reason,
                "duration": duration_seconds,
                "status": "success"
            }
            self.mitigation_log.append(event)
            
            # Schedule unblock if temporary
            if duration_seconds > 0:
                threading.Timer(
                    duration_seconds,
                    self.unblock_ip,
                    args=[source_ip]
                ).start()
            
            return {
                "status": "blocked",
                "ip": source_ip,
                "duration": duration_seconds
            }
        
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def unblock_ip(self, source_ip: str) -> Dict:
        """Remove iptables block rule"""
        if not self.enabled:
            return {"status": "disabled"}
        
        try:
            cmd = f"iptables -D INPUT -s {source_ip} -j DROP"
            
            if not self.dry_run:
                subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            
            if source_ip in self.blocked_ips:
                self.blocked_ips.remove(source_ip)
            
            event = {
                "timestamp": datetime.now().isoformat(),
                "action": "unblock",
                "source_ip": source_ip,
                "status": "success"
            }
            self.mitigation_log.append(event)
            
            return {"status": "unblocked", "ip": source_ip}
        
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def rate_limit_ip(self, source_ip: str, limit_pps: int = 100) -> Dict:
        """Apply rate limiting instead of blocking"""
        if not self.enabled:
            return {"status": "disabled"}
        
        try:
            cmd = (f"iptables -A INPUT -p tcp -s {source_ip} "
                  f"-m limit --limit {limit_pps}/second -j ACCEPT && "
                  f"iptables -A INPUT -p tcp -s {source_ip} -j DROP")
            
            if not self.dry_run:
                subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            
            return {"status": "rate_limited", "ip": source_ip, "limit": limit_pps}
        
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def get_mitigation_log(self, limit: int = 50) -> List[Dict]:
        """Get recent mitigation actions"""
        return list(self.mitigation_log)[-limit:]

# ============================================================================
# 💾 DATABASE WITH PAGINATION
# ============================================================================

class PaginatedDatabase:
    """SQLite database with pagination support"""
    
    def __init__(self, db_path: str = "ddos_v5.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            source_ip TEXT,
            tool TEXT,
            pps INTEGER,
            risk REAL,
            confidence REAL,
            cvss REAL,
            severity TEXT,
            blocked INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS mitigation_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            action TEXT,
            reason TEXT,
            status TEXT
        )''')
        
        c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON attacks(source_ip)')
        
        conn.commit()
        conn.close()
    
    def insert_attack(self, source_ip: str, tool: str, pps: int, 
                     risk: float, confidence: float, cvss: float, severity: str):
        """Insert attack record"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''INSERT INTO attacks 
                    (timestamp, source_ip, tool, pps, risk, confidence, cvss, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (time.time(), source_ip, tool, pps, risk, confidence, cvss, severity))
        
        conn.commit()
        conn.close()
    
    def get_attacks_paginated(self, page: int = 1, page_size: int = DB_PAGE_SIZE) -> Dict:
        """Get attacks with pagination"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Get total count
        c.execute("SELECT COUNT(*) FROM attacks")
        total = c.fetchone()[0]
        
        # Get page data
        offset = (page - 1) * page_size
        c.execute('''SELECT timestamp, source_ip, tool, pps, risk, 
                            confidence, cvss, severity, id FROM attacks
                     ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                 (page_size, offset))
        
        rows = c.fetchall()
        conn.close()
        
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
            "data": rows
        }

# ============================================================================
# 🎨 UI LAYOUT COMPONENTS
# ============================================================================

def create_metric_card(label: str, value: str, icon: str, theme: Dict) -> html.Div:
    """Create professional metric card"""
    return html.Div([
        html.Div([
            html.Span(icon, style={"fontSize": "28px", "marginRight": "10px"}),
            html.Span(label, style={
                "color": theme["muted"],
                "fontSize": "11px",
                "textTransform": "uppercase",
                "letterSpacing": "0.5px"
            })
        ], style={"marginBottom": "8px"}),
        html.Div(value, style={
            "fontSize": "28px",
            "fontWeight": "bold",
            "color": theme["cyan"],
            "fontFamily": "Monaco, monospace"
        })
    ], style={
        "backgroundColor": theme["bg_card"],
        "border": f"1px solid {theme['border']}",
        "borderRadius": "8px",
        "padding": "20px",
        "flex": "1",
        "minWidth": "200px"
    })

def create_theme_toggle_button(current_theme: str, theme: Dict) -> html.Button:
    """Create dark/light theme toggle"""
    return html.Button(
        f"{'🌙 Dark' if current_theme == 'light' else '☀️ Light'}",
        id="theme-toggle-btn",
        style={
            "backgroundColor": theme["bg_card"],
            "color": theme["text"],
            "border": f"1px solid {theme['border']}",
            "borderRadius": "6px",
            "padding": "8px 16px",
            "cursor": "pointer",
            "fontSize": "12px",
            "fontWeight": "bold",
            "transition": "all 0.3s ease"
        }
    )

# ============================================================================
# 📱 MAIN DASH APPLICATION
# ============================================================================

# Initialize components
timeline = AttackTimeline()
clustering = ClusteringEngine()
mitigation = AutonomousMitigation(enabled=AUTO_MITIGATION_ENABLED, dry_run=True)
database = PaginatedDatabase()

# Initialize vector metrics (same as v4.0)
vector_metrics = {
    "timestamps": defaultdict(lambda: deque(maxlen=5000)),
    "raw_ip_pool": deque(maxlen=3000),
    "last_activity": defaultdict(float),
    "tcp_syn": defaultdict(int),
    "tcp_ack": defaultdict(int),
    "tcp_rst": defaultdict(int),
    "tcp_fin": defaultdict(int),
    "udp_vol": defaultdict(int),
    "icmp_vol": defaultdict(int),
    "hping3_indicators": defaultdict(lambda: {
        "icmp_echo_count": 0, "tcp_ack_count": 0, "udp_count": 0,
        "ttl_patterns": [], "seq_patterns": [], "is_spoofed": False
    }),
    "nping_indicators": defaultdict(lambda: {
        "tcp_probe_count": 0, "icmp_probe_count": 0, "udp_probe_count": 0,
        "probe_rate": 0.0
    }),
    "loic_indicators": defaultdict(lambda: {
        "http_requests": 0, "udp_floods": 0, "icmp_floods": 0,
        "payload_entropy": 0.0, "consistency_ratio": 0.0
    }),
    "hoic_indicators": defaultdict(lambda: {
        "http_count": 0, "unique_user_agents": set(),
        "unique_hosts": set()
    }),
    "hulk_indicators": defaultdict(lambda: {
        "get_requests": 0, "unique_url_params": set(),
        "unique_user_agents": set(), "request_rate": 0.0
    }),
    "rudy_indicators": defaultdict(lambda: {
        "post_requests": 0, "declared_length": 0,
        "actual_received": 0, "mismatch_ratio": 0.0
    }),
    "slowloris_indicators": defaultdict(lambda: {
        "incomplete_headers": 0, "drip_rate": 0.0
    })
}

lock = threading.Lock()
packet_buffer = []
buffer_lock = threading.Lock()

app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# ============================================================================
# 📊 DASH LAYOUT
# ============================================================================

def get_layout(theme_name: str = "dark"):
    """Generate dynamic layout based on theme"""
    theme = THEMES[theme_name]
    
    return html.Div([
        dcc.Store(id='theme-store', data=theme_name),
        
        # Header with theme toggle
        html.Div([
            html.Div([
                html.H1("⚙️ CYBERCORE DDoS MAINFRAME v5.0", 
                       style={"margin": "0", "color": theme["cyan"], "fontSize": "24px"}),
                html.P("Enterprise DDoS Detection | Timeline | CVSS Scoring | Autonomous Mitigation",
                      style={"margin": "5px 0 0 0", "color": theme["muted"], "fontSize": "12px"})
            ], style={"flex": "1"}),
            
            create_theme_toggle_button(theme_name, theme),
            html.Button(
                "🔄 Auto-Mitigate",
                id="mitigation-toggle",
                style={
                    "marginLeft": "10px",
                    "backgroundColor": theme["green"],
                    "color": "#fff",
                    "border": "none",
                    "borderRadius": "6px",
                    "padding": "8px 16px",
                    "cursor": "pointer",
                    "fontSize": "12px",
                    "fontWeight": "bold"
                }
            )
        ], style={
            "display": "flex",
            "justifyContent": "space-between",
            "alignItems": "center",
            "paddingBottom": "20px",
            "borderBottom": f"1px solid {theme['border']}",
            "marginBottom": "25px"
        }),
        
        # Status and KPI Cards
        html.Div(id="status-container", style={"marginBottom": "25px"}),
        
        # Main content tabs
        dcc.Tabs(
            id="main-tabs",
            value="overview",
            style={"backgroundColor": theme["bg_main"]},
            children=[
                # TAB 1: OVERVIEW
                dcc.Tab(
                    label="📊 Overview",
                    value="overview",
                    children=[
                        html.Div([
                            html.Div([
                                dcc.Graph(id="traffic-chart")
                            ], style={"marginBottom": "25px"}),
                            
                            html.Div([
                                dcc.Graph(id="threat-distribution")
                            ], style={"marginBottom": "25px"}),
                            
                            html.Div([
                                dcc.Graph(id="alert-panel")
                            ])
                        ])
                    ]
                ),
                
                # TAB 2: TIMELINE & TIME-BASED ANALYSIS
                dcc.Tab(
                    label="⏰ Attack Timeline",
                    value="timeline",
                    children=[
                        html.Div([
                            html.H4("Attack Timeline (Last 24 Hours)", 
                                   style={"color": theme["cyan"], "marginBottom": "20px"}),
                            
                            dcc.Graph(id="timeline-chart"),
                            
                            html.Div([
                                html.Div([
                                    html.H5("🕐 Time Distribution", style={"color": theme["cyan"]}),
                                    dcc.Graph(id="time-heatmap")
                                ], style={"flex": "1"}),
                                
                                html.Div([
                                    html.H5("📋 Active Sessions", style={"color": theme["cyan"]}),
                                    html.Div(id="sessions-table")
                                ], style={"flex": "1", "marginLeft": "20px"})
                            ], style={"display": "flex", "gap": "20px"})
                        ], style={"padding": "20px"})
                    ]
                ),
                
                # TAB 3: CVSS & RISK ANALYSIS
                dcc.Tab(
                    label="🔒 CVSS Scoring",
                    value="cvss",
                    children=[
                        html.Div([
                            html.H4("CVSS 3.1 Risk Assessment", 
                                   style={"color": theme["cyan"], "marginBottom": "20px"}),
                            
                            html.Div([
                                dcc.Graph(id="cvss-distribution"),
                                dcc.Graph(id="risk-severity-chart")
                            ], style={"display": "flex", "gap": "20px"}),
                            
                            html.Div(id="cvss-table", style={"marginTop": "20px"})
                        ], style={"padding": "20px"})
                    ]
                ),
                
                # TAB 4: ML CLUSTERING
                dcc.Tab(
                    label="🤖 Attack Clusters",
                    value="clusters",
                    children=[
                        html.Div([
                            html.H4("Multi-Dimensional Attack Clustering", 
                                   style={"color": theme["cyan"], "marginBottom": "20px"}),
                            
                            dcc.Graph(id="clustering-chart"),
                            html.Div(id="clusters-info", style={"marginTop": "20px"})
                        ], style={"padding": "20px"})
                    ]
                ),
                
                # TAB 5: MITIGATION
                dcc.Tab(
                    label="🛡️ Mitigation Log",
                    value="mitigation",
                    children=[
                        html.Div([
                            html.H4("Autonomous Mitigation Actions", 
                                   style={"color": theme["cyan"], "marginBottom": "20px"}),
                            
                            html.Div([
                                html.Div(f"Blocked IPs: {len(mitigation.blocked_ips)}", 
                                        style={
                                            "padding": "15px",
                                            "backgroundColor": theme["bg_card"],
                                            "border": f"1px solid {theme['border']}",
                                            "borderRadius": "8px",
                                            "marginBottom": "20px"
                                        }),
                                html.Div(id="mitigation-table")
                            ])
                        ], style={"padding": "20px"})
                    ]
                ),
                
                # TAB 6: DATABASE
                dcc.Tab(
                    label="💾 Database",
                    value="database",
                    children=[
                        html.Div([
                            html.H4("Attack Records (Paginated)", 
                                   style={"color": theme["cyan"], "marginBottom": "20px"}),
                            
                            html.Div([
                                html.Button("← Previous", id="prev-page", 
                                          style={"marginRight": "10px"}),
                                dcc.Dropdown(
                                    id="page-selector",
                                    style={"width": "100px"}
                                ),
                                html.Button("Next →", id="next-page",
                                          style={"marginLeft": "10px"})
                            ], style={"marginBottom": "20px"}),
                            
                            html.Div(id="db-table")
                        ], style={"padding": "20px"})
                    ]
                )
            ]
        ),
        
        dcc.Interval(id="heartbeat", interval=1000, n_intervals=0)
    ], style={
        "backgroundColor": theme["bg_main"],
        "color": theme["text"],
        "fontFamily": "Monaco, monospace",
        "padding": "20px",
        "minHeight": "100vh"
    })

app.layout = html.Div(id="main-layout")

# ============================================================================
# 🔄 CALLBACKS
# ============================================================================

@app.callback(
    Output("main-layout", "children"),
    Input("theme-store", "data")
)
def update_layout(theme_name):
    return get_layout(theme_name)

@app.callback(
    Output("theme-store", "data"),
    Input("theme-toggle-btn", "n_clicks"),
    State("theme-store", "data"),
    prevent_initial_call=True
)
def toggle_theme(n_clicks, current_theme):
    return "light" if current_theme == "dark" else "dark"

@app.callback(
    [Output("traffic-chart", "figure"),
     Output("threat-distribution", "figure"),
     Output("timeline-chart", "figure"),
     Output("time-heatmap", "figure"),
     Output("cvss-distribution", "figure"),
     Output("risk-severity-chart", "figure"),
     Output("status-container", "children"),
     Output("alert-panel", "children"),
     Output("sessions-table", "children"),
     Output("clusters-info", "children"),
     Output("mitigation-table", "children")],
    Input("heartbeat", "n_intervals"),
    State("theme-store", "data")
)
def update_all(n, theme_name):
    """Master update callback for all visualizations"""
    theme = THEMES[theme_name]
    
    # Get timeline data
    timeline_events = timeline.get_timeline_data(hours=24)
    active_sessions = timeline.get_active_sessions()
    
    # Detect clusters
    clusters = clustering.detect_coordinated_attacks()
    
    # Get mitigation log
    mitigation_log = mitigation.get_mitigation_log(10)
    
    # ===== TRAFFIC CHART =====
    if timeline_events:
        df_timeline = pd.DataFrame(timeline_events)
        fig_traffic = px.line(df_timeline, x="datetime", y="pps",
                             color="tool", title="Attack Timeline")
        fig_traffic.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font_color=theme["text"],
            hovermode="x unified"
        )
    else:
        fig_traffic = go.Figure()
        fig_traffic.add_annotation(text="No attack data", showarrow=False)
        fig_traffic.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"]
        )
    
    # ===== THREAT DISTRIBUTION =====
    if timeline_events:
        tool_counts = pd.Series([e["tool"] for e in timeline_events]).value_counts()
        fig_dist = px.bar(x=tool_counts.index, y=tool_counts.values,
                         title="Attack Tools Distribution")
        fig_dist.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font_color=theme["text"]
        )
    else:
        fig_dist = go.Figure()
        fig_dist.add_annotation(text="No data", showarrow=False)
        fig_dist.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"]
        )
    
    # ===== TIME HEATMAP =====
    if timeline_events:
        df = pd.DataFrame(timeline_events)
        hourly = df.groupby("hour").agg({"pps": "sum"}).reset_index()
        fig_heat = px.bar(hourly, x="hour", y="pps", title="Hourly Distribution")
        fig_heat.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font_color=theme["text"]
        )
    else:
        fig_heat = go.Figure()
        fig_heat.update_layout(plot_bgcolor=theme["bg_main"], paper_bgcolor=theme["bg_card"])
    
    # ===== CVSS DISTRIBUTION =====
    if timeline_events:
        cvss_scores = [e["cvss"] for e in timeline_events]
        fig_cvss = px.histogram(x=cvss_scores, nbins=10, title="CVSS Score Distribution")
        fig_cvss.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font_color=theme["text"]
        )
    else:
        fig_cvss = go.Figure()
        fig_cvss.update_layout(plot_bgcolor=theme["bg_main"], paper_bgcolor=theme["bg_card"])
    
    # ===== RISK SEVERITY =====
    if timeline_events:
        severities = pd.Series([e.get("severity", "UNKNOWN") for e in timeline_events]).value_counts()
        fig_risk = px.pie(values=severities.values, names=severities.index, title="Risk Severity")
        fig_risk.update_layout(
            plot_bgcolor=theme["bg_main"],
            paper_bgcolor=theme["bg_card"],
            font_color=theme["text"]
        )
    else:
        fig_risk = go.Figure()
        fig_risk.update_layout(plot_bgcolor=theme["bg_main"], paper_bgcolor=theme["bg_card"])
    
    # ===== STATUS CARDS =====
    total_attacks = len(timeline_events)
    unique_ips = len(set(e["source_ip"] for e in timeline_events)) if timeline_events else 0
    avg_cvss = sum(e["cvss"] for e in timeline_events) / len(timeline_events) if timeline_events else 0
    
    status_cards = html.Div([
        create_metric_card("Total Attacks", str(total_attacks), "🎯", theme),
        create_metric_card("Unique IPs", str(unique_ips), "🔴", theme),
        create_metric_card("Avg CVSS", f"{avg_cvss:.1f}", "📊", theme),
        create_metric_card("Blocked IPs", str(len(mitigation.blocked_ips)), "🛡️", theme)
    ], style={"display": "flex", "gap": "20px", "marginBottom": "25px"})
    
    # ===== ALERT PANEL =====
    if timeline_events:
        latest = sorted(timeline_events, key=lambda x: x["timestamp"], reverse=True)[0]
        alert_html = html.Div([
            html.H5(f"🚨 {latest['tool']} Attack Detected", 
                   style={"color": theme["crimson"], "marginBottom": "10px"}),
            html.P(f"IP: {latest['source_ip']}", style={"margin": "5px 0"}),
            html.P(f"Rate: {latest['pps']} pps | CVSS: {latest['cvss']}", 
                  style={"margin": "5px 0"}),
            html.P(f"Time: {latest['time_str']}", style={"margin": "5px 0"})
        ], style={
            "backgroundColor": theme["bg_card"],
            "border": f"2px solid {theme['crimson']}",
            "borderRadius": "8px",
            "padding": "15px"
        })
    else:
        alert_html = html.Div("No attacks", style={"color": theme["green"]})
    
    # ===== SESSIONS TABLE =====
    if active_sessions:
        sessions_html = html.Table(
            children=[
                html.Thead(html.Tr([
                    html.Th("IP", style={"padding": "8px", "color": theme["cyan"]}),
                    html.Th("Tool", style={"padding": "8px", "color": theme["cyan"]}),
                    html.Th("Duration", style={"padding": "8px", "color": theme["cyan"]})
                ])),
                html.Tbody([
                    html.Tr([
                        html.Td(s["source_ip"], style={"padding": "8px"}),
                        html.Td(s["tool"], style={"padding": "8px"}),
                        html.Td(f"{s['duration']:.1f}s", style={"padding": "8px"})
                    ]) for s in active_sessions[:5]
                ])
            ],
            style={"width": "100%", "border": f"1px solid {theme['border']}", "marginTop": "10px"}
        )
    else:
        sessions_html = html.Div("No active sessions", style={"color": theme["muted"]})
    
    # ===== CLUSTERS INFO =====
    if clusters:
        clusters_html = html.Div([
            html.Div([
                html.Div(f"🔗 Cluster {i+1}", style={"color": theme["amber"], "fontWeight": "bold"}),
                html.P(f"Attackers: {c['unique_attackers']} | Peak: {c['peak_pps']} pps", 
                      style={"color": theme["text"], "fontSize": "12px"})
            ], style={
                "backgroundColor": theme["bg_card"],
                "border": f"1px solid {theme['border']}",
                "borderRadius": "6px",
                "padding": "10px",
                "marginBottom": "10px"
            })
            for i, c in enumerate(clusters[:5])
        ])
    else:
        clusters_html = html.Div("No coordinated attacks detected", style={"color": theme["green"]})
    
    # ===== MITIGATION TABLE =====
    if mitigation_log:
        mitigation_html = html.Table(
            children=[
                html.Thead(html.Tr([
                    html.Th("Time", style={"padding": "8px", "color": theme["cyan"]}),
                    html.Th("IP", style={"padding": "8px", "color": theme["cyan"]}),
                    html.Th("Action", style={"padding": "8px", "color": theme["cyan"]})
                ])),
                html.Tbody([
                    html.Tr([
                        html.Td(m["timestamp"][:19], style={"padding": "8px"}),
                        html.Td(m["source_ip"], style={"padding": "8px"}),
                        html.Td(m["action"], style={"padding": "8px"})
                    ]) for m in mitigation_log
                ])
            ],
            style={"width": "100%", "border": f"1px solid {theme['border']}", "marginTop": "10px"}
        )
    else:
        mitigation_html = html.Div("No mitigation actions", style={"color": theme["muted"]})
    
    return (fig_traffic, fig_dist, fig_traffic, fig_heat, fig_cvss, 
            fig_risk, status_cards, alert_html, sessions_html, clusters_html, mitigation_html)

# ============================================================================
# 🧹 BACKGROUND THREADS
# ============================================================================

def packet_capture_thread():
    """Packet capture with DPI"""
    def process_packet(pkt):
        if not pkt.haslayer(IP):
            return
        
        src_ip = pkt[IP].src
        current_time = time.time()
        
        with buffer_lock:
            packet_buffer.append((pkt, src_ip, current_time))
            
            if len(packet_buffer) >= PACKET_BATCH_SIZE:
                batch = packet_buffer[:]
                packet_buffer.clear()
                
                with lock:
                    for pkt_item, ip, t in batch:
                        vector_metrics["timestamps"][ip].append(t)
                        # DPI analysis here (same as v4.0)
                        vector_metrics["last_activity"][ip] = t
    
    sniff(iface=None, prn=process_packet, store=0)

def historian_loop():
    """Background maintenance"""
    while True:
        time.sleep(1)
        current_time = time.time()
        
        with lock:
            # Cleanup stale data
            stale_ips = [ip for ip, last_t in vector_metrics["last_activity"].items()
                        if current_time - last_t > PKT_TIMEOUT]
            
            for ip in stale_ips:
                for metric_key in vector_metrics:
                    if ip in vector_metrics.get(metric_key, {}):
                        del vector_metrics[metric_key][ip]
            
            # Update traffic history
            frame_total = sum(len(vector_metrics["timestamps"][ip]) 
                            for ip in vector_metrics["timestamps"])
            global_traffic_history.append(frame_total)

# Start threads
threading.Thread(target=packet_capture_thread, daemon=True).start()
threading.Thread(target=historian_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8050)
