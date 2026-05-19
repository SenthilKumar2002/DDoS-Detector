"""
⏰ ATTACK TIMELINE MODULE v1.0
Advanced Temporal Analysis & Time-Series Attack Tracking
Integrates with CYBERCORE DDoS MAINFRAME v4.0
"""

import time
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Dict, List, Tuple, Optional
import math

class AttackTimeline:
    """Comprehensive attack timeline and temporal analysis engine"""
    
    def __init__(self, max_history_hours=24):
        """
        Initialize attack timeline tracking
        
        Args:
            max_history_hours: Keep timeline data for this many hours (default 24)
        """
        self.max_history_hours = max_history_hours
        self.max_entries = max_history_hours * 3600  # 1 entry per second max
        
        # Timeline data structures
        self.attack_timeline = deque(maxlen=self.max_entries)  # Chronological attack log
        self.attack_intervals = defaultdict(lambda: deque(maxlen=1000))  # Per-IP attack intervals
        self.attack_bursts = defaultdict(list)  # Burst detection per IP
        self.tool_timeline = defaultdict(lambda: deque(maxlen=500))  # Per-tool timeline
        
        # Attack session tracking
        self.active_sessions = defaultdict(lambda: {
            "start_time": 0.0,
            "last_activity": 0.0,
            "duration": 0.0,
            "packet_count": 0,
            "peak_rate": 0,
            "attack_type": "",
            "status": "active"  # active, paused, concluded
        })
        
        # Temporal statistics
        self.hourly_stats = defaultdict(lambda: {
            "attack_count": 0,
            "total_packets": 0,
            "peak_rate_pps": 0,
            "unique_attackers": set(),
            "tools_used": set()
        })
        
        # Attack pattern detection
        self.recurring_patterns = defaultdict(list)  # Recurring attack patterns
        self.attack_clusters = []  # Temporally close attacks
    
    def log_attack_event(self, source_ip: str, tool_name: str, 
                        packet_rate: int, risk_score: float, 
                        confidence: float, timestamp: Optional[float] = None) -> Dict:
        """
        Log an attack event with complete temporal information
        
        Args:
            source_ip: Attacker IP address
            tool_name: Detected attack tool (hping3, LOIC, etc.)
            packet_rate: Current packet rate (pps)
            risk_score: Risk severity (0-100)
            confidence: Detection confidence (0-100)
            timestamp: Unix timestamp (defaults to now)
        
        Returns:
            Dictionary with attack event details
        """
        if timestamp is None:
            timestamp = time.time()
        
        dt = datetime.fromtimestamp(timestamp)
        event = {
            "timestamp": timestamp,
            "datetime": dt.isoformat(),
            "source_ip": source_ip,
            "tool": tool_name,
            "pps": packet_rate,
            "risk": risk_score,
            "confidence": confidence,
            "hour": dt.hour,
            "date": dt.date().isoformat(),
            "day_of_week": dt.strftime("%A"),
            "time_of_day": dt.strftime("%H:%M:%S"),
            "unix_time": timestamp
        }
        
        # Add to main timeline
        self.attack_timeline.append(event)
        
        # Update IP-specific timeline
        self.attack_intervals[source_ip].append(timestamp)
        
        # Update tool-specific timeline
        self.tool_timeline[tool_name].append(event)
        
        # Update hourly statistics
        hour_key = f"{dt.date().isoformat()}_{dt.hour}"
        self.hourly_stats[hour_key]["attack_count"] += 1
        self.hourly_stats[hour_key]["total_packets"] += packet_rate
        self.hourly_stats[hour_key]["peak_rate_pps"] = max(
            self.hourly_stats[hour_key]["peak_rate_pps"],
            packet_rate
        )
        self.hourly_stats[hour_key]["unique_attackers"].add(source_ip)
        self.hourly_stats[hour_key]["tools_used"].add(tool_name)
        
        # Update session tracking
        self._update_session(source_ip, tool_name, packet_rate, risk_score, timestamp)
        
        return event
    
    def _update_session(self, source_ip: str, tool_name: str, 
                       packet_rate: int, risk_score: float, 
                       timestamp: float) -> None:
        """Update attack session tracking"""
        session_key = f"{source_ip}_{tool_name}"
        session = self.active_sessions[session_key]
        
        if session["start_time"] == 0:
            # New session
            session["start_time"] = timestamp
            session["attack_type"] = tool_name
            session["status"] = "active"
        
        session["last_activity"] = timestamp
        session["duration"] = timestamp - session["start_time"]
        session["packet_count"] += packet_rate
        session["peak_rate"] = max(session["peak_rate"], packet_rate)
    
    def detect_attack_bursts(self, source_ip: str, 
                            threshold_pps: int = 100,
                            window_seconds: int = 10) -> List[Dict]:
        """
        Detect sudden burst patterns in attack traffic
        
        Args:
            source_ip: IP to analyze
            threshold_pps: Packet rate threshold for burst detection
            window_seconds: Time window for burst analysis
        
        Returns:
            List of detected burst events
        """
        intervals = list(self.attack_intervals[source_ip])
        if len(intervals) < 2:
            return []
        
        current_time = time.time()
        bursts = []
        
        # Analyze packet arrival times in windows
        burst_start = None
        burst_packets = 0
        
        for i, ts in enumerate(intervals):
            if current_time - ts > window_seconds:
                continue
            
            if burst_start is None:
                burst_start = ts
            
            burst_packets += 1
            
            # Check if burst rate exceeds threshold
            burst_duration = ts - burst_start
            if burst_duration > 0:
                burst_rate = burst_packets / burst_duration
                if burst_rate >= threshold_pps:
                    bursts.append({
                        "start": burst_start,
                        "end": ts,
                        "duration": burst_duration,
                        "packets": burst_packets,
                        "rate": burst_rate,
                        "intensity": "EXTREME" if burst_rate > threshold_pps * 2 else "HIGH"
                    })
                    burst_start = None
                    burst_packets = 0
        
        return bursts
    
    def analyze_attack_patterns(self, source_ip: str) -> Dict:
        """
        Analyze temporal patterns for a specific attacker
        
        Args:
            source_ip: IP to analyze
        
        Returns:
            Pattern analysis dictionary
        """
        intervals = list(self.attack_intervals[source_ip])
        if len(intervals) < 3:
            return {}
        
        # Calculate inter-packet timing
        deltas = []
        for i in range(1, len(intervals)):
            delta = intervals[i] - intervals[i-1]
            if delta > 0:
                deltas.append(delta)
        
        if not deltas:
            return {}
        
        avg_delta = sum(deltas) / len(deltas)
        variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
        std_dev = math.sqrt(variance)
        
        return {
            "total_events": len(intervals),
            "time_span": intervals[-1] - intervals[0] if intervals else 0,
            "avg_interval": avg_delta,
            "std_deviation": std_dev,
            "min_interval": min(deltas),
            "max_interval": max(deltas),
            "regularity": "HIGH" if std_dev < avg_delta * 0.3 else "VARIABLE",
            "pattern_type": self._classify_pattern(deltas)
        }
    
    def _classify_pattern(self, deltas: List[float]) -> str:
        """Classify attack timing pattern"""
        if not deltas:
            return "UNKNOWN"
        
        # Check for periodic pattern
        avg = sum(deltas) / len(deltas)
        variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
        cv = math.sqrt(variance) / avg if avg > 0 else 0
        
        if cv < 0.1:
            return "CLOCKWORK"  # Very regular
        elif cv < 0.3:
            return "PERIODIC"  # Fairly regular
        elif cv < 0.7:
            return "BURSTY"  # Irregular bursts
        else:
            return "RANDOM"  # Highly random
    
    def get_timeline_summary(self, hours: int = 1) -> Dict:
        """
        Get summary of attacks in specified time window
        
        Args:
            hours: Number of hours to summarize (default 1)
        
        Returns:
            Summary statistics
        """
        current_time = time.time()
        cutoff_time = current_time - (hours * 3600)
        
        # Filter recent events
        recent_events = [e for e in self.attack_timeline 
                        if e["timestamp"] >= cutoff_time]
        
        if not recent_events:
            return {
                "period_hours": hours,
                "attack_count": 0,
                "unique_ips": 0,
                "unique_tools": 0,
                "total_packets": 0,
                "peak_rate": 0,
                "earliest": None,
                "latest": None
            }
        
        # Calculate metrics
        unique_ips = set(e["source_ip"] for e in recent_events)
        unique_tools = set(e["tool"] for e in recent_events)
        total_packets = sum(e["pps"] for e in recent_events)
        peak_rate = max(e["pps"] for e in recent_events)
        
        return {
            "period_hours": hours,
            "attack_count": len(recent_events),
            "unique_ips": len(unique_ips),
            "unique_tools": len(unique_tools),
            "tools_list": list(unique_tools),
            "total_packets": total_packets,
            "peak_rate": peak_rate,
            "avg_rate": total_packets / len(recent_events) if recent_events else 0,
            "earliest": datetime.fromtimestamp(min(e["timestamp"] for e in recent_events)).isoformat(),
            "latest": datetime.fromtimestamp(max(e["timestamp"] for e in recent_events)).isoformat()
        }
    
    def get_attack_sessions(self, filter_status: str = None) -> List[Dict]:
        """
        Get all active attack sessions
        
        Args:
            filter_status: Filter by status ('active', 'paused', 'concluded')
        
        Returns:
            List of session summaries
        """
        sessions_list = []
        current_time = time.time()
        
        for session_key, session in self.active_sessions.items():
            if filter_status and session["status"] != filter_status:
                continue
            
            # Mark concluded sessions (no activity for 5 minutes)
            if current_time - session["last_activity"] > 300:
                session["status"] = "concluded"
            
            source_ip, tool = session_key.rsplit("_", 1)
            
            session_summary = {
                "source_ip": source_ip,
                "tool": tool,
                "start_time": datetime.fromtimestamp(session["start_time"]).isoformat(),
                "last_activity": datetime.fromtimestamp(session["last_activity"]).isoformat(),
                "duration_seconds": session["duration"],
                "total_packets": session["packet_count"],
                "peak_rate_pps": session["peak_rate"],
                "avg_rate_pps": session["packet_count"] / session["duration"] if session["duration"] > 0 else 0,
                "status": session["status"]
            }
            sessions_list.append(session_summary)
        
        # Sort by duration (longest first)
        return sorted(sessions_list, key=lambda x: x["duration_seconds"], reverse=True)
    
    def get_timeline_csv(self, hours: int = 24) -> str:
        """
        Export timeline as CSV for external analysis
        
        Args:
            hours: Number of hours to export
        
        Returns:
            CSV-formatted string
        """
        current_time = time.time()
        cutoff_time = current_time - (hours * 3600)
        
        recent_events = [e for e in self.attack_timeline 
                        if e["timestamp"] >= cutoff_time]
        
        if not recent_events:
            return "timestamp,source_ip,tool,pps,risk,confidence,time_of_day\n"
        
        lines = ["timestamp,source_ip,tool,pps,risk,confidence,time_of_day"]
        for event in recent_events:
            line = (f"{event['unix_time']},{event['source_ip']},"
                   f"{event['tool']},{event['pps']},{event['risk']},"
                   f"{event['confidence']},{event['time_of_day']}")
            lines.append(line)
        
        return "\n".join(lines)
    
    def get_hourly_distribution(self, days: int = 7) -> Dict:
        """
        Get attack distribution across hours (heat map data)
        
        Args:
            days: Number of days to analyze
        
        Returns:
            Hourly distribution statistics
        """
        distribution = defaultdict(lambda: {"count": 0, "total_pps": 0, "peak_pps": 0})
        
        current_time = time.time()
        cutoff_time = current_time - (days * 86400)
        
        for event in self.attack_timeline:
            if event["timestamp"] < cutoff_time:
                continue
            
            hour = event["datetime"][:13]  # YYYY-MM-DD HH format
            distribution[hour]["count"] += 1
            distribution[hour]["total_pps"] += event["pps"]
            distribution[hour]["peak_pps"] = max(distribution[hour]["peak_pps"], event["pps"])
        
        return dict(sorted(distribution.items()))
    
    def predict_next_attack_window(self, source_ip: str) -> Dict:
        """
        Predict likely next attack window based on historical patterns
        
        Args:
            source_ip: IP to predict for
        
        Returns:
            Prediction dictionary with confidence score
        """
        intervals = list(self.attack_intervals[source_ip])
        if len(intervals) < 5:
            return {"confidence": 0, "message": "Insufficient data for prediction"}
        
        current_time = time.time()
        recent_intervals = [t for t in intervals if current_time - t < 86400]  # Last 24h
        
        if not recent_intervals:
            return {"confidence": 0, "message": "No recent activity"}
        
        # Analyze inter-event timing
        deltas = []
        for i in range(1, len(recent_intervals)):
            deltas.append(recent_intervals[i] - recent_intervals[i-1])
        
        if not deltas:
            return {"confidence": 0, "message": "No interval data"}
        
        # Calculate statistics
        avg_interval = sum(deltas) / len(deltas)
        variance = sum((d - avg_interval) ** 2 for d in deltas) / len(deltas)
        std_dev = math.sqrt(variance)
        
        # Predict next attack time
        last_time = recent_intervals[-1]
        predicted_time = last_time + avg_interval
        
        confidence = min(95, max(10, 100 - (std_dev / avg_interval * 100)))
        
        return {
            "predicted_unix_time": predicted_time,
            "predicted_datetime": datetime.fromtimestamp(predicted_time).isoformat(),
            "time_until_predicted": max(0, predicted_time - current_time),
            "confidence": confidence,
            "avg_interval_seconds": avg_interval,
            "std_deviation": std_dev
        }
    
    def detect_coordinated_attacks(self, time_window_seconds: int = 60) -> List[Dict]:
        """
        Detect coordinated attacks from multiple IPs within time window
        
        Args:
            time_window_seconds: Time window for coordination detection
        
        Returns:
            List of detected coordinated attack clusters
        """
        current_time = time.time()
        cutoff_time = current_time - time_window_seconds
        
        # Group recent events by tool
        tool_events = defaultdict(list)
        for event in self.attack_timeline:
            if event["timestamp"] >= cutoff_time:
                tool_events[event["tool"]].append(event)
        
        coordinated = []
        for tool, events in tool_events.items():
            unique_ips = set(e["source_ip"] for e in events)
            if len(unique_ips) >= 3:  # Coordinated if 3+ unique IPs
                coordinated.append({
                    "tool": tool,
                    "attacker_count": len(unique_ips),
                    "attack_count": len(events),
                    "total_pps": sum(e["pps"] for e in events),
                    "peak_pps": max(e["pps"] for e in events),
                    "avg_confidence": sum(e["confidence"] for e in events) / len(events),
                    "attackers": list(unique_ips),
                    "start_time": events[0]["datetime"],
                    "end_time": events[-1]["datetime"]
                })
        
        return sorted(coordinated, key=lambda x: x["total_pps"], reverse=True)
    
    def cleanup_old_data(self, max_age_hours: int = 24) -> int:
        """
        Clean up attack data older than specified age
        
        Args:
            max_age_hours: Remove data older than this
        
        Returns:
            Number of records removed
        """
        current_time = time.time()
        cutoff_time = current_time - (max_age_hours * 3600)
        
        removed_count = 0
        
        # Timeline already limited by deque maxlen
        
        # Clean up old sessions
        sessions_to_remove = []
        for key, session in self.active_sessions.items():
            if session["last_activity"] < cutoff_time:
                sessions_to_remove.append(key)
                removed_count += 1
        
        for key in sessions_to_remove:
            del self.active_sessions[key]
        
        # Clean up old hourly stats
        current_hour = datetime.now().hour
        current_date = datetime.now().date().isoformat()
        
        hours_to_remove = []
        for hour_key in self.hourly_stats.keys():
            try:
                stored_date, stored_hour = hour_key.rsplit("_", 1)
                if f"{stored_date}" != current_date:
                    # Old data from previous days
                    hours_to_remove.append(hour_key)
                    removed_count += 1
            except:
                pass
        
        for key in hours_to_remove:
            del self.hourly_stats[key]
        
        return removed_count
