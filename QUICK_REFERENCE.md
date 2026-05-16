# 🚀 DDoS DETECTOR v2.0 - QUICK REFERENCE

## ⚡ 30-SECOND STARTUP

```bash
# Install dependencies
pip install -r requirements.txt

# Run with admin privileges
sudo python3 ddos_detector_enhanced.py

# Open browser
http://localhost:8050
```

---

## 🎯 ATTACK DETECTION SIGNATURES

### TCP SYN Flood
- **Trigger**: SYN count > 25 AND SYN/ACK ratio > 4.0
- **Risk Score**: 30-50/100
- **Mitigation**: Rate-limit SYN packets, enable SYN cookies
- **Example**: Attacker sends 100 SYN packets, receives 5 ACKs

### HTTP/2 Stream Abuse
- **Trigger**: HTTP streams > 40/sec
- **Risk Score**: 28/100
- **Mitigation**: Limit stream resets, enable connection throttling
- **Example**: RapidReset attacks resetting HTTP/2 streams

### TLS Handshake Flood
- **Trigger**: TLS handshakes > 20/sec
- **Risk Score**: 32/100
- **Mitigation**: Implement TLS session caching, rate limit
- **Example**: Repeated STARTTLS commands from single IP

### UDP Volumetric Flood
- **Trigger**: UDP volume > 80 packets/sec
- **Risk Score**: 28/100
- **Mitigation**: Implement anti-amplification filtering
- **Example**: NTP/DNS amplification attacks

### DNS Query Flood
- **Trigger**: DNS queries > 70% of UDP traffic
- **Risk Score**: 22/100
- **Mitigation**: DNS firewall, query rate limiting
- **Example**: Attacker resolves random subdomains

### Connection Reset Flood (FIN/RST)
- **Trigger**: (FIN+RST) > SYN count
- **Risk Score**: 25/100
- **Mitigation**: Aggressive connection timeout, TCP reset filtering
- **Example**: Attacker sends RST packets to all connections

### Distributed Carpet Bombing
- **Trigger**: High traffic + High IP entropy (>4.5 H')
- **Risk Score**: 95/100
- **Mitigation**: BGP Flowspec, rate limiting per CIDR
- **Example**: Botnet with 10K+ spoofed IPs

---

## 📊 UNDERSTANDING THE METRICS

### Packets Per Second (pps)
```
Normal:   1,000-10,000 pps
Warning:  10,000-50,000 pps
Critical: 50,000+ pps
```

### Entropy (H')
- **High (6-8)**: Normal diverse traffic or botnet (randomized IPs)
- **Medium (3-5)**: Concentrated attack from few sources
- **Low (0-2)**: Single-source attack or targeted flood

### Z-Score (σ)
```
< 1.0:  Normal variation
1-2:    Elevated activity
2-3:    Suspicious activity
> 3:    Likely attack
```

### Threat Score (0-100)
```
0-20:    Legitimate
20-50:   Suspicious (worth monitoring)
50-80:   High threat (investigate)
80+:     Confirmed attack (take action)
```

---

## 🎛️ PARAMETER TUNING GUIDE

### For High False Positives:
```
Increase thresholds:
- Z-Score: 3.5 (stricter)
- Entropy: 5.0 (higher)
- TCP SYN threshold: 40 (instead of 25)
```

### For Missed Attacks:
```
Decrease thresholds:
- Z-Score: 1.5 (looser)
- Entropy: 3.5 (lower)
- TCP SYN threshold: 15 (instead of 25)
```

### For High CPU Usage:
```
Reduce processing:
- Refresh rate: 5000ms (5 seconds)
- WINDOW_SIZE: 60 (instead of 120)
- Payload parsing: disable (comment out)
```

### For Network Conditions:
```
ISP Network (high baseline):
- Z-Score: 3.0 (higher variance)
- Entropy: 5.5 (normal)

Datacenter (low baseline):
- Z-Score: 2.0 (lower variance)
- Entropy: 4.0 (strict)
```

---

## 🔧 COMMON TROUBLESHOOTING

| Problem | Cause | Solution |
|---------|-------|----------|
| No packets detected | Permission denied | Run with `sudo` |
| High false positives | Thresholds too low | Increase Z-score to 3.5 |
| High false negatives | Thresholds too high | Decrease Z-score to 1.5 |
| Memory growing | Memory leak | Restart daily or check maxlen bounds |
| Web UI slow | Too many incidents | Trim incident history table |
| CPU at 100% | Processing overhead | Increase refresh rate, reduce window |
| Database locked | Concurrent access | Check for multiple instances |

---

## 📈 BASELINE CALIBRATION

### Phase 1: Learning (First 5 minutes)
- System collects traffic patterns
- Status: "📚 Learning Baseline"
- No attacks detected (training phase)
- **Action**: Observe normal traffic patterns

### Phase 2: Established (After 5 minutes)
- Status: "✅ Baseline Established"
- Z-scores now meaningful
- Full detection enabled
- **Action**: Ready for production

### Phase 3: Continuous (Ongoing)
- Baseline updates every 10 seconds
- Adapts to network changes
- Learns normal patterns
- **Action**: Monitor metrics panels

---

## 🚨 INCIDENT RESPONSE WORKFLOW

```
1. DETECTION (Automated)
   └─> Alert appears in "ACTIVE INCIDENTS" section
   └─> Risk score calculated (0-100)
   └─> Logged to database

2. ANALYSIS (Manual - 1-5 minutes)
   └─> Check Source IP reputation
   └─> Review attack vector (SYN/HTTP/UDP/etc)
   └─> Cross-reference with threat intel

3. DECISION (Manual)
   └─> False Positive? → Whitelist IP
   └─> Low Risk? → Monitor only
   └─> High Risk? → Block IP

4. MITIGATION (Manual or Automated)
   └─> iptables rule: DROP packets from IP
   └─> WAF rule: Block at application layer
   └─> BGP Flowspec: Upstream blocking
   └─> Alert SOC/security team

5. FORENSICS (Post-incident)
   └─> Export incident history (CSV)
   └─> Analyze attack patterns
   └─> Update signatures
   └─> Review logs (ddos_detector.log)
```

---

## 💾 DATA EXPORT

### Export Incident History
```python
# SQLite database queries
sqlite3 ddos_detector.db

# View all incidents
SELECT timestamp, source_ip, attack_type, severity, packets_per_sec
FROM incidents 
ORDER BY timestamp DESC;

# View IP reputation
SELECT ip_address, threat_score, incident_count
FROM ip_reputation
ORDER BY threat_score DESC;

# Export as CSV
.mode csv
.output incidents.csv
SELECT * FROM incidents;
.quit
```

### View Logs
```bash
# Real-time log viewing
tail -f ddos_detector.log

# Search for specific IP
grep "192.168.1.100" ddos_detector.log

# Count attacks per IP
grep "MALICIOUS" ddos_detector.log | cut -d'[' -f2 | cut -d']' -f1 | sort | uniq -c

# Export last 1000 lines
tail -1000 ddos_detector.log > export_$(date +%Y%m%d).log
```

---

## 🧪 TEST CASES

### Test 1: SYN Flood Detection
```bash
# Generate SYN flood (requires hping3)
sudo hping3 -S --flood -p 80 127.0.0.1

# Expected: Alert appears with "TCP SYN Flood" vector
# Expected: Risk score > 50
# Expected: Incident logged to database
```

### Test 2: UDP Flood Detection
```bash
# Generate UDP flood
sudo hping3 -2 --flood -p 53 127.0.0.1

# Expected: "UDP Volumetric Flood" alert
# Expected: High packets/sec in chart
# Expected: Entropy may increase
```

### Test 3: HTTP Flood Detection
```bash
# Using Apache Bench
ab -n 1000 -c 50 http://localhost:8080/

# Expected: "HTTP/2 Stream Abuse" alert if HTTP/2 enabled
# Expected: Stream count increases
# Expected: Risk score reflects HTTP attacks
```

### Test 4: False Positive Test
```bash
# Generate normal traffic
for i in {1..100}; do curl http://localhost:8080/ &; done

# Expected: Elevated pps but no alert
# Expected: Normal entropy (~5)
# Expected: Status remains 🟢 NORMAL
```

---

## 🔐 SECURITY CHECKLIST

- [ ] Run with minimal privileges (drop privileges after packet sniffing starts)
- [ ] Protect database with file permissions: `chmod 600 ddos_detector.db`
- [ ] Secure Web UI (use reverse proxy with SSL/TLS)
- [ ] Restrict Web UI access to trusted networks
- [ ] Backup incident database regularly
- [ ] Rotate logs weekly
- [ ] Never commit database to version control
- [ ] Sanitize output before sharing (remove real IPs in reports)
- [ ] Monitor tool itself for DoS (e.g., packet processing overhead)
- [ ] Keep Scapy updated for security patches

---

## 🎓 LEARNING OUTCOMES

After implementing this tool, you'll understand:

✅ **Network Protocols**
- TCP flags (SYN, ACK, FIN, RST)
- UDP/ICMP protocols
- DNS queries and responses
- TLS handshake process

✅ **Attack Signatures**
- SYN flood mechanics
- HTTP/2 stream attacks
- DNS amplification
- Botnet behavior patterns

✅ **Statistical Analysis**
- Z-score calculation
- Shannon entropy
- Baseline anomaly detection
- Payload variance analysis

✅ **Incident Response**
- Alert triage and prioritization
- Threat scoring
- Evidence preservation
- Mitigation strategies

✅ **Database & Logging**
- SQLite operations
- Log file management
- Data persistence
- Query optimization

---

## 📱 USEFUL LINUX COMMANDS

```bash
# Monitor real-time traffic
sudo tcpdump -i eth0 -nn 'tcp or udp' | head -100

# Count packets by source IP
tcpdump -r packets.pcap -nnn | cut -d'>' -f1 | sort | uniq -c | sort -rn | head

# Check open ports
sudo netstat -tulpn | grep LISTEN

# View IP routing table
route -n

# Monitor network interfaces
watch -n 1 'ifstat 1 1'

# Capture to file
sudo tcpdump -i eth0 -w captured_traffic.pcap -c 10000

# Analyze with Wireshark
wireshark captured_traffic.pcap &
```

---

## 📞 QUICK SUPPORT

### Database Issues
```
Error: "database is locked"
Fix: pkill -f ddos_detector_enhanced.py
    wait 2 seconds
    restart script
```

### Packet Sniffing Issues
```
Error: "sniff() requires root"
Fix: sudo python3 ddos_detector_enhanced.py
     OR: setcap cap_net_raw=ep python3
```

### Web UI Issues
```
Error: "Port 8050 already in use"
Fix: change port in code: app.run(port=8051)
     OR: kill existing process: lsof -i :8050 | kill -9
```

---

## 🎯 CEH EXAM RELEVANCE

This tool covers CEH v13 domains:

| Domain | Covered Topics |
|--------|---|
| Footprinting | Network reconnaissance, data gathering |
| Scanning | Port enumeration, protocol identification |
| Enumeration | Service version detection, vulnerability scanning |
| System Hacking | Attack detection, incident response |
| Social Engineering | IP reputation, threat intelligence |
| Denial of Service | DDoS attacks, mitigation techniques |
| Security Tools | IDS, packet analysis, forensics |

---

**Version**: 2.0
**Last Updated**: 2025
**Author**: Enhanced Security Tool
**License**: Educational Use Only

For production deployment, consider:
- Hardening authentication
- Implementing rate limiting
- Adding compliance logging
- Integrating with SIEM
- Setting up automated response
