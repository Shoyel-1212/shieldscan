"""
NIDS — Network Intrusion Detection System
Cybersecurity Self-Assignment | Blue Team / Defensive Security
Author: Self-Assignment
 
Detection Modules:
  1. Port Scan Detection     (SYN, NULL, XMAS, FIN sweeps)
  2. Brute Force Detection   (SSH/FTP/HTTP repeated failures)
  3. SYN Flood Detection     (half-open connection flood)
  4. DNS Tunneling Detection (oversized / encoded DNS queries)
  5. ARP Spoofing Detection  (duplicate MAC for gateway)
 
Dashboard: Flask web server at http://localhost:5000
 
REQUIREMENTS:
  pip install scapy flask colorama
 
RUN AS ROOT (packet capture requires raw socket access):
  sudo python3 nids.py --iface eth0
"""
 
import time
import threading
import argparse
import json
from collections import defaultdict, deque
from datetime import datetime
 
from colorama import Fore, Style, init
from flask import Flask, jsonify, render_template_string
 
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, DNSQR, get_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[WARN] Scapy not installed. Run: pip install scapy")
 
init(autoreset=True)
 
# ─────────────────────────────────────────────
# CONFIG — tune these thresholds
# ─────────────────────────────────────────────
 
THRESHOLDS = {
    "port_scan_window":    10,    # seconds
    "port_scan_count":     15,    # unique ports → alert
    "brute_force_window":  60,    # seconds
    "brute_force_count":   10,    # attempts → alert
    "syn_flood_window":    5,     # seconds
    "syn_flood_count":     200,   # SYN pkts → alert
    "dns_payload_size":    100,   # bytes, oversized = suspicious
    "dns_entropy_thresh":  3.8,   # Shannon entropy threshold
}
 
BRUTE_FORCE_PORTS = {22: "SSH", 21: "FTP", 3389: "RDP", 110: "POP3", 25: "SMTP", 80: "HTTP"}
 
# ─────────────────────────────────────────────
# SHARED STATE
# ─────────────────────────────────────────────
 
alerts      = deque(maxlen=200)
packet_log  = deque(maxlen=500)
stats       = {"packets": 0, "alerts": 0, "blocked": 0}
blocked_ips = set()
threat_counts = defaultdict(int)
lock = threading.Lock()
 
# Per-IP tracking windows
port_tracker  = defaultdict(lambda: deque())   # ip → [(ts, port), ...]
syn_tracker   = defaultdict(lambda: deque())   # ip → [ts, ...]
brute_tracker = defaultdict(lambda: deque())   # ip → [ts, ...]
arp_table     = {}                             # ip → mac
 
# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
 
def ts():
    return datetime.now().strftime("%H:%M:%S")
 
def log(msg, level="INFO"):
    colors = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW,
               "CRIT": Fore.RED, "OK": Fore.GREEN}
    c = colors.get(level, Fore.WHITE)
    print(f"{c}[{level}]{Style.RESET_ALL} {ts()} {msg}")
 
def raise_alert(threat, src_ip, severity, detail):
    entry = {
        "time": ts(), "threat": threat,
        "src": src_ip, "severity": severity, "detail": detail
    }
    with lock:
        alerts.appendleft(entry)
        stats["alerts"] += 1
        threat_counts[threat] += 1
        if severity == "Critical":
            blocked_ips.add(src_ip)
            stats["blocked"] = len(blocked_ips)
    log(f"[{severity.upper()}] {threat} | {src_ip} | {detail}", "CRIT" if severity == "Critical" else "WARN")
 
def shannon_entropy(data: str) -> float:
    import math
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
 
def clean_window(dq, window_secs):
    cutoff = time.time() - window_secs
    while dq and dq[0] < cutoff:
        dq.popleft()
 
# ─────────────────────────────────────────────
# MODULE 1 — Port Scan Detection
# ─────────────────────────────────────────────
 
def detect_port_scan(src_ip, dst_port, flags):
    now = time.time()
    dq = port_tracker[src_ip]
    clean_window(dq, THRESHOLDS["port_scan_window"])
    dq.append(now)
 
    unique_ports = len(set(p for p in port_tracker[src_ip]))
 
    # Detect stealth scans by flag pattern
    scan_type = None
    if flags == 0x00:
        scan_type = "NULL scan"
    elif flags & 0x29 == 0x29:
        scan_type = "XMAS scan"
    elif flags == 0x01:
        scan_type = "FIN scan"
    elif unique_ports >= THRESHOLDS["port_scan_count"]:
        scan_type = "SYN sweep"
 
    if scan_type:
        raise_alert(
            "Port Scan", src_ip, "Critical",
            f"{scan_type} — {unique_ports} ports probed in {THRESHOLDS['port_scan_window']}s"
        )
 
# ─────────────────────────────────────────────
# MODULE 2 — Brute Force Detection
# ─────────────────────────────────────────────
 
def detect_brute_force(src_ip, dst_port):
    if dst_port not in BRUTE_FORCE_PORTS:
        return
    now = time.time()
    dq = brute_tracker[f"{src_ip}:{dst_port}"]
    clean_window(dq, THRESHOLDS["brute_force_window"])
    dq.append(now)
 
    if len(dq) >= THRESHOLDS["brute_force_count"]:
        service = BRUTE_FORCE_PORTS[dst_port]
        raise_alert(
            "Brute Force", src_ip, "High",
            f"{len(dq)} {service} attempts in {THRESHOLDS['brute_force_window']}s"
        )
        dq.clear()
 
# ─────────────────────────────────────────────
# MODULE 3 — SYN Flood Detection
# ─────────────────────────────────────────────
 
def detect_syn_flood(src_ip, flags):
    if not (flags & 0x02 and not flags & 0x10):  # SYN only, no ACK
        return
    now = time.time()
    dq = syn_tracker[src_ip]
    clean_window(dq, THRESHOLDS["syn_flood_window"])
    dq.append(now)
 
    if len(dq) >= THRESHOLDS["syn_flood_count"]:
        raise_alert(
            "SYN Flood", src_ip, "Critical",
            f"{len(dq)} SYN packets in {THRESHOLDS['syn_flood_window']}s — possible DDoS"
        )
        dq.clear()
 
# ─────────────────────────────────────────────
# MODULE 4 — DNS Tunneling Detection
# ─────────────────────────────────────────────
 
def detect_dns_tunnel(src_ip, pkt):
    if not pkt.haslayer(DNSQR):
        return
    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    payload_len = len(qname)
    entropy = shannon_entropy(qname)
 
    if (payload_len > THRESHOLDS["dns_payload_size"] or
            entropy > THRESHOLDS["dns_entropy_thresh"]):
        raise_alert(
            "DNS Tunneling", src_ip, "High",
            f"Query: {qname[:50]}... | len={payload_len} entropy={entropy:.2f}"
        )
 
# ─────────────────────────────────────────────
# MODULE 5 — ARP Spoofing Detection
# ─────────────────────────────────────────────
 
def detect_arp_spoof(pkt):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    if arp.op != 2:  # only ARP replies
        return
 
    src_ip = arp.psrc
    src_mac = arp.hwsrc
 
    if src_ip in arp_table and arp_table[src_ip] != src_mac:
        raise_alert(
            "ARP Spoofing", src_ip, "High",
            f"MAC changed: {arp_table[src_ip]} → {src_mac} — possible MITM"
        )
    else:
        arp_table[src_ip] = src_mac
 
# ─────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────
 
def packet_handler(pkt):
    with lock:
        stats["packets"] += 1
 
    # ARP layer
    if pkt.haslayer(ARP):
        detect_arp_spoof(pkt)
        return
 
    if not pkt.haslayer(IP):
        return
 
    src_ip = pkt[IP].src
 
    # Skip already-blocked IPs
    if src_ip in blocked_ips:
        return
 
    # Log packet summary
    summary = f"{src_ip} → {pkt[IP].dst}"
    if pkt.haslayer(TCP):
        summary += f" TCP:{pkt[TCP].dport}"
    elif pkt.haslayer(UDP):
        summary += f" UDP:{pkt[UDP].dport}"
    packet_log.appendleft({"time": ts(), "summary": summary})
 
    # DNS
    if pkt.haslayer(DNS):
        detect_dns_tunnel(src_ip, pkt)
 
    # TCP analysis
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        detect_port_scan(src_ip, tcp.dport, flags)
        detect_brute_force(src_ip, tcp.dport)
        detect_syn_flood(src_ip, flags)
 
# ─────────────────────────────────────────────
# FLASK DASHBOARD
# ─────────────────────────────────────────────
 
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">
<title>NIDS Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0a0e17; color: #7eb8d4; padding: 20px; }
  h1 { color: #1d9e75; font-size: 18px; letter-spacing: 3px; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
  .card { background: #0f1623; border: 0.5px solid #1e2d45; border-radius: 8px; padding: 16px; text-align: center; }
  .card .num { font-size: 28px; font-weight: bold; }
  .card .lbl { font-size: 11px; color: #4a7fa5; margin-top: 4px; letter-spacing: 1px; }
  .red { color: #f85149; } .yellow { color: #febc2e; } .green { color: #1d9e75; } .blue { color: #378add; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 20px; }
  th { text-align: left; color: #4a7fa5; padding: 8px; border-bottom: 0.5px solid #1e2d45; font-size: 10px; letter-spacing: 1px; }
  td { padding: 8px; border-bottom: 0.5px solid #0f1623; }
  .sev-crit { color: #f85149; } .sev-high { color: #febc2e; } .sev-med { color: #378add; }
  .section { font-size: 10px; letter-spacing: 2px; color: #4a7fa5; margin-bottom: 10px; }
</style>
</head>
<body>
<h1>NIDS — NETWORK INTRUSION DETECTION SYSTEM</h1>
 
<div class="grid">
  <div class="card"><div class="num red">{{ stats.alerts }}</div><div class="lbl">TOTAL ALERTS</div></div>
  <div class="card"><div class="num yellow">{{ stats.packets }}</div><div class="lbl">PACKETS</div></div>
  <div class="card"><div class="num green">{{ stats.blocked }}</div><div class="lbl">BLOCKED IPs</div></div>
  <div class="card"><div class="num blue">{{ threat_counts | length }}</div><div class="lbl">THREAT TYPES</div></div>
</div>
 
<div class="section">LIVE ALERTS</div>
<table>
  <thead><tr><th>TIME</th><th>THREAT</th><th>SOURCE IP</th><th>SEVERITY</th><th>DETAIL</th></tr></thead>
  <tbody>
  {% for a in alerts %}
  <tr>
    <td>{{ a.time }}</td>
    <td>{{ a.threat }}</td>
    <td>{{ a.src }}</td>
    <td class="sev-{{ 'crit' if a.severity == 'Critical' else 'high' if a.severity == 'High' else 'med' }}">{{ a.severity }}</td>
    <td style="color:#4a7fa5">{{ a.detail }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
 
<div class="section">BLOCKED IPs</div>
<table>
  <thead><tr><th>IP ADDRESS</th></tr></thead>
  <tbody>{% for ip in blocked %}<tr><td class="red">{{ ip }}</td></tr>{% endfor %}</tbody>
</table>
</body>
</html>
"""
 
app = Flask(__name__)
 
@app.route("/")
def dashboard():
    return render_template_string(
        DASHBOARD_HTML,
        stats=dict(stats),
        alerts=list(alerts)[:50],
        blocked=sorted(blocked_ips),
        threat_counts=dict(threat_counts),
    )
 
@app.route("/api/stats")
def api_stats():
    return jsonify({
        "stats": dict(stats),
        "alerts": list(alerts)[:20],
        "blocked": sorted(blocked_ips),
        "threat_counts": dict(threat_counts),
    })
 
# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
 
def start_sniffer(iface, bpf_filter=""):
    log(f"Starting packet capture on {iface}", "OK")
    sniff(
        iface=iface,
        prn=packet_handler,
        filter=bpf_filter,
        store=False,
    )
 
def banner():
    print(Fore.CYAN + r"""
  _   _ ___ ____  ____
 | \ | |_ _|  _ \/ ___|
 |  \| || || | | \___ \
 | |\  || || |_| |___) |
 |_| \_|___|____/|____/
 
  Network Intrusion Detection System v1.0
  Blue Team | Defensive Security
""")
 
if __name__ == "__main__":
    banner()
 
    parser = argparse.ArgumentParser(description="NIDS — Network Intrusion Detection System")
    parser.add_argument("--iface", default="eth0", help="Network interface to monitor (default: eth0)")
    parser.add_argument("--filter", default="", help="BPF filter string (default: all traffic)")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port (default: 5000)")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces")
    args = parser.parse_args()
 
    if args.list_ifaces:
        if SCAPY_OK:
            print("Available interfaces:")
            for iface in get_if_list():
                print(f"  {iface}")
        else:
            print("Scapy not installed.")
        exit(0)
 
    if not SCAPY_OK:
        print("Scapy is required: pip install scapy")
        exit(1)
 
    log(f"Dashboard: http://localhost:{args.port}", "OK")
    log(f"Interface: {args.iface}", "OK")
    log("Press Ctrl+C to stop\n", "OK")
 
    # Start Flask dashboard in background thread
    flask_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False),
        daemon=True
    )
    flask_thread.start()
 
    # Start packet capture (blocking)
    try:
        start_sniffer(args.iface, args.filter)
    except KeyboardInterrupt:
        log("NIDS stopped.", "OK")
    except PermissionError:
        log("Permission denied. Run with: sudo python3 nids.py", "CRIT")
 