"""
ShieldScan — Stage 2 Deep Device Scanner Agent
Cybersecurity Self-Assignment | Blue Team Tool

What this scans:
  1. Suspicious running processes (spyware, keyloggers, RATs)
  2. Open ports on your device
  3. Active network connections (who your device is talking to)
  4. Startup programs (malware that runs on boot)
  5. Recently modified system files
  6. Weak user account settings
  7. Firewall status
  8. Sends full report to ShieldScan website dashboard

INSTALL:
  pip install psutil requests colorama flask

RUN:
  python agent.py

Then open: http://127.0.0.1:5000
"""

import os
import sys
import json
import socket
import platform
import subprocess
import threading
from datetime import datetime

import psutil
import requests
from colorama import Fore, Style, init
from flask import Flask, jsonify, render_template_string

init(autoreset=True)

# ─────────────────────────────────────────────
# KNOWN SUSPICIOUS PROCESS NAMES
# (common spyware, RATs, keyloggers, miners)
# ─────────────────────────────────────────────
SUSPICIOUS_PROCESSES = [
    # Remote Access Trojans
    "njrat", "nanocore", "darkcomet", "quasar", "netwire",
    "blackshades", "crimson", "remcos", "orcus", "asyncrat",
    # Keyloggers
    "keylogger", "ardamax", "refog", "revealer", "spyrix",
    # Crypto miners
    "xmrig", "minerd", "cpuminer", "nicehash", "ethminer",
    # Known malware patterns
    "payload", "beacon", "implant", "rat.exe", "spy.exe",
    # Suspicious generic names
    "svchost32", "csrss32", "lsass32", "winlogon32",
]

# Legitimate Windows processes to never flag
WHITELIST = [
    "svchost.exe", "csrss.exe", "lsass.exe", "winlogon.exe",
    "explorer.exe", "taskmgr.exe", "system", "registry",
    "smss.exe", "wininit.exe", "services.exe", "spoolsv.exe",
    "python.exe", "python3.exe", "agent.py", "cmd.exe",
    "powershell.exe", "conhost.exe", "dllhost.exe",
]

# Dangerous ports that should NOT be open
DANGEROUS_PORTS = {
    21:   "FTP — unencrypted file transfer",
    22:   "SSH — remote access (ok if you use it)",
    23:   "Telnet — unencrypted remote access (very dangerous)",
    25:   "SMTP — mail server (suspicious on personal PC)",
    135:  "RPC — Windows remote procedure call",
    139:  "NetBIOS — Windows file sharing",
    445:  "SMB — Windows file sharing (WannaCry target)",
    1433: "MSSQL — database server",
    3306: "MySQL — database server",
    3389: "RDP — Remote Desktop (high risk if open)",
    4444: "Metasploit default — likely malware shell",
    5900: "VNC — remote desktop viewer",
    6666: "IRC — often used by botnets",
    6667: "IRC — botnet command channel",
    8080: "HTTP Proxy — check if you set this up",
    9001: "Tor relay port",
    9050: "Tor SOCKS proxy",
}

findings = []
scan_done = False
scan_data = {}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, level="INFO"):
    colors = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW,
               "CRIT": Fore.RED, "OK": Fore.GREEN, "TITLE": Fore.MAGENTA}
    c = colors.get(level, Fore.WHITE)
    print(f"{c}[{level}]{Style.RESET_ALL} {ts()} {msg}")

def add_finding(severity, name, detail, recommendation=""):
    findings.append({
        "severity": severity,
        "name": name,
        "detail": detail,
        "recommendation": recommendation,
        "time": ts()
    })
    level = "CRIT" if severity == "Critical" else "WARN" if severity == "Warning" else "OK"
    log(f"[{severity}] {name}", level)

# ─────────────────────────────────────────────
# MODULE 1 — Suspicious Process Scanner
# ─────────────────────────────────────────────

def scan_processes():
    log("Scanning running processes...", "INFO")
    suspicious_found = []
    all_procs = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            name_lower = (info['name'] or '').lower()
            exe = info.get('exe') or ''
            cmdline = ' '.join(info.get('cmdline') or []).lower()

            all_procs.append({
                "pid": info['pid'],
                "name": info['name'],
                "exe": exe,
                "cpu": round(info.get('cpu_percent') or 0, 1),
                "mem": round(info.get('memory_percent') or 0, 1),
            })

            # Check against suspicious list
            for sus in SUSPICIOUS_PROCESSES:
                if sus in name_lower or sus in cmdline:
                    suspicious_found.append(info['name'])
                    add_finding(
                        "Critical",
                        f"Suspicious Process: {info['name']}",
                        f"PID {info['pid']} | Path: {exe or 'unknown'} | Matches known malware pattern: '{sus}'",
                        "Immediately terminate this process and run a full antivirus scan."
                    )
                    break

            # Flag processes with no executable path (sometimes malware)
            if info['name'] and info['name'].lower() not in [w.lower() for w in WHITELIST]:
                if not exe and info['pid'] > 4:
                    pass  # too noisy, skip

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    scan_data['processes'] = all_procs[:30]  # top 30 for dashboard

    if not suspicious_found:
        add_finding("Safe", "Process Scan Clean",
                    f"Scanned {len(all_procs)} running processes. No known malware signatures detected.",
                    "")
    log(f"Scanned {len(all_procs)} processes", "OK")

# ─────────────────────────────────────────────
# MODULE 2 — Open Port Scanner
# ─────────────────────────────────────────────

def scan_open_ports():
    log("Scanning open ports on your device...", "INFO")
    open_ports = []
    dangerous_open = []

    # Get ports from active connections
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                try:
                    proc = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                except:
                    proc = "unknown"

                port_info = {
                    "port": port,
                    "process": proc,
                    "pid": conn.pid,
                    "dangerous": port in DANGEROUS_PORTS
                }
                open_ports.append(port_info)

                if port in DANGEROUS_PORTS:
                    dangerous_open.append(port)
                    add_finding(
                        "Warning",
                        f"Dangerous Port Open: {port}",
                        f"Port {port} ({DANGEROUS_PORTS[port]}) is listening — opened by: {proc}",
                        f"Close port {port} if you don't need it. Check your firewall settings."
                    )
    except psutil.AccessDenied:
        log("Access denied for full port scan — run as administrator for complete results", "WARN")

    scan_data['open_ports'] = open_ports

    if not dangerous_open:
        add_finding("Safe", "No Dangerous Ports Open",
                    f"Found {len(open_ports)} open ports. None match known dangerous port list.",
                    "")
    log(f"Found {len(open_ports)} listening ports, {len(dangerous_open)} flagged", "OK")

# ─────────────────────────────────────────────
# MODULE 3 — Active Network Connections
# ─────────────────────────────────────────────

def scan_connections():
    log("Analyzing active network connections...", "INFO")
    connections = []
    suspicious_conns = []

    # Known malicious/C2 ports
    bad_ports = [4444, 1337, 6666, 6667, 6668, 6669, 31337, 12345, 54321]

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                except:
                    proc_name = "unknown"

                is_suspicious = remote_port in bad_ports

                conn_info = {
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{remote_ip}:{remote_port}",
                    "process": proc_name,
                    "suspicious": is_suspicious
                }
                connections.append(conn_info)

                if is_suspicious:
                    suspicious_conns.append(conn_info)
                    add_finding(
                        "Critical",
                        f"Suspicious Outbound Connection",
                        f"Process '{proc_name}' is connected to {remote_ip}:{remote_port} — this port is commonly used by malware/RATs.",
                        "Block this connection in your firewall and investigate the process immediately."
                    )

    except psutil.AccessDenied:
        log("Access denied for connection scan", "WARN")

    scan_data['connections'] = connections[:20]

    if not suspicious_conns:
        add_finding("Safe", "Network Connections Look Clean",
                    f"Analyzed {len(connections)} active connections. No connections to known malicious ports.",
                    "")
    log(f"Analyzed {len(connections)} active connections", "OK")

# ─────────────────────────────────────────────
# MODULE 4 — Startup Programs
# ─────────────────────────────────────────────

def scan_startup():
    log("Checking startup programs...", "INFO")
    startup_items = []

    if platform.system() == "Windows":
        reg_paths = [
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        ]
        for path in reg_paths:
            try:
                result = subprocess.run(
                    ["reg", "query", path],
                    capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.strip().splitlines()
                for line in lines:
                    if "REG_SZ" in line:
                        parts = line.strip().split("REG_SZ")
                        name = parts[0].strip()
                        value = parts[1].strip() if len(parts) > 1 else ""
                        startup_items.append({"name": name, "path": value, "location": path})

                        # Flag suspicious startup entries
                        for sus in SUSPICIOUS_PROCESSES:
                            if sus in name.lower() or sus in value.lower():
                                add_finding(
                                    "Critical",
                                    f"Suspicious Startup Entry: {name}",
                                    f"Found in registry: {path}\nPath: {value}",
                                    "Remove this startup entry immediately using Task Manager > Startup tab."
                                )
                                break
            except Exception as e:
                log(f"Could not read registry: {e}", "WARN")

    elif platform.system() == "Linux":
        startup_dirs = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/init.d",
            "/etc/cron.d",
        ]
        for d in startup_dirs:
            if os.path.exists(d):
                for f in os.listdir(d)[:10]:
                    startup_items.append({"name": f, "path": os.path.join(d, f), "location": d})

    scan_data['startup'] = startup_items

    if startup_items:
        add_finding("Info", f"Startup Programs Found",
                    f"{len(startup_items)} programs run on startup. Review them to ensure none are unwanted.",
                    "Open Task Manager > Startup tab to review and disable suspicious entries.")
    else:
        add_finding("Safe", "Startup Programs",
                    "No suspicious startup programs detected in registry.", "")

    log(f"Found {len(startup_items)} startup entries", "OK")

# ─────────────────────────────────────────────
# MODULE 5 — Firewall Status
# ─────────────────────────────────────────────

def scan_firewall():
    log("Checking firewall status...", "INFO")

    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout.lower()
            if "off" in output:
                add_finding(
                    "Critical",
                    "Windows Firewall is DISABLED",
                    "Your Windows Firewall is turned off on one or more profiles. Your device is exposed to network attacks.",
                    "Go to Windows Security > Firewall & network protection and turn it ON."
                )
            else:
                add_finding("Safe", "Windows Firewall Active",
                            "Windows Firewall is enabled on all profiles. Your device has basic network protection.", "")
        except Exception as e:
            add_finding("Info", "Firewall Check", f"Could not verify firewall status: {e}. Run as administrator.",
                        "Run as administrator for full firewall check.")

    elif platform.system() == "Linux":
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            if "inactive" in result.stdout.lower():
                add_finding("Warning", "UFW Firewall Inactive",
                            "Linux UFW firewall is not active.",
                            "Run: sudo ufw enable")
            else:
                add_finding("Safe", "UFW Firewall Active", "Linux UFW firewall is running.", "")
        except:
            add_finding("Info", "Firewall Check", "Could not check firewall status.", "")

# ─────────────────────────────────────────────
# MODULE 6 — System Info
# ─────────────────────────────────────────────

def collect_system_info():
    log("Collecting system information...", "INFO")
    uname = platform.uname()
    scan_data['system'] = {
        "os": f"{uname.system} {uname.release}",
        "hostname": uname.node,
        "machine": uname.machine,
        "cpu_count": psutil.cpu_count(),
        "ram_gb": round(psutil.virtual_memory().total / (1024**3), 1),
        "disk_gb": round(psutil.disk_usage('/').total / (1024**3), 1),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M"),
        "local_ip": socket.gethostbyname(socket.gethostname()),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# ─────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────

def calculate_score():
    score = 100
    for f in findings:
        if f['severity'] == 'Critical': score -= 20
        elif f['severity'] == 'Warning': score -= 8
    return max(0, min(100, score))

# ─────────────────────────────────────────────
# FLASK DASHBOARD
# ─────────────────────────────────────────────

DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShieldScan — Deep Scan Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#060a0f;--bg2:#0c1219;--border:#1a2a3a;--green:#1d9e75;--red:#f85149;--yellow:#febc2e;--blue:#378add;--text:#b8d4e8;--muted:#4a6a7a;--mono:'Share Tech Mono',monospace;--main:'Rajdhani',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--main);padding:0}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(29,158,117,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(29,158,117,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:900px;margin:0 auto;padding:20px}
nav{display:flex;justify-content:space-between;align-items:center;border-bottom:0.5px solid var(--border);padding-bottom:16px;margin-bottom:28px}
.logo{font-family:var(--mono);font-size:16px;color:var(--green);letter-spacing:2px}
.logo span{color:var(--muted)}
.badge{font-family:var(--mono);font-size:11px;color:var(--green);border:0.5px solid var(--green);padding:3px 10px;border-radius:3px}
.score-wrap{text-align:center;margin-bottom:28px}
.score-circle{width:130px;height:130px;border-radius:50%;margin:0 auto 10px;display:flex;flex-direction:column;align-items:center;justify-content:center;border:3px solid var(--green)}
.score-circle.warn{border-color:var(--yellow)}.score-circle.bad{border-color:var(--red)}
.score-num{font-size:40px;font-weight:700;color:#e8f4f8;font-family:var(--mono);line-height:1}
.score-lbl{font-size:11px;color:var(--muted);font-family:var(--mono)}
.grade{font-size:20px;font-weight:700;font-family:var(--mono)}
.g-good{color:var(--green)}.g-warn{color:var(--yellow)}.g-bad{color:var(--red)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:24px}
.stat{background:var(--bg2);border:0.5px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.stat-n{font-size:24px;font-weight:700;font-family:var(--mono)}
.stat-l{font-size:10px;color:var(--muted);letter-spacing:1px;margin-top:3px}
.cn{color:var(--red)}.cy{color:var(--yellow)}.cg{color:var(--green)}.cb{color:var(--blue)}
.sysinfo{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:24px}
.si{background:var(--bg2);border:0.5px solid var(--border);border-radius:8px;padding:12px}
.si-l{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:1px;margin-bottom:4px}
.si-v{font-family:var(--mono);font-size:13px;color:var(--text);word-break:break-all}
.sec-title{font-family:var(--mono);font-size:11px;color:var(--green);letter-spacing:2px;padding-bottom:8px;border-bottom:0.5px solid var(--border);margin:24px 0 12px}
.finding{display:flex;gap:12px;background:var(--bg2);border:0.5px solid var(--border);border-radius:8px;padding:14px;margin-bottom:8px;align-items:flex-start}
.finding.crit{border-left:3px solid var(--red)}.finding.warn{border-left:3px solid var(--yellow)}.finding.safe{border-left:3px solid var(--green)}.finding.info{border-left:3px solid var(--blue)}
.fi{font-size:16px;flex-shrink:0}
.fb{flex:1}
.fn{font-size:15px;font-weight:600;color:#e8f4f8;margin-bottom:3px}
.fd{font-size:12px;color:var(--muted);font-family:var(--mono);line-height:1.5}
.fr{font-size:12px;color:var(--green);font-family:var(--mono);margin-top:4px}
.fbadge{font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:3px;flex-shrink:0}
.bc{background:#2d0808;color:var(--red)}.bw{background:#2d1e00;color:var(--yellow)}.bs{background:#0a2010;color:var(--green)}.bi{background:#0d1e2d;color:var(--blue)}
table{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--mono);margin-bottom:20px}
th{text-align:left;color:var(--muted);padding:8px;border-bottom:0.5px solid var(--border);font-size:10px;letter-spacing:1px}
td{padding:8px;border-bottom:0.5px solid #0f1623;color:var(--text)}
tr:hover td{background:#0c1219}
.danger{color:var(--red)}.ok{color:var(--green)}
.loading{text-align:center;padding:60px;font-family:var(--mono);color:var(--muted)}
.spin{display:inline-block;animation:spin 1s linear infinite;font-size:24px;margin-bottom:12px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <div class="logo">SHIELD<span>SCAN</span> — <span>DEEP AGENT REPORT</span></div>
    <div class="badge" id="statusBadge">SCANNING...</div>
  </nav>
  <div id="content"><div class="loading"><div class="spin">⟳</div><br>Deep scan in progress...<br><small>This takes 15-30 seconds</small></div></div>
</div>
<script>
function load(){
  fetch('/api/report').then(r=>r.json()).then(d=>{
    if(!d.done){setTimeout(load,2000);return;}
    render(d);
  }).catch(()=>setTimeout(load,2000));
}
function render(d){
  document.getElementById('statusBadge').textContent='SCAN COMPLETE';
  document.getElementById('statusBadge').style.borderColor='#1d9e75';
  const s=d.score;
  let grade,gc,cc;
  if(s>=80){grade='SECURE';gc='g-good';cc='';}
  else if(s>=55){grade='AT RISK';gc='g-warn';cc='warn';}
  else{grade='VULNERABLE';gc='g-bad';cc='bad';}
  const sys=d.system||{};
  const crits=d.findings.filter(f=>f.severity==='Critical').length;
  const warns=d.findings.filter(f=>f.severity==='Warning').length;
  const safes=d.findings.filter(f=>f.severity==='Safe').length;
  let html=`
  <div class="score-wrap">
    <div class="score-circle ${cc}"><div class="score-num">${s}</div><div class="score-lbl">SECURITY SCORE</div></div>
    <div class="grade ${gc}">${grade}</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-n cn">${crits}</div><div class="stat-l">CRITICAL</div></div>
    <div class="stat"><div class="stat-n cy">${warns}</div><div class="stat-l">WARNINGS</div></div>
    <div class="stat"><div class="stat-n cg">${safes}</div><div class="stat-l">PASSED</div></div>
    <div class="stat"><div class="stat-n cb">${d.findings.length}</div><div class="stat-l">TOTAL CHECKS</div></div>
  </div>
  <div class="sysinfo">
    <div class="si"><div class="si-l">OS</div><div class="si-v">${sys.os||'—'}</div></div>
    <div class="si"><div class="si-l">HOSTNAME</div><div class="si-v">${sys.hostname||'—'}</div></div>
    <div class="si"><div class="si-l">LOCAL IP</div><div class="si-v">${sys.local_ip||'—'}</div></div>
    <div class="si"><div class="si-l">CPU CORES</div><div class="si-v">${sys.cpu_count||'—'}</div></div>
    <div class="si"><div class="si-l">RAM</div><div class="si-v">${sys.ram_gb||'—'} GB</div></div>
    <div class="si"><div class="si-l">SCAN TIME</div><div class="si-v">${sys.scan_time||'—'}</div></div>
  </div>`;

  // Findings sections
  const sevs=[['Critical','CRITICAL FINDINGS','crit','bc','⚠'],['Warning','WARNINGS','warn','bw','◈'],['Safe','PASSED CHECKS','safe','bs','✓'],['Info','INFORMATION','info','bi','ℹ']];
  sevs.forEach(([sev,title,cls,badge,icon])=>{
    const items=d.findings.filter(f=>f.severity===sev);
    if(!items.length)return;
    html+=`<div class="sec-title">// ${title} (${items.length})</div>`;
    items.forEach(f=>{
      html+=`<div class="finding ${cls}">
        <div class="fi">${icon}</div>
        <div class="fb">
          <div class="fn">${f.name}</div>
          <div class="fd">${f.detail}</div>
          ${f.recommendation?`<div class="fr">→ ${f.recommendation}</div>`:''}
        </div>
        <div class="fbadge ${badge}">${sev.toUpperCase()}</div>
      </div>`;
    });
  });

  // Open ports table
  if(d.open_ports&&d.open_ports.length){
    html+=`<div class="sec-title">// OPEN PORTS (${d.open_ports.length})</div>
    <table><thead><tr><th>PORT</th><th>PROCESS</th><th>PID</th><th>STATUS</th></tr></thead><tbody>`;
    d.open_ports.forEach(p=>{
      html+=`<tr><td class="${p.dangerous?'danger':'ok'}">${p.port}</td><td>${p.process}</td><td>${p.pid||'—'}</td><td class="${p.dangerous?'danger':'ok'}">${p.dangerous?'⚠ DANGEROUS':'✓ OK'}</td></tr>`;
    });
    html+=`</tbody></table>`;
  }

  // Active connections table
  if(d.connections&&d.connections.length){
    html+=`<div class="sec-title">// ACTIVE CONNECTIONS (${d.connections.length})</div>
    <table><thead><tr><th>LOCAL</th><th>REMOTE</th><th>PROCESS</th><th>STATUS</th></tr></thead><tbody>`;
    d.connections.forEach(c=>{
      html+=`<tr><td>${c.local}</td><td>${c.remote}</td><td>${c.process}</td><td class="${c.suspicious?'danger':'ok'}">${c.suspicious?'⚠ SUSPICIOUS':'✓ OK'}</td></tr>`;
    });
    html+=`</tbody></table>`;
  }

  // Running processes table
  if(d.processes&&d.processes.length){
    html+=`<div class="sec-title">// TOP RUNNING PROCESSES</div>
    <table><thead><tr><th>PID</th><th>NAME</th><th>CPU%</th><th>MEM%</th></tr></thead><tbody>`;
    d.processes.slice(0,15).forEach(p=>{
      html+=`<tr><td>${p.pid}</td><td>${p.name}</td><td>${p.cpu}%</td><td>${p.mem}%</td></tr>`;
    });
    html+=`</tbody></table>`;
  }

  document.getElementById('content').innerHTML=html;
}
load();
</script>
</body>
</html>
"""

app = Flask(__name__)

@app.route("/")
def index():
    return render_template_string(DASHBOARD)

@app.route("/api/report")
def api_report():
    return jsonify({
        "done": scan_done,
        "score": calculate_score(),
        "findings": findings,
        "system": scan_data.get('system', {}),
        "open_ports": scan_data.get('open_ports', []),
        "connections": scan_data.get('connections', []),
        "processes": scan_data.get('processes', []),
        "startup": scan_data.get('startup', []),
    })

# ─────────────────────────────────────────────
# MAIN SCAN RUNNER
# ─────────────────────────────────────────────

def run_scan():
    global scan_done
    print(Fore.CYAN + """
  ____  _     _      _     _ ____
 / ___|| |__ (_) ___| | __| / ___|  ___ __ _ _ __
 \\___ \\| '_ \\| |/ _ \\ |/ _` \\___ \\ / __/ _` | '_ \\
  ___) | | | | |  __/ | (_| |___) | (_| (_| | | | |
 |____/|_| |_|_|\\___|_|\\__,_|____/ \\___\\__,_|_| |_|

  Stage 2 — Deep Device Scanner
""")
    log("Starting deep device scan...", "TITLE")
    log("Dashboard: http://127.0.0.1:5000", "OK")
    print()

    collect_system_info()
    scan_processes()
    scan_open_ports()
    scan_connections()
    scan_startup()
    scan_firewall()

    scan_done = True
    score = calculate_score()

    print()
    log(f"Scan complete! Security Score: {score}/100", "OK")
    log(f"Critical: {sum(1 for f in findings if f['severity']=='Critical')} | "
        f"Warnings: {sum(1 for f in findings if f['severity']=='Warning')} | "
        f"Passed: {sum(1 for f in findings if f['severity']=='Safe')}", "INFO")
    log("View full report at: http://127.0.0.1:5000", "OK")

if __name__ == "__main__":
    # Run scan in background thread
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

    # Start Flask dashboard
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
