"""
ShieldScan Agent v2 — Deep Device Scanner
Sends results to ShieldScan server and gives you a report link.
 
USAGE:
  python shieldscan_agent.py
  python shieldscan_agent.py --server https://your-deployed-url.com
 
INSTALL:
  pip install psutil requests colorama flask
"""
 
import os, sys, json, socket, platform, subprocess, threading, argparse, time
from datetime import datetime
from collections import defaultdict
import psutil, requests
from colorama import Fore, Style, init
from flask import Flask, jsonify, render_template_string
 
init(autoreset=True)
 
# ── CONFIG ───────────────────────────────────
SUSPICIOUS = ["njrat","nanocore","darkcomet","quasar","netwire","blackshades","remcos","orcus","asyncrat","keylogger","ardamax","refog","xmrig","minerd","cpuminer","nicehash","payload","beacon","rat.exe","spy.exe","svchost32","csrss32","lsass32"]
DANGEROUS_PORTS = {21:"FTP unencrypted",23:"Telnet (very dangerous)",135:"Windows RPC",139:"NetBIOS",445:"SMB (WannaCry target)",3389:"Remote Desktop (RDP)",4444:"Metasploit shell",5900:"VNC remote desktop",6666:"IRC botnet",6667:"IRC botnet",9050:"Tor proxy"}
BAD_CONN_PORTS = [4444,1337,6666,6667,31337,12345,54321]
 
findings, scan_data = [], {}
scan_done = False
 
# ── HELPERS ──────────────────────────────────
def ts(): return datetime.now().strftime("%H:%M:%S")
def log(msg, lv="INFO"):
    c={"INFO":Fore.CYAN,"WARN":Fore.YELLOW,"CRIT":Fore.RED,"OK":Fore.GREEN,"TITLE":Fore.MAGENTA}.get(lv,Fore.WHITE)
    print(f"{c}[{lv}]{Style.RESET_ALL} {ts()} {msg}")
 
def add(sev, name, detail, rec=""):
    findings.append({"severity":sev,"name":name,"detail":detail,"recommendation":rec,"time":ts()})
    log(f"[{sev}] {name}", "CRIT" if sev=="Critical" else "WARN" if sev=="Warning" else "OK")
 
# ── MODULES ──────────────────────────────────
def scan_processes():
    log("Scanning processes for malware signatures...", "INFO")
    all_p, found = [], []
    for p in psutil.process_iter(['pid','name','exe','cmdline','cpu_percent','memory_percent']):
        try:
            i=p.info; nl=(i['name']or'').lower(); cl=' '.join(i.get('cmdline')or[]).lower()
            all_p.append({"pid":i['pid'],"name":i['name'],"exe":i.get('exe')or'',"cpu":round(i.get('cpu_percent')or 0,1),"mem":round(i.get('memory_percent')or 0,1)})
            for s in SUSPICIOUS:
                if s in nl or s in cl:
                    found.append(i['name'])
                    add("Critical",f"Suspicious Process: {i['name']}",f"PID {i['pid']} | {i.get('exe','unknown')} | Matches: '{s}'","Terminate immediately and run antivirus.")
                    break
        except: pass
    scan_data['processes']=all_p[:25]
    if not found: add("Safe","Process Scan Clean",f"Scanned {len(all_p)} processes. No malware signatures found.")
    log(f"Scanned {len(all_p)} processes, {len(found)} flagged", "OK")
 
def scan_ports():
    log("Scanning open ports...", "INFO")
    ports, danger = [], []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status=='LISTEN' and c.laddr:
                port=c.laddr.port
                try: proc=psutil.Process(c.pid).name() if c.pid else "unknown"
                except: proc="unknown"
                p={"port":port,"process":proc,"pid":c.pid,"dangerous":port in DANGEROUS_PORTS}
                ports.append(p)
                if port in DANGEROUS_PORTS:
                    danger.append(port)
                    add("Warning",f"Dangerous Port Open: {port}",f"Port {port} — {DANGEROUS_PORTS[port]} — opened by: {proc}",f"Close port {port} if not needed.")
    except psutil.AccessDenied: log("Run as admin for full port scan","WARN")
    scan_data['open_ports']=ports
    if not danger: add("Safe","No Dangerous Ports",f"{len(ports)} ports open, none flagged as dangerous.")
    log(f"{len(ports)} ports open, {len(danger)} dangerous", "OK")
 
def scan_connections():
    log("Analyzing active network connections...", "INFO")
    conns, sus = [], []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status=='ESTABLISHED' and c.raddr:
                rip,rport=c.raddr.ip,c.raddr.port
                try: proc=psutil.Process(c.pid).name() if c.pid else "unknown"
                except: proc="unknown"
                isSus=rport in BAD_CONN_PORTS
                ci={"local":f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "","remote":f"{rip}:{rport}","process":proc,"suspicious":isSus}
                conns.append(ci)
                if isSus:
                    sus.append(ci)
                    add("Critical","Suspicious Outbound Connection",f"'{proc}' → {rip}:{rport} — known malware/RAT port","Block in firewall and investigate this process.")
    except psutil.AccessDenied: pass
    scan_data['connections']=conns[:20]
    if not sus: add("Safe","Connections Clean",f"{len(conns)} active connections. None to known malicious ports.")
    log(f"{len(conns)} connections, {len(sus)} suspicious", "OK")
 
def scan_startup():
    log("Checking startup programs...", "INFO")
    items=[]
    if platform.system()=="Windows":
        for path in [r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"]:
            try:
                out=subprocess.run(["reg","query",path],capture_output=True,text=True,timeout=5).stdout
                for line in out.splitlines():
                    if "REG_SZ" in line:
                        parts=line.strip().split("REG_SZ"); name=parts[0].strip(); val=parts[1].strip() if len(parts)>1 else ""
                        items.append({"name":name,"path":val,"location":path})
                        for s in SUSPICIOUS:
                            if s in name.lower() or s in val.lower():
                                add("Critical",f"Suspicious Startup: {name}",f"Registry: {path}\nPath: {val}","Remove from Task Manager > Startup tab.")
                                break
            except: pass
    elif platform.system()=="Linux":
        for d in [os.path.expanduser("~/.config/autostart"),"/etc/init.d"]:
            if os.path.exists(d):
                for f in os.listdir(d)[:10]: items.append({"name":f,"path":os.path.join(d,f),"location":d})
    scan_data['startup']=items
    if items: add("Info",f"{len(items)} Startup Programs",f"Review startup entries to ensure none are unwanted.","Check Task Manager > Startup.")
    else: add("Safe","Startup Clean","No suspicious startup entries found.")
    log(f"Found {len(items)} startup entries", "OK")
 
def scan_firewall():
    log("Checking firewall...", "INFO")
    if platform.system()=="Windows":
        try:
            out=subprocess.run(["netsh","advfirewall","show","allprofiles","state"],capture_output=True,text=True,timeout=5).stdout.lower()
            if "off" in out: add("Critical","Firewall DISABLED","Windows Firewall is turned off. Your device is exposed.","Go to Windows Security > Firewall and turn it ON.")
            else: add("Safe","Firewall Active","Windows Firewall is enabled on all profiles.")
        except: add("Info","Firewall","Could not check firewall. Run as administrator.","")
    elif platform.system()=="Linux":
        try:
            out=subprocess.run(["ufw","status"],capture_output=True,text=True,timeout=5).stdout
            if "inactive" in out.lower(): add("Warning","UFW Firewall Inactive","UFW is not running.","Run: sudo ufw enable")
            else: add("Safe","UFW Active","Linux firewall is running.")
        except: add("Info","Firewall","Could not check UFW.","")
 
def collect_sysinfo():
    u=platform.uname()
    scan_data['system']={"os":f"{u.system} {u.release}","hostname":u.node,"machine":u.machine,"cpu_count":psutil.cpu_count(),"ram_gb":round(psutil.virtual_memory().total/(1024**3),1),"disk_gb":round(psutil.disk_usage('/').total/(1024**3),1),"boot_time":datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M"),"local_ip":socket.gethostbyname(socket.gethostname()),"scan_time":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 
def calc_score():
    s=100
    for f in findings:
        if f['severity']=='Critical': s-=20
        elif f['severity']=='Warning': s-=8
    return max(0,min(100,s))
 
def send_to_server(server_url):
    try:
        score=calc_score()
        r=requests.post(f"{server_url}/api/scan",json={"score":score,"findings":findings,"system":scan_data.get('system',{}),"open_ports":scan_data.get('open_ports',[]),"connections":scan_data.get('connections',[]),"processes":scan_data.get('processes',[]),"startup":scan_data.get('startup',[]),"scan_type":"agent"},timeout=10)
        d=r.json()
        if d.get('scan_id'):
            log(f"Report saved! ID: {d['scan_id']}", "OK")
            log(f"View report: {server_url}/report/{d['scan_id']}", "OK")
            return d['scan_id']
    except Exception as e:
        log(f"Could not reach server: {e}", "WARN")
        log("Running in local-only mode. Start server.py to save reports.", "WARN")
    return None
 
def run_scan(server_url):
    global scan_done
    print(Fore.CYAN+"""
  ____  _     _      _     _ ____
 / ___|| |__ (_) ___| | __| / ___|  ___ __ _ _ __
 \___ \| '_ \| |/ _ \ |/ _` \___ \ / __/ _` | '_ \\
  ___) | | | | |  __/ | (_| |___) | (_| (_| | | | |
 |____/|_| |_|_|\___|_|\__,_|____/ \___\__,_|_| |_|
 
  Stage 2+3 — Deep Device Scanner + Server Agent
""")
    log("Starting deep device scan...", "TITLE")
    collect_sysinfo()
    scan_processes()
    scan_ports()
    scan_connections()
    scan_startup()
    scan_firewall()
    scan_done=True
    score=calc_score()
    crits=sum(1 for f in findings if f['severity']=='Critical')
    warns=sum(1 for f in findings if f['severity']=='Warning')
    print()
    log(f"Scan complete! Score: {score}/100 | Critical: {crits} | Warnings: {warns}", "OK")
    if server_url:
        scan_id=send_to_server(server_url)
    log("Done!", "OK")
 
if __name__=="__main__":
    parser=argparse.ArgumentParser(description="ShieldScan Agent")
    parser.add_argument("--server",default="http://127.0.0.1:5000",help="ShieldScan server URL")
    args=parser.parse_args()
    run_scan(args.server)