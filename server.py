"""
ShieldScan — Stage 3 Backend (Railway Fixed)
"""
import os, json, uuid, sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
 
app = Flask(__name__)
CORS(app)
 
DB_FILE = "shieldscan.db"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
 
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn
 
def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            ip TEXT, os TEXT, hostname TEXT,
            score INTEGER,
            critical INTEGER DEFAULT 0,
            warnings INTEGER DEFAULT 0,
            passed INTEGER DEFAULT 0,
            findings TEXT, system_info TEXT,
            open_ports TEXT, connections TEXT,
            processes TEXT, startup TEXT,
            scan_type TEXT DEFAULT 'browser'
        );
    """)
    conn.commit()
    conn.close()
 
@app.route("/")
def home():
    return send_file(os.path.join(BASE_DIR, "index.html"))
 
@app.route("/report/<scan_id>")
def report_page(scan_id):
    return send_file(os.path.join(BASE_DIR, "report.html"))
 
@app.route("/download")
def download_agent():
    return send_file(os.path.join(BASE_DIR, "shieldscan_agent.py"), as_attachment=True, download_name="shieldscan_agent.py")
 
@app.route("/api/scan", methods=["POST"])
def submit_scan():
    data = request.get_json()
    if not data: return jsonify({"error": "No data"}), 400
    scan_id = str(uuid.uuid4())[:8].upper()
    findings = data.get("findings", [])
    system = data.get("system", {})
    crits = sum(1 for f in findings if f.get("severity") == "Critical")
    warns = sum(1 for f in findings if f.get("severity") == "Warning")
    passed = sum(1 for f in findings if f.get("severity") == "Safe")
    conn = get_db()
    conn.execute("INSERT INTO scans (id,created_at,ip,os,hostname,score,critical,warnings,passed,findings,system_info,open_ports,connections,processes,startup,scan_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, datetime.now().isoformat(), request.remote_addr, system.get("os",""), system.get("hostname",""),
         data.get("score",0), crits, warns, passed, json.dumps(findings), json.dumps(system),
         json.dumps(data.get("open_ports",[])), json.dumps(data.get("connections",[])),
         json.dumps(data.get("processes",[])), json.dumps(data.get("startup",[])), data.get("scan_type","agent")))
    conn.commit(); conn.close()
    return jsonify({"success": True, "scan_id": scan_id, "report_url": f"/report/{scan_id}"})
 
@app.route("/api/scan/browser", methods=["POST"])
def submit_browser_scan():
    data = request.get_json()
    if not data: return jsonify({"error": "No data"}), 400
    scan_id = str(uuid.uuid4())[:8].upper()
    findings = data.get("findings", [])
    crits = sum(1 for f in findings if f.get("severity") == "Critical")
    warns = sum(1 for f in findings if f.get("severity") == "Warning")
    passed = sum(1 for f in findings if f.get("severity") == "Safe")
    conn = get_db()
    conn.execute("INSERT INTO scans (id,created_at,ip,score,critical,warnings,passed,findings,scan_type) VALUES (?,?,?,?,?,?,?,?,?)",
        (scan_id, datetime.now().isoformat(), request.remote_addr, data.get("score",0), crits, warns, passed, json.dumps(findings), "browser"))
    conn.commit(); conn.close()
    return jsonify({"success": True, "scan_id": scan_id, "report_url": f"/report/{scan_id}"})
 
@app.route("/api/report/<scan_id>")
def get_report(scan_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id.upper(),)).fetchone()
    conn.close()
    if not row: return jsonify({"error": "Not found"}), 404
    return jsonify({"id": row["id"], "created_at": row["created_at"], "score": row["score"],
        "critical": row["critical"], "warnings": row["warnings"], "passed": row["passed"],
        "os": row["os"], "hostname": row["hostname"],
        "findings": json.loads(row["findings"] or "[]"),
        "system_info": json.loads(row["system_info"] or "{}"),
        "open_ports": json.loads(row["open_ports"] or "[]"),
        "connections": json.loads(row["connections"] or "[]"),
        "processes": json.loads(row["processes"] or "[]"),
        "scan_type": row["scan_type"]})
 
@app.route("/api/stats")
def get_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    avg = conn.execute("SELECT AVG(score) as a FROM scans").fetchone()["a"]
    crits = conn.execute("SELECT SUM(critical) as c FROM scans").fetchone()["c"]
    conn.close()
    return jsonify({"total_scans": total, "avg_score": round(avg or 0, 1), "total_criticals": crits or 0})
 
init_db()
 
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
 
    app.run(host="0.0.0.0", port=port, debug=debug)
 
