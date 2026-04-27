"""
ShieldScan — Stage 3 Backend Server
Full Platform: Database + API + Web Dashboard
 
HOW IT WORKS:
  1. User visits your website (index.html)
  2. Browser scan runs automatically (Stage 1)
  3. User downloads agent.py and runs it
  4. Agent scans their device and sends results to THIS server
  5. Server stores results in SQLite database
  6. User gets a shareable report link
 
INSTALL:
  pip install flask flask-cors psutil requests colorama
 
RUN:
  python server.py
 
DEPLOY FREE:
  - Railway.app (recommended)
  - Render.com
  - PythonAnywhere.com
"""
 
import os
import json
import uuid
import sqlite3
import hashlib
from datetime import datetime
from functools import wraps
 
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS
 
app = Flask(__name__)
CORS(app)
 
DB_FILE = "shieldscan.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "shieldscan-dev-key-change-in-production")
 
# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────
 
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn
 
def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          TEXT PRIMARY KEY,
            created_at  TEXT NOT NULL,
            ip          TEXT,
            os          TEXT,
            hostname    TEXT,
            score       INTEGER,
            critical    INTEGER DEFAULT 0,
            warnings    INTEGER DEFAULT 0,
            passed      INTEGER DEFAULT 0,
            findings    TEXT,
            system_info TEXT,
            open_ports  TEXT,
            connections TEXT,
            processes   TEXT,
            startup     TEXT,
            scan_type   TEXT DEFAULT 'browser'
        );
 
        CREATE TABLE IF NOT EXISTS stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            date        TEXT,
            total_scans INTEGER DEFAULT 0,
            avg_score   REAL DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()
    print("[OK] Database initialized")
 
# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────
 
@app.route("/api/scan", methods=["POST"])
def submit_scan():
    """Agent posts scan results here."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400
 
    scan_id = str(uuid.uuid4())[:8].upper()
    findings = data.get("findings", [])
    system  = data.get("system", {})
 
    crits = sum(1 for f in findings if f.get("severity") == "Critical")
    warns = sum(1 for f in findings if f.get("severity") == "Warning")
    passed = sum(1 for f in findings if f.get("severity") == "Safe")
 
    conn = get_db()
    conn.execute("""
        INSERT INTO scans
        (id, created_at, ip, os, hostname, score, critical, warnings, passed,
         findings, system_info, open_ports, connections, processes, startup, scan_type)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        scan_id,
        datetime.now().isoformat(),
        request.remote_addr,
        system.get("os", ""),
        system.get("hostname", ""),
        data.get("score", 0),
        crits, warns, passed,
        json.dumps(findings),
        json.dumps(system),
        json.dumps(data.get("open_ports", [])),
        json.dumps(data.get("connections", [])),
        json.dumps(data.get("processes", [])),
        json.dumps(data.get("startup", [])),
        data.get("scan_type", "agent")
    ))
    conn.commit()
    conn.close()
 
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "report_url": f"/report/{scan_id}",
        "message": f"Scan saved! View your report at /report/{scan_id}"
    })
 
 
@app.route("/api/scan/browser", methods=["POST"])
def submit_browser_scan():
    """Browser posts its scan results here."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400
 
    scan_id = str(uuid.uuid4())[:8].upper()
    findings = data.get("findings", [])
 
    crits  = sum(1 for f in findings if f.get("severity") == "Critical")
    warns  = sum(1 for f in findings if f.get("severity") == "Warning")
    passed = sum(1 for f in findings if f.get("severity") == "Safe")
 
    conn = get_db()
    conn.execute("""
        INSERT INTO scans
        (id, created_at, ip, score, critical, warnings, passed, findings, scan_type)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        scan_id,
        datetime.now().isoformat(),
        request.remote_addr,
        data.get("score", 0),
        crits, warns, passed,
        json.dumps(findings),
        "browser"
    ))
    conn.commit()
    conn.close()
 
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "report_url": f"/report/{scan_id}"
    })
 
 
@app.route("/api/report/<scan_id>")
def get_report_api(scan_id):
    """Return scan data as JSON."""
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id.upper(),)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Report not found"}), 404
    return jsonify({
        "id": row["id"],
        "created_at": row["created_at"],
        "score": row["score"],
        "critical": row["critical"],
        "warnings": row["warnings"],
        "passed": row["passed"],
        "os": row["os"],
        "hostname": row["hostname"],
        "findings": json.loads(row["findings"] or "[]"),
        "system_info": json.loads(row["system_info"] or "{}"),
        "open_ports": json.loads(row["open_ports"] or "[]"),
        "connections": json.loads(row["connections"] or "[]"),
        "processes": json.loads(row["processes"] or "[]"),
        "scan_type": row["scan_type"],
    })
 
 
@app.route("/api/stats")
def get_stats():
    """Global platform stats."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    avg   = conn.execute("SELECT AVG(score) as a FROM scans").fetchone()["a"]
    crits = conn.execute("SELECT SUM(critical) as c FROM scans").fetchone()["c"]
    conn.close()
    return jsonify({
        "total_scans": total,
        "avg_score": round(avg or 0, 1),
        "total_criticals": crits or 0,
    })
 
 
@app.route("/api/recent")
def get_recent():
    """Recent scans (anonymized)."""
    conn = get_db()
    rows = conn.execute("""
        SELECT id, created_at, score, critical, warnings, passed, os, scan_type
        FROM scans ORDER BY created_at DESC LIMIT 10
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
 
 
# ─────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────
 
@app.route("/")
def home():
    return send_from_directory(".", "index.html")
 
@app.route("/report/<scan_id>")
def report_page(scan_id):
    return send_from_directory(".", "report.html")
 
@app.route("/download")
def download_agent():
    return send_from_directory(".", "agent.py",
                               as_attachment=True,
                               download_name="shieldscan_agent.py")
 
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(".", filename)
 
 
# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
 
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "true").lower() == "true"
    print(f"""
╔══════════════════════════════════════╗
║   ShieldScan — Stage 3 Server       ║
║   http://localhost:{port}              ║
╚══════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=port, debug=debug)
 