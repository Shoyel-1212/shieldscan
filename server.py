"""
ShieldScan — Stage 3 Backend Server
Full Platform: Database + API + Web Dashboard

Routes added in this upgrade:
  POST /api/webscan          — real HTTP header fetch + security analysis
  POST /api/networkscan      — DNS lookup (real), port probe stub
  POST /api/dnslookup        — A/AAAA/MX/NS/TXT record lookup
  POST /api/whois            — WHOIS via RDAP (no external dep)
  GET  /api/stats            — enhanced with week_scans, week_criticals
  GET  /api/recent           — unchanged
  GET  /api/report/<id>      — unchanged
  POST /api/scan             — agent scan submission (unchanged)
  POST /api/scan/browser     — browser scan submission (unchanged)

Security controls:
  - SSRF protection: blocked private IP ranges + loopback for webscan
  - Input validation on every endpoint that accepts user data
  - SQL uses parameterised queries throughout
  - No stack traces exposed to client
"""

import os
import re
import json
import uuid
import socket
import secrets
import ipaddress
import sqlite3
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import requests as req_lib
from flask import Flask, request, jsonify, send_from_directory, session, redirect
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

DB_FILE    = "shieldscan.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "shieldscan-dev-key-change-in-production")
app.secret_key = SECRET_KEY

# Timeout (seconds) for outbound HTTP/DNS calls
FETCH_TIMEOUT = 8

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

        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            last_login   TEXT
        );
    """)
    conn.commit()
    conn.close()
    print("[OK] Database initialized")

# ─────────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """PBKDF2-SHA256 with random salt. Returns 'salt$hash'."""
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${h.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored 'salt$hash' string."""
    try:
        salt, h = stored.split("$", 1)
        new_h   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return secrets.compare_digest(new_h.hex(), h)
    except Exception:
        return False

def _validate_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))

def _validate_username(username: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_]{3,30}$', username))

def login_required(f):
    """Decorator — returns 401 JSON if no active session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Authentication required", "redirect": "/login"}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    """Create a new user account."""
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    # Input validation
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if not _validate_username(username):
        return jsonify({"error": "Username must be 3–30 characters, letters/numbers/underscores only"}), 400
    if not email or not _validate_email(email):
        return jsonify({"error": "A valid email address is required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(password) > 128:
        return jsonify({"error": "Password too long"}), 400

    pw_hash = _hash_password(password)
    conn    = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?,?,?,?)",
            (username, email, pw_hash, datetime.now().isoformat()),
        )
        conn.commit()
        row = conn.execute("SELECT id, username, email FROM users WHERE email=?", (email,)).fetchone()
        # Log in immediately after registration
        session["user_id"]  = row["id"]
        session["username"] = row["username"]
        session["email"]    = row["email"]
        return jsonify({"success": True, "username": row["username"], "email": row["email"]}), 201
    except sqlite3.IntegrityError as e:
        err_msg = str(e)
        if "username" in err_msg.lower():
            return jsonify({"error": "Username already taken"}), 409
        return jsonify({"error": "Email address already registered"}), 409
    finally:
        conn.close()


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Authenticate with email + password."""
    data = request.get_json(silent=True) or {}

    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, password_hash FROM users WHERE email=?", (email,)
        ).fetchone()
    finally:
        conn.close()

    # Same error message for missing user or wrong password (prevents user enumeration)
    if not row or not _verify_password(password, row["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    # Update last_login
    conn2 = get_db()
    try:
        conn2.execute("UPDATE users SET last_login=? WHERE id=?",
                      (datetime.now().isoformat(), row["id"]))
        conn2.commit()
    finally:
        conn2.close()

    session["user_id"]  = row["id"]
    session["username"] = row["username"]
    session["email"]    = row["email"]
    return jsonify({"success": True, "username": row["username"], "email": row["email"]})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Clear the session."""
    session.clear()
    return jsonify({"success": True})


@app.route("/api/auth/me")
def auth_me():
    """Return current user info if session is active."""
    if not session.get("user_id"):
        return jsonify({"authenticated": False}), 200
    return jsonify({
        "authenticated": True,
        "user_id":  session["user_id"],
        "username": session["username"],
        "email":    session["email"],
    })

# ─────────────────────────────────────────────
# INPUT VALIDATION HELPERS
# ─────────────────────────────────────────────

def _validate_url(url: str):
    """
    Returns (cleaned_url, error_string).
    Rejects non-http(s), private IPs, loopback, link-local (SSRF protection).
    """
    if not url:
        return None, "URL is required"
    url = url.strip()
    if len(url) > 2048:
        return None, "URL too long"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None, "Malformed URL"
    if parsed.scheme not in ("http", "https"):
        return None, "Only http and https URLs are permitted"
    host = parsed.hostname
    if not host:
        return None, "Cannot determine hostname from URL"
    # Resolve and block private/loopback ranges
    try:
        addr_info = socket.getaddrinfo(host, None)
        for ai in addr_info:
            ip = ipaddress.ip_address(ai[4][0])
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                return None, f"Scanning private/internal addresses is not permitted ({ip})"
    except socket.gaierror:
        return None, f"Could not resolve hostname: {host}"
    except Exception:
        return None, "Address validation error"
    return url, None


def _validate_hostname(host: str):
    """Validate a hostname or IP for DNS/network tools."""
    if not host:
        return None, "Hostname or IP is required"
    host = host.strip().lower()
    if len(host) > 253:
        return None, "Hostname too long"
    # Reject obviously private targets
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return None, f"Scanning private/internal addresses is not permitted"
    except ValueError:
        pass  # it's a hostname, not an IP — that's fine
    # Basic hostname pattern
    if not re.match(r'^[a-zA-Z0-9._\-]+$', host):
        return None, "Invalid characters in hostname"
    return host, None

# ─────────────────────────────────────────────
# WEB SECURITY SCAN
# ─────────────────────────────────────────────

# Headers we check, with metadata
SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "severity_missing": "warning",
        "why": "HSTS tells browsers to always use HTTPS. Without it, users may be downgraded to HTTP by a MITM attacker.",
        "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "label": "Content-Security-Policy (CSP)",
        "severity_missing": "warning",
        "why": "CSP reduces XSS risk by restricting which scripts, styles and resources the browser will load.",
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self'",
        "cwe": "CWE-79",
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "severity_missing": "warning",
        "why": "Prevents your page from being embedded in an iframe on another site, mitigating clickjacking attacks.",
        "example": "X-Frame-Options: DENY",
        "cwe": "CWE-1021",
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity_missing": "info",
        "why": "Stops browsers from MIME-sniffing a response away from the declared Content-Type, preventing content injection.",
        "example": "X-Content-Type-Options: nosniff",
        "cwe": "CWE-430",
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity_missing": "info",
        "why": "Controls how much referrer information is sent with requests. Missing policy may leak sensitive URLs to third parties.",
        "example": "Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity_missing": "info",
        "why": "Allows a site to restrict which browser features (camera, mic, geolocation) can be used by the page and embedded frames.",
        "example": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "cwe": "CWE-732",
    },
}

@app.route("/api/webscan", methods=["POST"])
def web_scan():
    """Fetch a URL server-side and analyse its security headers + TLS."""
    data = request.get_json(silent=True) or {}
    url, err = _validate_url(data.get("url", ""))
    if err:
        return jsonify({"error": err}), 400

    results = {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "headers": {},
        "tls": {},
        "redirect_to_https": False,
        "final_url": url,
        "status_code": None,
        "server": None,
        "findings": [],
        "score": 100,
        "error": None,
    }

    try:
        resp = req_lib.get(
            url,
            timeout=FETCH_TIMEOUT,
            allow_redirects=True,
            verify=True,
            headers={"User-Agent": "ShieldScan/2.0 Security Scanner"},
        )
        results["status_code"] = resp.status_code
        results["final_url"]   = resp.url
        results["server"]      = resp.headers.get("server", "Not disclosed")

        # Capture all response headers (lowercase keys)
        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        results["headers"] = dict(resp.headers)  # preserve original casing for display

        # HTTPS redirect check
        parsed_final = urllib.parse.urlparse(resp.url)
        results["redirect_to_https"] = (parsed_final.scheme == "https")

        # TLS info
        if parsed_final.scheme == "https":
            results["tls"]["enabled"] = True
            results["tls"]["note"]    = "Connection used HTTPS. Certificate validated by requests/OpenSSL."
        else:
            results["tls"]["enabled"] = False
            results["tls"]["note"]    = "Site does not use HTTPS. Data is transmitted in plaintext."
            results["findings"].append({
                "check": "HTTPS",
                "status": "critical",
                "label": "No HTTPS",
                "evidence": f"Final URL: {resp.url}",
                "why": "Without HTTPS, all data between the user and server is transmitted in plaintext and can be intercepted.",
                "recommendation": "Obtain a TLS certificate (free via Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
                "cwe": "CWE-319",
            })
            results["score"] -= 25

        # Analyse security headers
        for header_key, meta in SECURITY_HEADERS.items():
            value = raw_headers.get(header_key)
            if value:
                results["findings"].append({
                    "check": meta["label"],
                    "status": "pass",
                    "label": "Present",
                    "evidence": f"{header_key}: {value[:200]}",
                    "why": meta["why"],
                    "recommendation": "Header is present. Verify the policy is not overly permissive.",
                    "cwe": meta["cwe"],
                })
            else:
                sev = meta["severity_missing"]
                deduct = 15 if sev == "warning" else 5
                results["score"] -= deduct
                results["findings"].append({
                    "check": meta["label"],
                    "status": sev,
                    "label": "Missing",
                    "evidence": "Header not present in HTTP response",
                    "why": meta["why"],
                    "recommendation": f"Add this header to your server configuration.\nExample: {meta['example']}",
                    "cwe": meta["cwe"],
                })

        # Check for information disclosure
        server_hdr = raw_headers.get("server", "")
        if server_hdr and any(v in server_hdr.lower() for v in ["apache/", "nginx/", "iis/", "php/"]):
            results["findings"].append({
                "check": "Server Version Disclosure",
                "status": "info",
                "label": "Version Exposed",
                "evidence": f"Server: {server_hdr}",
                "why": "Exposing the web server version helps attackers find version-specific CVEs.",
                "recommendation": "Configure your server to suppress or genericise the Server header.",
                "cwe": "CWE-200",
            })

        results["score"] = max(0, min(100, results["score"]))

    except req_lib.exceptions.SSLError as e:
        results["error"] = "TLS/SSL certificate error — the site's certificate could not be verified."
        results["tls"]["enabled"] = False
        results["tls"]["error"]   = str(e)[:200]
        results["score"] -= 30
        results["findings"].append({
            "check": "TLS Certificate",
            "status": "critical",
            "label": "Certificate Error",
            "evidence": str(e)[:300],
            "why": "An invalid certificate means the identity of the server cannot be verified.",
            "recommendation": "Renew or replace the TLS certificate. Use a CA-signed cert from Let's Encrypt.",
            "cwe": "CWE-295",
        })
    except req_lib.exceptions.ConnectionError as e:
        results["error"] = "Connection refused or host unreachable."
    except req_lib.exceptions.Timeout:
        results["error"] = f"Request timed out after {FETCH_TIMEOUT} seconds."
    except req_lib.exceptions.TooManyRedirects:
        results["error"] = "Too many redirects — possible redirect loop."
    except Exception as e:
        # Do not expose internal details
        results["error"] = "Scan failed. Check the URL and try again."
        app.logger.error("webscan error: %s", e)

    return jsonify(results)

# ─────────────────────────────────────────────
# DNS LOOKUP
# ─────────────────────────────────────────────

@app.route("/api/dnslookup", methods=["POST"])
def dns_lookup():
    """Resolve A, AAAA, MX, NS, TXT records for a hostname."""
    data = request.get_json(silent=True) or {}
    host, err = _validate_hostname(data.get("host", ""))
    if err:
        return jsonify({"error": err}), 400

    results = {"host": host, "records": {}, "error": None}

    # We use socket for basic A/AAAA — for MX/NS/TXT we use the
    # Google DNS-over-HTTPS JSON API (pure HTTPS, no extra dep)
    DOH = "https://dns.google/resolve"

    def doh_query(name, rtype):
        try:
            r = req_lib.get(DOH, params={"name": name, "type": rtype},
                            timeout=FETCH_TIMEOUT,
                            headers={"Accept": "application/dns-json"})
            j = r.json()
            answers = j.get("Answer") or j.get("Authority") or []
            return [a["data"] for a in answers if a.get("type") == _dns_type_num(rtype)]
        except Exception:
            return []

    def _dns_type_num(t):
        return {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16}.get(t, 0)

    try:
        # A records
        results["records"]["A"] = doh_query(host, "A") or []
        results["records"]["AAAA"] = doh_query(host, "AAAA") or []
        results["records"]["MX"]   = doh_query(host, "MX")   or []
        results["records"]["NS"]   = doh_query(host, "NS")   or []
        results["records"]["TXT"]  = doh_query(host, "TXT")  or []

        if not any(results["records"].values()):
            results["error"] = f"No DNS records found for {host}"
    except Exception as e:
        results["error"] = "DNS lookup failed."
        app.logger.error("dns_lookup error: %s", e)

    return jsonify(results)

# ─────────────────────────────────────────────
# WHOIS (via RDAP — no extra dependency)
# ─────────────────────────────────────────────

@app.route("/api/whois", methods=["POST"])
def whois_lookup():
    """Fetch RDAP registration data for a domain."""
    data = request.get_json(silent=True) or {}
    host, err = _validate_hostname(data.get("host", ""))
    if err:
        return jsonify({"error": err}), 400

    # Strip to root domain for RDAP
    parts = host.split(".")
    if len(parts) >= 2:
        domain = ".".join(parts[-2:])
    else:
        domain = host

    results = {"domain": domain, "rdap": {}, "error": None}

    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        r = req_lib.get(rdap_url, timeout=FETCH_TIMEOUT,
                        headers={"User-Agent": "ShieldScan/2.0"})
        if r.status_code == 200:
            j = r.json()
            # Extract key fields safely
            results["rdap"] = {
                "ldhName":    j.get("ldhName", domain),
                "status":     j.get("status", []),
                "registrar":  _rdap_entity(j, "registrar"),
                "registrant": _rdap_entity(j, "registrant"),
                "registered": _rdap_date(j, "registration"),
                "expires":    _rdap_date(j, "expiration"),
                "updated":    _rdap_date(j, "last changed"),
                "nameservers": [ns.get("ldhName","") for ns in j.get("nameservers", [])],
            }
        elif r.status_code == 404:
            results["error"] = f"Domain {domain} not found in RDAP registry."
        else:
            results["error"] = f"RDAP returned status {r.status_code}."
    except req_lib.exceptions.Timeout:
        results["error"] = "RDAP request timed out."
    except Exception as e:
        results["error"] = "WHOIS lookup failed."
        app.logger.error("whois error: %s", e)

    return jsonify(results)

def _rdap_entity(j, role):
    for ent in j.get("entities", []):
        if role in (ent.get("roles") or []):
            return ent.get("handle") or ent.get("ldhName") or role
    return "N/A"

def _rdap_date(j, event_action):
    for ev in j.get("events", []):
        if event_action in ev.get("eventAction", "").lower():
            return ev.get("eventDate", "")[:10]
    return "N/A"

# ─────────────────────────────────────────────
# NETWORK SCAN (DNS-based host discovery)
# ─────────────────────────────────────────────

@app.route("/api/networkscan", methods=["POST"])
def network_scan():
    """
    Attempt a DNS resolution of the target and report basic reachability.
    Active port scanning is not performed server-side as it requires
    authorisation. The frontend agent (shieldscan_agent.py) provides real
    port data for the user's own machine.
    """
    data = request.get_json(silent=True) or {}
    raw_target = (data.get("target") or "").strip()

    if not raw_target:
        return jsonify({"error": "Target is required (hostname or IP)"}), 400
    if len(raw_target) > 253:
        return jsonify({"error": "Target too long"}), 400

    results = {
        "target": raw_target,
        "resolved_ips": [],
        "hostname": None,
        "reachable": False,
        "dns_ok": False,
        "note": "",
        "error": None,
    }

    try:
        # Attempt resolution
        addr_infos = socket.getaddrinfo(raw_target, None)
        ips = list({ai[4][0] for ai in addr_infos})
        results["resolved_ips"] = ips
        results["dns_ok"]       = True

        # Reverse lookup
        try:
            results["hostname"] = socket.gethostbyaddr(ips[0])[0]
        except Exception:
            results["hostname"] = raw_target

        # Simple TCP reachability check on port 443 then 80
        reachable = False
        for port in (443, 80):
            try:
                s = socket.create_connection((raw_target, port), timeout=3)
                s.close()
                reachable = True
                break
            except Exception:
                pass
        results["reachable"] = reachable
        results["note"] = (
            "Host resolved and is reachable on a web port."
            if reachable else
            "Host resolved but did not respond on ports 443 or 80. "
            "It may be firewalled or not a web server."
        )

        # Block internal IPs
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    return jsonify({
                        "error": "Scanning private/internal addresses is not permitted.",
                        "target": raw_target,
                    }), 400
            except ValueError:
                pass

    except socket.gaierror:
        results["dns_ok"] = False
        results["error"]  = f"DNS resolution failed for '{raw_target}'. Check the hostname."
    except Exception as e:
        results["error"] = "Network scan failed."
        app.logger.error("networkscan error: %s", e)

    return jsonify(results)

# ─────────────────────────────────────────────
# PING (ICMP not available without root — use TCP)
# ─────────────────────────────────────────────

@app.route("/api/ping", methods=["POST"])
def ping_host():
    """TCP-based reachability check on common ports."""
    data = request.get_json(silent=True) or {}
    host, err = _validate_hostname(data.get("host", ""))
    if err:
        return jsonify({"error": err}), 400

    results = {"host": host, "results": [], "error": None}
    probe_ports = [80, 443, 22, 25, 8080]

    for port in probe_ports:
        t_start = __import__("time").time()
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            rtt = round((__import__("time").time() - t_start) * 1000, 1)
            results["results"].append({
                "port": port, "status": "open", "rtt_ms": rtt
            })
        except socket.timeout:
            results["results"].append({"port": port, "status": "timeout", "rtt_ms": None})
        except ConnectionRefusedError:
            results["results"].append({"port": port, "status": "closed", "rtt_ms": None})
        except Exception:
            results["results"].append({"port": port, "status": "error", "rtt_ms": None})

    return jsonify(results)

# ─────────────────────────────────────────────
# EXISTING SCAN SUBMISSION ROUTES (unchanged)
# ─────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def submit_scan():
    """Agent posts scan results here."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data received"}), 400

    scan_id  = str(uuid.uuid4())[:8].upper()
    findings = data.get("findings", [])
    system   = data.get("system", {})

    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 400

    crits  = sum(1 for f in findings if f.get("severity") == "Critical")
    warns  = sum(1 for f in findings if f.get("severity") == "Warning")
    passed = sum(1 for f in findings if f.get("severity") == "Safe")

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO scans
            (id, created_at, ip, os, hostname, score, critical, warnings, passed,
             findings, system_info, open_ports, connections, processes, startup, scan_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id,
            datetime.now().isoformat(),
            request.remote_addr,
            str(system.get("os", ""))[:100],
            str(system.get("hostname", ""))[:100],
            int(data.get("score", 0)),
            crits, warns, passed,
            json.dumps(findings),
            json.dumps(system),
            json.dumps(data.get("open_ports", [])),
            json.dumps(data.get("connections", [])),
            json.dumps(data.get("processes", [])),
            json.dumps(data.get("startup", [])),
            data.get("scan_type", "agent"),
        ))
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "report_url": f"/report/{scan_id}",
        "message": f"Scan saved! View your report at /report/{scan_id}",
    })


@app.route("/api/scan/browser", methods=["POST"])
def submit_browser_scan():
    """Browser posts its scan results here."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data"}), 400

    scan_id  = str(uuid.uuid4())[:8].upper()
    findings = data.get("findings", [])

    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list"}), 400

    crits  = sum(1 for f in findings if f.get("severity") == "Critical")
    warns  = sum(1 for f in findings if f.get("severity") == "Warning")
    passed = sum(1 for f in findings if f.get("severity") == "Safe")

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO scans
            (id, created_at, ip, score, critical, warnings, passed, findings, scan_type)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            scan_id,
            datetime.now().isoformat(),
            request.remote_addr,
            int(data.get("score", 0)),
            crits, warns, passed,
            json.dumps(findings),
            "browser",
        ))
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "report_url": f"/report/{scan_id}",
    })

# ─────────────────────────────────────────────
# REPORT API
# ─────────────────────────────────────────────

@app.route("/api/report/<scan_id>")
def get_report_api(scan_id):
    """Return scan data as JSON."""
    if not re.match(r'^[A-F0-9]{8}$', scan_id.upper()):
        return jsonify({"error": "Invalid report ID format"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id.upper(),)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Report not found"}), 404
    return jsonify({
        "id":          row["id"],
        "created_at":  row["created_at"],
        "score":       row["score"],
        "critical":    row["critical"],
        "warnings":    row["warnings"],
        "passed":      row["passed"],
        "os":          row["os"],
        "hostname":    row["hostname"],
        "findings":    json.loads(row["findings"]    or "[]"),
        "system_info": json.loads(row["system_info"] or "{}"),
        "open_ports":  json.loads(row["open_ports"]  or "[]"),
        "connections": json.loads(row["connections"] or "[]"),
        "processes":   json.loads(row["processes"]   or "[]"),
        "scan_type":   row["scan_type"],
    })

# ─────────────────────────────────────────────
# STATS — enhanced with week comparison
# ─────────────────────────────────────────────

@app.route("/api/stats")
def get_stats():
    """Global platform stats with this-week vs last-week comparison."""
    conn = get_db()
    total  = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    avg    = conn.execute("SELECT AVG(score) as a FROM scans").fetchone()["a"]
    crits  = conn.execute("SELECT SUM(critical) as c FROM scans").fetchone()["c"]
    warns  = conn.execute("SELECT SUM(warnings) as c FROM scans").fetchone()["c"]

    # This week vs last week for trend arrows
    now      = datetime.now()
    wk_start = (now - timedelta(days=7)).isoformat()
    prev_start = (now - timedelta(days=14)).isoformat()

    week_scans = conn.execute(
        "SELECT COUNT(*) as c FROM scans WHERE created_at >= ?", (wk_start,)
    ).fetchone()["c"]
    prev_scans = conn.execute(
        "SELECT COUNT(*) as c FROM scans WHERE created_at >= ? AND created_at < ?",
        (prev_start, wk_start)
    ).fetchone()["c"]

    week_crits = conn.execute(
        "SELECT SUM(critical) as c FROM scans WHERE created_at >= ?", (wk_start,)
    ).fetchone()["c"] or 0
    prev_crits = conn.execute(
        "SELECT SUM(critical) as c FROM scans WHERE created_at >= ? AND created_at < ?",
        (prev_start, wk_start)
    ).fetchone()["c"] or 0

    conn.close()
    return jsonify({
        "total_scans":      total,
        "avg_score":        round(avg or 0, 1),
        "total_criticals":  crits or 0,
        "total_warnings":   warns or 0,
        "week_scans":       week_scans,
        "prev_week_scans":  prev_scans,
        "week_criticals":   week_crits,
        "prev_week_crits":  prev_crits,
    })


@app.route("/api/recent")
def get_recent():
    """Recent scans."""
    conn = get_db()
    rows = conn.execute("""
        SELECT id, created_at, score, critical, warnings, passed, os, scan_type
        FROM scans ORDER BY created_at DESC LIMIT 10
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ─────────────────────────────────────────────
# SHIELDSCAN SECURITY COPILOT
# ─────────────────────────────────────────────

# Intent keyword map — used as a lightweight pre-filter before LLM
INTENT_PATTERNS = {
    "explain_score": [
        "score", "why low", "why bad", "why is my score", "what reduced",
        "62", "points", "rating", "grade", "why did i get",
    ],
    "explain_scan": [
        "explain scan", "tell me about", "what happened", "what did you find",
        "scan result", "my result", "what is wrong", "what's wrong",
        "bro what", "summarise", "summary", "overview",
    ],
    "security_status": [
        "safe", "am i safe", "is my computer safe", "is my device safe",
        "am i protected", "how secure", "overall status",
    ],
    "show_critical": [
        "critical", "dangerous", "serious", "worst", "highest risk",
        "most important", "bad issues", "high risk", "severe",
    ],
    "remediation": [
        "fix", "solve", "how to", "how do i", "what should i do",
        "remediat", "address", "resolve", "close", "disable", "enable",
        "prevent", "stop", "remove", "patch",
    ],
    "prioritize": [
        "first", "priority", "what should i fix first", "which is most",
        "what to fix", "where to start", "what matters most",
    ],
    "network_info": [
        "port", "network", "connection", "smb", "rdp", "ftp", "445",
        "3389", "open port", "listening", "firewall",
    ],
    "educational": [
        "what is", "explain", "define", "tell me about", "what does",
        "how does", "what are", "mean", "meaning", "learn",
    ],
}

COPILOT_SYSTEM_PROMPT = """You are ShieldScan Security Copilot — an AI security analyst built into the ShieldScan cybersecurity platform. You help users understand their device security scan results, explain vulnerabilities, and guide remediation.

RULES YOU MUST FOLLOW:
1. Use the provided ShieldScan scan context as the ONLY source of truth for the user's device security status. Never invent, assume, or fabricate scan findings, scores, ports, processes, or vulnerabilities.
2. If asked about something ShieldScan did not detect/report, explicitly say "ShieldScan did not report that in this scan" — do NOT claim the device is clean or compromised based on missing data.
3. Never claim to have performed an action (closing a port, disabling a service, etc.). You are advisory only.
4. Never recommend disabling antivirus, Windows Defender, or any security software.
5. Never provide commands to execute malware, bypass security, or compromise systems.
6. Keep responses concise and structured. Use emoji section headers where helpful (🔴 🧠 🛠️ ✅).
7. Maintain conversation context. When the user says "it", "this", "that", refer to the most recently discussed finding.
8. Adapt language to the user — plain English for beginners, technical detail for advanced questions.
9. When no scan data is available, say so and suggest running a scan first.
10. For educational questions (what is malware, what is WebRTC, etc.), answer clearly as a cybersecurity tutor.

RESPONSE STYLE:
- For findings: use sections: 🔴 Risk | 🧠 Why it matters | 🛠️ What to do | ✅ How to verify
- For score explanations: reference the actual findings that deducted points
- For prioritization: rank by severity (critical first), then exposure risk
- Keep replies under 300 words unless a detailed breakdown is explicitly requested
- Never say "As an AI language model..."
- Never say "I don't have access to..." when scan data IS provided in context
"""

def _detect_intent(message: str) -> str:
    """Lightweight keyword-based intent pre-classification."""
    msg_lower = message.lower()
    scores = {intent: 0 for intent in INTENT_PATTERNS}
    for intent, keywords in INTENT_PATTERNS.items():
        for kw in keywords:
            if kw in msg_lower:
                scores[intent] += 1
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "general_conversation"

def _build_context_summary(scan_ctx: dict) -> str:
    """Convert the scan context object into a concise text block for the LLM."""
    if not scan_ctx:
        return "No scan data available. The user has not run a scan yet."

    lines = []
    score = scan_ctx.get("security_score")
    if score is not None:
        lines.append(f"Security Score: {score}/100 — Risk Level: {scan_ctx.get('risk_level', 'Unknown')}")

    scan_type = scan_ctx.get("scan_type", "unknown")
    ts = scan_ctx.get("scan_timestamp", "unknown time")
    lines.append(f"Scan Type: {scan_type} | Timestamp: {ts}")

    sys_info = scan_ctx.get("system_info", {})
    if sys_info:
        parts = []
        if sys_info.get("os"):      parts.append(f"OS: {sys_info['os']}")
        if sys_info.get("browser"): parts.append(f"Browser: {sys_info['browser']}")
        if sys_info.get("ip"):      parts.append(f"IP: {sys_info['ip']}")
        if sys_info.get("location"):parts.append(f"Location: {sys_info['location']}")
        if parts:
            lines.append("Device: " + " | ".join(parts))

    findings = scan_ctx.get("findings", [])
    critical = [f for f in findings if f.get("type") in ("critical",) or f.get("severity", "").lower() == "critical"]
    warnings = [f for f in findings if f.get("type") in ("warning",) or f.get("severity", "").lower() == "warning"]
    passed   = [f for f in findings if f.get("type") in ("safe","info") or f.get("severity", "").lower() in ("safe","info")]

    lines.append(f"Findings: {len(critical)} critical, {len(warnings)} warnings, {len(passed)} passed")

    if critical:
        lines.append("--- CRITICAL FINDINGS ---")
        for f in critical[:5]:
            name   = f.get("name") or f.get("title") or "Unknown"
            detail = f.get("detail") or f.get("description") or ""
            rec    = f.get("recommendation") or ""
            cwe    = f.get("cwe") or ""
            lines.append(f"[CRITICAL] {name}: {detail[:200]}")
            if rec:   lines.append(f"  Recommendation: {rec[:150]}")
            if cwe:   lines.append(f"  Reference: {cwe}")

    if warnings:
        lines.append("--- WARNINGS ---")
        for f in warnings[:6]:
            name   = f.get("name") or f.get("title") or "Unknown"
            detail = f.get("detail") or f.get("description") or ""
            rec    = f.get("recommendation") or ""
            lines.append(f"[WARNING] {name}: {detail[:150]}")
            if rec: lines.append(f"  Recommendation: {rec[:120]}")

    if passed:
        lines.append("--- PASSED CHECKS ---")
        for f in passed[:5]:
            name = f.get("name") or f.get("title") or "Unknown"
            lines.append(f"[PASS] {name}")

    open_ports = scan_ctx.get("open_ports", [])
    if open_ports:
        lines.append("--- OPEN PORTS ---")
        for p in open_ports[:8]:
            danger = "⚠ DANGEROUS" if p.get("dangerous") else "OK"
            lines.append(f"Port {p.get('port')} ({p.get('process','?')}) — {danger}")

    connections = scan_ctx.get("active_connections", [])
    if connections:
        lines.append("--- ACTIVE CONNECTIONS ---")
        for c in connections[:5]:
            sus = "⚠ SUSPICIOUS" if c.get("suspicious") else "OK"
            lines.append(f"{c.get('remote','?')} via {c.get('process','?')} — {sus}")

    processes = scan_ctx.get("suspicious_processes", [])
    if processes:
        lines.append("--- SUSPICIOUS PROCESSES ---")
        for p in processes[:4]:
            lines.append(f"{p.get('name','?')} (PID {p.get('pid','?')}): {p.get('detail','')[:100]}")

    score_breakdown = scan_ctx.get("score_breakdown", "")
    if score_breakdown:
        lines.append(f"Score Calculation: {score_breakdown}")

    return "\n".join(lines)

@app.route("/api/copilot/chat", methods=["POST"])
def copilot_chat():
    """
    ShieldScan Security Copilot endpoint.
    Accepts: { message, scan_context, conversation }
    Returns: { reply, intent, actions }
    API key is read from environment — never exposed to frontend.
    """
    import openai

    # ── Input validation ──────────────────────────────────────────
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data received"}), 400

    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Message is required"}), 400
    if len(message) > 2000:
        return jsonify({"error": "Message too long (max 2000 characters)"}), 400

    scan_ctx     = data.get("scan_context") or {}
    conversation = data.get("conversation") or []

    # Sanitise conversation history — only keep role/content, limit depth
    safe_history = []
    for msg in conversation[-12:]:  # last 12 messages = ~6 turns
        role    = msg.get("role", "")
        content = str(msg.get("content", ""))[:800]
        if role in ("user", "assistant") and content:
            safe_history.append({"role": role, "content": content})

    # ── Intent detection ──────────────────────────────────────────
    intent = _detect_intent(message)

    # ── Build context for LLM ─────────────────────────────────────
    ctx_summary = _build_context_summary(scan_ctx)

    # ── API key check ──────────────────────────────────────────────
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        # Fallback: rule-based response when no API key configured
        reply = _rule_based_fallback(message, intent, scan_ctx)
        return jsonify({
            "reply":   reply,
            "intent":  intent,
            "actions": _suggest_actions(scan_ctx, intent),
            "mode":    "fallback",
        })

    # ── Build LLM messages ─────────────────────────────────────────
    system_msg = COPILOT_SYSTEM_PROMPT + "\n\nCURRENT SHIELDSCAN CONTEXT:\n" + ctx_summary

    messages = [{"role": "system", "content": system_msg}]
    messages.extend(safe_history)
    messages.append({"role": "user", "content": message})

    # ── Call OpenAI ────────────────────────────────────────────────
    try:
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=os.environ.get("COPILOT_MODEL", "gpt-4o-mini"),
            messages=messages,
            max_tokens=600,
            temperature=0.4,
            timeout=20,
        )
        reply = response.choices[0].message.content.strip()

    except openai.AuthenticationError:
        app.logger.error("Copilot: OpenAI authentication failed")
        return jsonify({"error": "AI service configuration error. Check OPENAI_API_KEY."}), 500
    except openai.RateLimitError:
        return jsonify({"error": "AI service is busy. Please try again in a moment."}), 429
    except openai.APITimeoutError:
        return jsonify({"error": "AI response timed out. Please try again."}), 504
    except openai.APIConnectionError:
        return jsonify({"error": "Could not reach AI service. Check your connection."}), 503
    except Exception as e:
        app.logger.error("Copilot error: %s", type(e).__name__)
        return jsonify({"error": "AI assistant unavailable. Please try again later."}), 500

    return jsonify({
        "reply":   reply,
        "intent":  intent,
        "actions": _suggest_actions(scan_ctx, intent),
        "mode":    "ai",
    })

def _rule_based_fallback(message: str, intent: str, scan_ctx: dict) -> str:
    """
    Returns a useful response without an LLM — used when OPENAI_API_KEY
    is not configured. Covers the most common intents with real scan data.
    """
    msg = message.lower()
    findings = scan_ctx.get("findings", [])
    score    = scan_ctx.get("security_score")
    crits    = [f for f in findings if f.get("type") == "critical"]
    warns    = [f for f in findings if f.get("type") == "warning"]
    passed   = [f for f in findings if f.get("type") in ("safe","info")]

    if not scan_ctx or score is None:
        return (
            "🛡️ **No scan data available.**\n\n"
            "Run a security scan first so I can analyze your results. "
            "Click **Scanner** in the sidebar and press **RUN SECURITY SCAN**."
        )

    if intent == "explain_score" or any(w in msg for w in ["score","low","why","points","rating"]):
        breakdown = scan_ctx.get("score_breakdown","")
        parts = []
        for f in crits:  parts.append(f"• **{f.get('name','Finding')}** (Critical, −20 pts)")
        for f in warns:  parts.append(f"• **{f.get('name','Finding')}** (Warning, −8 pts)")
        detail = "\n".join(parts) if parts else "No deductions found."
        return (
            f"📊 **Security Score: {score}/100 — {scan_ctx.get('risk_level','Unknown')} Risk**\n\n"
            f"Your score was reduced by these findings:\n{detail}\n\n"
            f"{breakdown}\n\n"
            "Want me to explain any of these findings or show you how to fix them?"
        )

    if intent == "show_critical" or "critical" in msg or "dangerous" in msg:
        if not crits:
            return "✅ ShieldScan found **no critical issues** in this scan. Good news!"
        lines = [f"🔴 **{f.get('name','Finding')}**\n   {f.get('detail','')}" for f in crits]
        return f"**{len(crits)} Critical Finding(s):**\n\n" + "\n\n".join(lines)

    if intent == "security_status":
        level = scan_ctx.get("risk_level","Unknown")
        total = len(crits) + len(warns)
        if score >= 75:
            status = "✅ Your device looks relatively secure."
        elif score >= 50:
            status = "⚠️ Your device has some issues that should be addressed."
        else:
            status = "🔴 Your device has significant security concerns."
        return (
            f"{status}\n\n"
            f"**Score:** {score}/100 — **{level} Risk**\n"
            f"**Issues found:** {len(crits)} critical, {len(warns)} warnings\n"
            f"**Passed checks:** {len(passed)}\n\n"
            "Note: ShieldScan reports what it detected. A clean scan doesn't guarantee "
            "the device is completely free of all threats."
        )

    if intent == "remediation":
        top = crits[0] if crits else (warns[0] if warns else None)
        if not top:
            return "✅ No actionable issues found in this scan."
        name = top.get("name","Finding")
        rec  = top.get("recommendation","No specific recommendation available.")
        return (
            f"🛠️ **Fixing: {name}**\n\n"
            f"{rec}\n\n"
            "Always verify changes in a test environment first. "
            "These are advisory steps — ShieldScan does not make changes automatically."
        )

    if intent == "prioritize":
        if not crits and not warns:
            return "✅ Nothing to prioritize — no issues found in this scan."
        rows = []
        for i, f in enumerate(crits[:3], 1):
            rows.append(f"{i}. 🔴 **{f.get('name','?')}** — Critical")
        for i, f in enumerate(warns[:3], len(crits)+1):
            rows.append(f"{i}. ⚠️ **{f.get('name','?')}** — Warning")
        return "**Recommended fix order:**\n\n" + "\n".join(rows) + "\n\nStart with critical items — they carry the highest risk."

    if intent == "explain_scan":
        return (
            f"🛡️ **Scan Summary**\n\n"
            f"**Score:** {score}/100 — {scan_ctx.get('risk_level','Unknown')} Risk\n"
            f"**Critical:** {len(crits)} | **Warnings:** {len(warns)} | **Passed:** {len(passed)}\n\n"
            + ("\n".join(f"🔴 {f.get('name','?')}: {f.get('detail','')[:80]}" for f in crits))
            + ("\n".join(f"⚠️ {f.get('name','?')}: {f.get('detail','')[:80]}" for f in warns))
            + "\n\nAsk me to explain any finding or show you how to fix it."
        )

    # Generic fallback
    return (
        f"I'm ShieldScan Copilot. Your current security score is **{score}/100** "
        f"({scan_ctx.get('risk_level','Unknown')} risk) with {len(crits)} critical "
        f"and {len(warns)} warnings.\n\n"
        "Try asking: *Why is my score low?*, *What should I fix first?*, or *How do I fix [issue]?*\n\n"
        "💡 Add your **OPENAI_API_KEY** to `.env` for full AI-powered responses."
    )

def _suggest_actions(scan_ctx: dict, intent: str) -> list:
    """Return context-aware quick action buttons."""
    findings = scan_ctx.get("findings", [])
    score    = scan_ctx.get("security_score")
    crits    = [f for f in findings if f.get("type") == "critical"]

    if not scan_ctx or score is None:
        return [
            {"label": "Run Security Scan",       "message": "How do I run a scan?"},
            {"label": "What Can ShieldScan Do?",  "message": "What can ShieldScan check?"},
            {"label": "Learn Device Security",    "message": "Tell me about device security basics"},
        ]

    actions = [
        {"label": "Explain My Score",     "message": "Why is my security score low?"},
        {"label": "What To Fix First?",   "message": "What should I fix first?"},
        {"label": "Show Critical Issues", "message": "Show me the critical and dangerous findings"},
    ]
    if crits:
        top = crits[0].get("name","top issue")
        actions.append({"label": f"Fix: {top[:28]}", "message": f"How do I fix the {top} issue?"})
    if intent in ("explain_score", "show_critical"):
        actions.append({"label": "Explain This Finding", "message": "Can you explain that finding in more detail?"})
    if intent == "remediation":
        actions.append({"label": "How To Verify Fix",    "message": "How do I verify the fix worked?"})
    return actions[:5]

# ─────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────

@app.route("/login")
def login_page():
    return send_from_directory(".", "login.html")

@app.route("/")
def home():
    return send_from_directory(".", "index.html")

@app.route("/report/<scan_id>")
def report_page(scan_id):
    return send_from_directory(".", "index.html")

@app.route("/download")
def download_agent():
    return send_from_directory(".", "shieldscan_agent.py",
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
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "true").lower() == "true"
    print(f"""
╔══════════════════════════════════════════╗
║   ShieldScan v2.0 — Stage 3 Server      ║
║   http://localhost:{port}                  ║
║   New endpoints: /api/webscan            ║
║                  /api/dnslookup          ║
║                  /api/whois              ║
║                  /api/networkscan        ║
║                  /api/ping               ║
╚══════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=port, debug=debug)
