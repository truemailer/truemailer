# main.py — Truemailer (final production Flask)
# Replace your current main.py entirely with this file.

import os
import re
import json
import time
import atexit
import logging
import threading
import datetime
from typing import Optional, Dict, Any
from pathlib import Path

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import dns.resolver

# ---------------- CONFIG ----------------
APP_NAME = "Truemailer"
PORT = int(os.environ.get("PORT", 5000))
BASE_DIR = Path(__file__).resolve().parent
BLOCKLIST_DIR = BASE_DIR / "blocklist"
BLOCKLIST_FILE = BLOCKLIST_DIR / "blocklist.txt"
CLIENTS_FILE = BASE_DIR / "clients.json"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "server.log"

BLOCKLIST_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Remote sources (multiple mirrors increases reliability)
REMOTE_BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
    "https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt"
]

# Trusted providers (allow-list)
TRUSTED_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "yahoo.com", "icloud.com", "protonmail.com", "zoho.com",
    "mail.com", "yandex.com", "aol.com", "gmx.com", "fastmail.com",
    "tutanota.com"
}

# suspicious patterns (heuristic)
SUSPECT_PATTERNS = [
    "temp", "tempmail", "mailinator", "inbox", "trash", "shark",
    "guerrilla", "getnada", "spam", "fake", "free", "gta5", "forex",
    "yopmail", "dispostable", "mintemail"
]

DEFAULT_UPDATE_INTERVAL = 24 * 3600  # fetch every 24h (seconds)
DEFAULT_CLIENT_LIMIT = 100
MASTER_KEY = os.environ.get("MASTER_KEY", "master-2025")

# default demo client (if clients.json missing)
DEFAULT_CLIENTS = {
    "demo": {"key": "demo_key_123", "name": "Demo Client", "limit": DEFAULT_CLIENT_LIMIT, "usage": {}}
}

# ---------------- LOGGING ----------------
logging.basicConfig(filename=str(LOG_FILE), level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("requests").setLevel(logging.WARNING)

# ---------------- APP & STATE ----------------
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

BLOCKSET = set()
BLOCKSET_LOCK = threading.Lock()

CLIENTS: Dict[str, Dict[str, Any]] = {}
CLIENTS_LOCK = threading.Lock()

# ---------------- helpers for JSON files ----------------
def safe_load_json(path: Path, default):
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        else:
            with path.open("w", encoding="utf-8") as fh:
                json.dump(default, fh, indent=2)
            return default.copy()
    except Exception as e:
        logging.exception("safe_load_json error for %s: %s", path, e)
        return default.copy()

def safe_write_json(path: Path, data):
    try:
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception as e:
        logging.exception("safe_write_json error for %s: %s", path, e)

# ---------------- clients ----------------
def load_clients():
    global CLIENTS
    CLIENTS = safe_load_json(CLIENTS_FILE, DEFAULT_CLIENTS)
    logging.info("Loaded clients: %d", len(CLIENTS))

def save_clients():
    safe_write_json(CLIENTS_FILE, CLIENTS)
    logging.info("Saved clients.json")

def get_client_id_by_key(key: str) -> Optional[str]:
    with CLIENTS_LOCK:
        for cid, info in CLIENTS.items():
            if info.get("key") == key:
                return cid
    return None

def check_and_consume_quota(key: str):
    if not key:
        return False, "missing_api_key"
    cid = get_client_id_by_key(key)
    if cid is None:
        return False, "invalid_api_key"
    with CLIENTS_LOCK:
        client = CLIENTS[cid]
        today = datetime.date.today().isoformat()
        usage = client.setdefault("usage", {})
        cnt = usage.get(today, 0)
        limit = client.get("limit", DEFAULT_CLIENT_LIMIT)
        if cnt >= limit:
            return False, "daily_limit_exceeded"
        usage[today] = cnt + 1
        save_clients()
    return True, None

def create_client_key(name: str, limit: int = DEFAULT_CLIENT_LIMIT) -> Dict[str, Any]:
    ts = int(time.time())
    key = f"{name}-{ts}"
    with CLIENTS_LOCK:
        CLIENTS[key] = {"key": key, "name": name, "limit": int(limit), "usage": {}}
        save_clients()
    return {"key": key, "name": name, "limit": int(limit)}

# ---------------- blocklist local load/save ----------------
def load_local_blocklist() -> set:
    domains = set()
    try:
        if BLOCKLIST_FILE.exists():
            with BLOCKLIST_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    ln = line.strip().lower()
                    if not ln or ln.startswith("#"):
                        continue
                    if "@" in ln and ln.count("@") == 1:
                        ln = ln.split("@", 1)[1]
                    domains.add(ln)
        logging.info("Loaded local blocklist (%d domains)", len(domains))
    except Exception as e:
        logging.exception("load_local_blocklist error: %s", e)
    return domains

def save_local_blocklist(domains: set):
    try:
        with BLOCKLIST_FILE.open("w", encoding="utf-8") as fh:
            for d in sorted(domains):
                fh.write(d + "\n")
        logging.info("Saved local blocklist (%d domains) to %s", len(domains), BLOCKLIST_FILE)
    except Exception as e:
        logging.exception("save_local_blocklist error: %s", e)

# ---------------- fetch & merge remote blocklists ----------------
def fetch_remote_blocklists_once() -> int:
    domains = set()
    headers = {"User-Agent": f"{APP_NAME}-updater/1.0"}
    for url in REMOTE_BLOCKLIST_URLS:
        try:
            logging.info("Fetching blocklist source: %s", url)
            r = requests.get(url, timeout=30, headers=headers)
            if r.status_code == 200:
                text = r.text
                for line in text.splitlines():
                    ln = line.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    ln = ln.strip('"\', ')
                    if "@" in ln and ln.count("@") == 1:
                        ln = ln.split("@", 1)[1]
                    ln = ln.lower()
                    if re.match(r'^[a-z0-9\.-]+\.[a-z]{2,}$', ln):
                        domains.add(ln)
                logging.info("Source %s contributed; total now %d", url, len(domains))
            else:
                logging.warning("Source %s responded status %s", url, r.status_code)
        except Exception as e:
            logging.exception("Error fetching %s: %s", url, e)
            continue
    local = load_local_blocklist()
    domains.update(local)
    save_local_blocklist(domains)
    return len(domains)

# ---------------- background updater ----------------
def background_updater_loop(interval: int = DEFAULT_UPDATE_INTERVAL):
    while True:
        try:
            logging.info("Background updater: fetching remote blocklists...")
            total = fetch_remote_blocklists_once()
            logging.info("Background updater: merged total domains %d", total)
            with BLOCKSET_LOCK:
                global BLOCKSET
                BLOCKSET = load_local_blocklist()
                logging.info("Background updater: BLOCKSET loaded (%d)", len(BLOCKSET))
        except Exception as e:
            logging.exception("Background updater error: %s", e)
        time.sleep(interval)

def start_background_updater(interval: int = DEFAULT_UPDATE_INTERVAL):
    t = threading.Thread(target=background_updater_loop, args=(interval,), daemon=True)
    t.start()
    logging.info("Started background updater thread")

# ---------------- heuristics & checks ----------------
EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,255}$')

def is_valid_email_syntax(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))

def domain_from_email(email: str) -> str:
    return (email.split("@", 1)[-1] or "").lower().strip()

def has_mx(domain: str, timeout: float = 2.0) -> bool:
    try:
        dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return True
    except Exception:
        return False

def suspicious_by_pattern(domain: str) -> bool:
    d = domain.lower()
    for p in SUSPECT_PATTERNS:
        if p in d:
            return True
    digits = sum(c.isdigit() for c in d)
    if digits >= 4:
        return True
    labels = d.split(".")
    if any(len(lbl) <= 2 and lbl.isalpha() for lbl in labels):
        return True
    return False

def is_disposable_domain(domain: str) -> bool:
    domain = domain.lower().strip()
    with BLOCKSET_LOCK:
        if domain in BLOCKSET:
            return True
    if suspicious_by_pattern(domain):
        return True
    return False

# ---------------- core verification ----------------
def verify_email_core(email: str) -> Dict[str, Any]:
    email = (email or "").strip()
    if not email:
        return {"email": email, "valid": False, "reason": "empty"}
    if not is_valid_email_syntax(email):
        return {"email": email, "valid": False, "reason": "invalid_syntax"}
    domain = domain_from_email(email)
    if domain in TRUSTED_PROVIDERS:
        mx_ok = has_mx(domain)
        return {"email": email, "valid": True, "reason": "trusted_provider", "disposable": False, "mx": mx_ok, "provider": domain}
    if is_disposable_domain(domain):
        mx_ok = has_mx(domain)
        return {"email": email, "valid": False, "reason": "disposable_domain", "disposable": True, "mx": mx_ok, "provider": domain}
    mx_ok = has_mx(domain)
    if not mx_ok:
        return {"email": email, "valid": False, "reason": "no_mx", "disposable": False, "mx": False, "provider": domain}
    return {"email": email, "valid": True, "reason": "valid", "disposable": False, "mx": True, "provider": domain}

# ---------------- routes ----------------
@app.route("/", methods=["GET"])
def home():
    html = f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>{APP_NAME} — Demo</title></head>
      <body style="font-family:Arial;margin:30px;">
        <h2>{APP_NAME} — Email Verifier (Demo)</h2>
        <p>Enter email & API key (demo: <strong>demo_key_123</strong>)</p>
        <form id="f">
          <input name="email" id="email" placeholder="someone@example.com" style="width:60%;padding:8px" required>
          <input name="api_key" id="api_key" placeholder="API key" style="width:30%;padding:8px" required>
          <br/><br/><button type="submit" style="padding:10px 18px">Verify</button>
        </form>
        <h4>Result</h4>
        <pre id="out">Use the form above</pre>
        <p><a href="/status">Status</a> • <a href="/update-now">Update blocklist now</a></p>
        <script>
        document.getElementById('f').addEventListener('submit', async function(e){{
          e.preventDefault();
          const out = document.getElementById('out');
          out.textContent = 'Checking...';
          const form = new FormData(e.target);
          try {{
            const res = await fetch('/verify', {{ method: 'POST', body: form }});
            const txt = await res.text();
            try {{
              const j = JSON.parse(txt);
              out.textContent = JSON.stringify(j, null, 2);
            }} catch (err) {{
              out.textContent = 'Invalid JSON from server:\\n' + txt;
            }}
          }} catch (err) {{
            out.textContent = 'Network error: ' + err.message;
          }}
        }});
        </script>
      </body>
    </html>
    """
    return html

@app.route("/status", methods=["GET"])
def status():
    with BLOCKSET_LOCK:
        loaded = len(BLOCKSET)
    with CLIENTS_LOCK:
        client_keys = list(CLIENTS.keys())
    return jsonify({"ok": True, "loaded_domains": loaded, "client_keys": client_keys, "time": datetime.datetime.utcnow().isoformat() + "Z"})

@app.route("/verify", methods=["GET", "POST"])
def verify_route():
    try:
        if request.method == "GET":
            email = (request.args.get("email") or "").strip()
            api_key = (request.args.get("api_key") or "").strip()
        else:
            ct = (request.content_type or "").lower()
            if ct.startswith("application/json"):
                body = request.get_json(silent=True) or {}
                email = (body.get("email") or "").strip()
                api_key = (body.get("api_key") or "").strip()
            else:
                email = (request.form.get("email") or "").strip()
                api_key = (request.form.get("api_key") or "").strip()

        if not api_key:
            return jsonify({"error": "API key required"}), 401
        ok, reason = check_and_consume_quota(api_key)
        if not ok:
            status = 429 if reason == "daily_limit_exceeded" else 401
            return jsonify({"error": reason}), status

        result = verify_email_core(email)
        logging.info("verify: %s -> %s", email, result.get("reason"))
        return jsonify(result)
    except Exception as e:
        logging.exception("Exception in /verify: %s", e)
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500

@app.route("/update-now", methods=["GET", "POST"])
def update_now_route():
    try:
        trigger_key = (request.values.get("trigger_key") or "").strip()
        if trigger_key:
            if get_client_id_by_key(trigger_key) is None:
                return jsonify({"error": "invalid trigger_key"}), 401
        count = fetch_remote_blocklists_once()
        with BLOCKSET_LOCK:
            global BLOCKSET
            BLOCKSET = load_local_blocklist()
        return jsonify({"updated": True, "domains": count})
    except Exception as e:
        logging.exception("update-now failed: %s", e)
        return jsonify({"error": "update_failed", "detail": str(e)}), 500

@app.route("/create-key", methods=["POST"])
def create_key_route():
    try:
        provided = (request.headers.get("X-Master-Key") or request.form.get("master_key") or (request.get_json(silent=True) or {}).get("master_key"))
        if provided != MASTER_KEY:
            return jsonify({"error": "unauthorized"}), 403
        name = (request.values.get("name") or "").strip() or "client"
        limit_raw = (request.values.get("limit") or None)
        try:
            limit = int(limit_raw) if limit_raw else DEFAULT_CLIENT_LIMIT
        except Exception:
            limit = DEFAULT_CLIENT_LIMIT
        new = create_client_key(name, limit)
        logging.info("Created new key for %s (limit %d)", name, limit)
        return jsonify({"created": True, "client": new})
    except Exception as e:
        logging.exception("create-key failed: %s", e)
        return jsonify({"error": "create_failed", "detail": str(e)}), 500

@app.route("/logs", methods=["GET"])
def logs_route():
    try:
        provided = request.headers.get("X-Master-Key")
        if provided != MASTER_KEY:
            return jsonify({"error": "unauthorized"}), 403
        if not LOG_FILE.exists():
            return jsonify({"logs": []})
        with LOG_FILE.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()[-500:]
        return jsonify({"logs": lines})
    except Exception as e:
        logging.exception("logs retrieval failed: %s", e)
        return jsonify({"error": "logs_failed", "detail": str(e)}), 500

# ---------------- initialization ----------------
def initialize_server():
    load_clients()
    with BLOCKSET_LOCK:
        global BLOCKSET
        BLOCKSET = load_local_blocklist()
    logging.info("Server init: BLOCKSET size %d", len(BLOCKSET))
    start_background_updater(DEFAULT_UPDATE_INTERVAL)
    logging.info("Server init complete")

def on_shutdown():
    try:
        save_clients()
        logging.info("Saved clients on shutdown")
    except Exception:
        pass

atexit.register(on_shutdown)
initialize_server()

# ---------------- run ----------------
if __name__ == "__main__":
    logging.info("%s starting on port %s", APP_NAME, PORT)
    app.run(host="0.0.0.0", port=PORT)
