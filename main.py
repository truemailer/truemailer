# main.py
# Truemailer - Full production-ready email verification server (Flask)
# Features:
#  - API key auth (clients.json)
#  - Per-key daily rate limits (persisted)
#  - Big disposable blocklist fetched & merged from multiple sources (background)
#  - Trusted-provider allowlist
#  - Heuristic detection for new disposable domains
#  - MX lookup fallback (dnspython)
#  - Endpoints: / (UI), /verify (POST + GET), /status, /update-now, /create-key (admin), /logs
#  - Logging and file persistence

import os
import re
import json
import time
import queue
import atexit
import logging
import threading
import datetime
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
import requests
import dns.resolver

# -------------------------
# CONFIGURATION
# -------------------------
APP_NAME = "Truemailer"
PORT = int(os.environ.get("PORT", 5000))

# File storage
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BLOCKLIST_DIR = os.path.join(BASE_DIR, "blocklist")
BLOCKLIST_FILE = os.path.join(BLOCKLIST_DIR, "blocklist.txt")
CLIENTS_FILE = os.path.join(BASE_DIR, "clients.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(BLOCKLIST_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Logging setup
LOG_PATH = os.path.join(LOG_DIR, "server.log")
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Trusted providers (fast-pass)
TRUSTED_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "yahoo.com", "icloud.com", "protonmail.com", "zoho.com",
    "mail.com", "yandex.com", "aol.com", "gmx.com", "fastmail.com",
    "tutanota.com"
}

# Remote blocklist sources (mirrors + public sources)
REMOTE_BLOCKLIST_URLS = [
    # primary large lists
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
    # fallback mirrors (if one fails)
    "https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/disposable-email-blacklist.conf"
]

# default clients (demo)
DEFAULT_CLIENTS = {
    "demo": {
        "key": "demo_key_123",
        "name": "Demo Client",
        "limit": 200,
        "usage": {}  # usage keyed by YYYY-MM-DD
    }
}

# updater timing
DEFAULT_UPDATE_INTERVAL_SECONDS = 24 * 3600  # once per day

# Heuristics: suspicious patterns that often appear in disposable domains
SUSPECT_PATTERNS = [
    "temp", "tempmail", "trash", "mailinator", "mail", "inbox",
    "fake", "spam", "grr", "gta5", "forex", "free", "getnada",
    "shark", "guerrilla", "guerrillamail", "zero", "0mail"
]

# -------------------------
# APP + STATE
# -------------------------
app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# in-memory sets and locks
BLOCKSET = set()
BLOCKSET_LOCK = threading.Lock()

# clients state (loaded from file)
CLIENTS = {}
CLIENTS_LOCK = threading.Lock()

# update queue (to avoid parallel fetches)
_update_queue = queue.Queue()

# -------------------------
# UTILITIES
# -------------------------
def load_clients():
    global CLIENTS
    if os.path.exists(CLIENTS_FILE):
        try:
            with open(CLIENTS_FILE, "r", encoding="utf-8") as fh:
                CLIENTS = json.load(fh)
                logging.info("Loaded clients.json (keys=%d)", len(CLIENTS))
        except Exception as e:
            logging.exception("Failed to load clients.json: %s", e)
            CLIENTS = DEFAULT_CLIENTS.copy()
    else:
        CLIENTS = DEFAULT_CLIENTS.copy()
        save_clients()

def save_clients():
    try:
        with CLIENTS_LOCK:
            with open(CLIENTS_FILE, "w", encoding="utf-8") as fh:
                json.dump(CLIENTS, fh, indent=2)
    except Exception as e:
        logging.exception("Failed to save clients.json: %s", e)

def load_local_blocklist():
    domains = set()
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    ln = line.strip().lower()
                    if not ln or ln.startswith("#"):
                        continue
                    # some lists include local@domain entries
                    if '@' in ln and ln.count('@') == 1:
                        ln = ln.split('@', 1)[1]
                    domains.add(ln)
        except Exception as e:
            logging.exception("Failed to load local blocklist: %s", e)
    return domains

def save_local_blocklist(domains):
    try:
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as fh:
            for d in sorted(domains):
                fh.write(d + "\n")
        logging.info("Saved blocklist to %s (%d domains)", BLOCKLIST_FILE, len(domains))
    except Exception as e:
        logging.exception("Failed to save blocklist: %s", e)

# Basic email format regex (fast)
EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,255}$')

def is_valid_syntax(email: str) -> bool:
    return bool(EMAIL_RE.match(email))

def domain_from_email(email: str) -> str:
    return email.split("@", 1)[-1].lower().strip()

def has_mx(domain: str, timeout: float = 2.0) -> bool:
    try:
        dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return True
    except Exception:
        return False

def is_suspicious_pattern(domain: str) -> bool:
    low = domain.lower()
    # check for patterns
    for p in SUSPECT_PATTERNS:
        if p in low:
            return True
    # lots of digits (like x12345xyz) - often disposable
    digits = sum(c.isdigit() for c in low)
    if digits >= 4:
        return True
    # very short label (like a6.co) sometimes suspect
    labels = low.split(".")
    if any(len(lbl) <= 2 for lbl in labels if lbl.isalpha()):
        return True
    return False

# -------------------------
# BLOCKLIST FETCHER & MERGER
# -------------------------
def fetch_remote_blocklist_once():
    """
    Fetch remote lists, merge them and save locally.
    Returns number of unique domains fetched (int).
    """
    domains = set()
    headers = {"User-Agent": "Truemailer-Updater/1.0 (+https://example.com)"}
    for url in REMOTE_BLOCKLIST_URLS:
        try:
            logging.info("Fetching blocklist source: %s", url)
            r = requests.get(url, timeout=30, headers=headers)
            if r.status_code == 200:
                text = r.text
                # extract probable domain-like tokens
                # Many lists are plain domain-per-line; this will also handle JSON arrays
                for line in text.splitlines():
                    ln = line.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    # If line looks like JSON array element, try to extract domain
                    if '"' in ln or "'" in ln:
                        # basic cleanup
                        ln = ln.strip('"\' ,')
                    ln = ln.strip().lower()
                    if not ln:
                        continue
                    # remove local@ entries
                    if '@' in ln and ln.count('@') == 1:
                        ln = ln.split('@', 1)[1]
                    # simple domain validation: has a dot and only allowed chars
                    if re.match(r'^[a-z0-9\.-]+\.[a-z]{2,}$', ln):
                        domains.add(ln)
                logging.info("Fetched %d lines from %s", len(text.splitlines()), url)
            else:
                logging.warning("Source returned status %s for %s", r.status_code, url)
        except Exception as e:
            logging.exception("Failed to fetch %s: %s", url, e)

    # include any local blocklist extras
    local = load_local_blocklist()
    domains.update(local)
    save_local_blocklist(domains)
    return len(domains)

def updater_background_loop(interval_seconds: int = DEFAULT_UPDATE_INTERVAL_SECONDS):
    """
    Runs forever in background to update blocklist periodically.
    """
    while True:
        try:
            logging.info("Updater loop: fetching remote blocklists...")
            count = fetch_remote_blocklist_once()
            logging.info("Updater loop: merged %d domains", count)
            # reload into memory
            with BLOCKSET_LOCK:
                global BLOCKSET
                BLOCKSET = load_local_blocklist()
                logging.info("Blockset loaded into memory (%d domains)", len(BLOCKSET))
        except Exception as e:
            logging.exception("Updater loop failed: %s", e)
        time.sleep(interval_seconds)

def start_background_updater(interval_seconds: int = DEFAULT_UPDATE_INTERVAL_SECONDS):
    # spawn the background thread for updater
    t = threading.Thread(target=updater_background_loop, args=(interval_seconds,), daemon=True, name="blocklist-updater")
    t.start()
    logging.info("Started background updater thread")

# Manual fetch helper (callable from endpoint)
def manual_update_blocklist():
    n = fetch_remote_blocklist_once()
    with BLOCKSET_LOCK:
        global BLOCKSET
        BLOCKSET = load_local_blocklist()
    return n

# -------------------------
# CLIENT / QUOTA HELPERS
# -------------------------
def get_client_by_key(key: str) -> Optional[str]:
    with CLIENTS_LOCK:
        for cid, info in CLIENTS.items():
            if info.get("key") == key:
                return cid
    return None

def check_and_consume_quota_for_key(key: str) -> (bool, Optional[str]):
    """
    Return (True, None) if allowed and quota consumed, else (False, reason)
    """
    with CLIENTS_LOCK:
        cid = get_client_by_key(key)
        if cid is None:
            return False, "invalid_api_key"
        client = CLIENTS[cid]
        # find today's date
        today = datetime.date.today().isoformat()
        usage = client.setdefault("usage", {})
        cnt = usage.get(today, 0)
        limit = client.get("limit", client.get("limit", 100))
        if cnt >= limit:
            return False, "daily_limit_exceeded"
        usage[today] = cnt + 1
        # persist small write
        save_clients()
        return True, None

def create_client_key(name: str, limit: int = 100) -> Dict[str, Any]:
    ts = int(time.time())
    key = f"{name}-{ts}"
    with CLIENTS_LOCK:
        CLIENTS[key] = {
            "key": key,
            "name": name,
            "limit": limit,
            "usage": {}
        }
        save_clients()
    return {"key": key, "limit": limit, "name": name}

# -------------------------
# CORE VERIFICATION LOGIC
# -------------------------
def is_disposable_domain(domain: str) -> bool:
    domain = domain.lower().strip()
    with BLOCKSET_LOCK:
        if domain in BLOCKSET:
            return True
    # pattern heuristics
    if is_suspicious_pattern(domain):
        return True
    return False

def verify_email_core(email: str) -> Dict[str, Any]:
    """Return a result dict describing verification outcome."""
    email = (email or "").strip()
    if not email:
        return {"email": email, "valid": False, "reason": "empty"}
    # syntax check
    if not is_valid_syntax(email):
        return {"email": email, "valid": False, "reason": "invalid_syntax"}
    domain = domain_from_email(email)
    # trusted provider quick-pass
    if domain in TRUSTED_PROVIDERS:
        mx_ok = has_mx(domain)
        return {"email": email, "valid": True, "reason": "trusted_provider", "disposable": False, "mx": mx_ok, "provider": domain}
    # disposable check
    if is_disposable_domain(domain):
        mx_ok = has_mx(domain)
        return {"email": email, "valid": False, "reason": "disposable_domain", "disposable": True, "mx": mx_ok}
    # MX check fallback
    mx_ok = has_mx(domain)
    if not mx_ok:
        return {"email": email, "valid": False, "reason": "no_mx", "disposable": False, "mx": False}
    # passed
    return {"email": email, "valid": True, "reason": "valid", "disposable": False, "mx": True, "provider": domain}

# -------------------------
# ROUTES
# -------------------------
@app.route("/", methods=["GET"])
def home():
    """Simple HTML UI to test verify endpoint (form posts to /verify)."""
    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>{APP_NAME} — Demo</title>
        <style>
          body {{ font-family: Arial, sans-serif; background:#f6f8fa; color:#0b1226; }}
          .wrap {{ max-width:760px; margin:40px auto; background:#fff; padding:20px; border-radius:8px; box-shadow:0 6px 24px rgba(0,0,0,0.06); }}
          input, button {{ padding:10px; margin:6px 0; font-size:16px; border-radius:6px; border:1px solid #ddd; }}
          button {{ background:#0b79f7; color:#fff; border:0; padding:10px 18px; cursor:pointer; }}
          pre {{ background:#f3f4f6; padding:12px; border-radius:6px; }}
        </style>
      </head>
      <body>
        <div class="wrap">
          <h2>{APP_NAME} — Email Verifier (Demo)</h2>
          <p>Enter email and API key (demo key shown). The server auto-updates blocklists in background.</p>
          <form id="verifyForm" method="post" action="/verify">
            <input type="text" id="email" name="email" placeholder="someone@example.com" style="width:60%" required>
            <input type="text" id="api_key" name="api_key" placeholder="API key (demo_key_123)" style="width:35%; margin-left:8px" required>
            <br>
            <button type="submit">Verify</button>
          </form>
          <p>Demo key: <strong>demo_key_123</strong></p>
          <h4>Result</h4>
          <pre id="out">Use the form above to test.</pre>
          <p><a href="/status">Status</a> • <a href="/update-now">Update blocklist now</a></p>
        </div>

        <script>
        document.getElementById('verifyForm').addEventListener('submit', async function(e) {{
          e.preventDefault();
          const out = document.getElementById('out');
          out.textContent = 'Checking...';
          const email = document.getElementById('email').value;
          const api_key = document.getElementById('api_key').value;
          try {{
            const form = new FormData();
            form.append('email', email);
            form.append('api_key', api_key);
            const res = await fetch('/verify', {{ method: 'POST', body: form }});
            const j = await res.json();
            out.textContent = JSON.stringify(j, null, 2);
          }} catch (err) {{
            out.textContent = 'Error: ' + err.message;
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
    return jsonify({"ok": True, "loaded_domains": loaded, "client_keys": client_keys})

@app.route("/verify", methods=["GET", "POST"])
def verify_route():
    """
    GET: /verify?email=...&api_key=...
    POST form-data: email, api_key
    """
    if request.method == "GET":
        email = request.args.get("email", "").strip()
        api_key = request.args.get("api_key", "").strip()
    else:
        # POST
        email = (request.form.get("email") or "").strip()
        api_key = (request.form.get("api_key") or "").strip()

    # require api key by default
    if CLIENTS and isinstance(CLIENTS, dict):
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        cid = get_client_by_key(api_key)
        if cid is None:
            return jsonify({"error": "Invalid API key"}), 401
        ok, reason = check_and_consume_quota_for_key(api_key)
        if not ok:
            return jsonify({"error": reason}), 429

    # run core verification
    try:
        result = verify_email_core(email)
        # log the check
        logging.info("verify: %s -> %s", email, result.get("reason"))
        return jsonify(result)
    except Exception as e:
        logging.exception("Error verifying email: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/update-now", methods=["GET", "POST"])
def update_now_route():
    """
    Manually trigger blocklist update. Optional form/query field 'trigger_key' - must be valid key if present.
    """
    trigger_key = request.values.get("trigger_key")
    if trigger_key:
        if get_client_by_key(trigger_key) is None:
            return jsonify({"error": "Invalid trigger_key"}), 401
    try:
        count = manual_update_blocklist()
        return jsonify({"updated": True, "domains": count})
    except Exception as e:
        logging.exception("update-now failed: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/create-key", methods=["POST"])
def create_key_route():
    """
    Create a new client key (admin). Protected by master_key header or form 'master_key'.
    Use the value in MASTER_KEY env or default 'master-2025' for now.
    """
    master_key_env = os.environ.get("MASTER_KEY", "master-2025")
    provided = request.headers.get("X-Master-Key") or request.form.get("master_key") or request.json.get("master_key") if request.is_json else None
    if provided != master_key_env:
        return jsonify({"error": "Unauthorized (master key required)"}), 403
    # parse name and limit
    name = (request.values.get("name") or "client").strip()
    limit = int(request.values.get("limit") or 100)
    client = create_client_key(name, limit)
    return jsonify({"created": True, "client": client})

@app.route("/logs", methods=["GET"])
def logs():
    # restricted view (master key)
    master_key_env = os.environ.get("MASTER_KEY", "master-2025")
    provided = request.headers.get("X-Master-Key")
    if provided != master_key_env:
        return jsonify({"error": "Unauthorized"}), 403
    if not os.path.exists(LOG_PATH):
        return jsonify({"logs": []})
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as fh:
            lines = fh.readlines()[-200:]
        return jsonify({"logs": lines})
    except Exception as e:
        logging.exception("Failed to read logs: %s", e)
        return jsonify({"error": str(e)}), 500

# -------------------------
# STARTUP: load clients + blocklist + start updater
# -------------------------
def initialize_server():
    load_clients()
    # load local blocklist if available
    with BLOCKSET_LOCK:
        global BLOCKSET
        BLOCKSET = load_local_blocklist()
    logging.info("Initial blockset size: %d", len(BLOCKSET))
    # Start background updater thread (daemon)
    start_background_updater(DEFAULT_UPDATE_INTERVAL_SECONDS)

# ensure we initialize when module is loaded
initialize_server()

# Clean shutdown: save clients on exit
def _shutdown_save():
    try:
        save_clients()
        logging.info("Saved clients on shutdown")
    except Exception:
        pass

atexit.register(_shutdown_save)

# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    logging.info("%s starting on port %s", APP_NAME, PORT)
    # For development/testing on Replit, use Flask built-in
    app.run(host="0.0.0.0", port=PORT)
