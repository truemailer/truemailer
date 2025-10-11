# main.py - Truemailer (Render-ready, full version)
# - Flask app (stable on Render)
# - / (HTML UI), /verify (GET + POST), /status, /update-now, /create-key
# - Local blocklist load (blocklist/blocklist.txt)
# - Clients + API-key + daily limits (clients.json)
# - Syntax -> trusted -> blocklist -> pattern -> MX checks

import os
import json
import time
import datetime
import threading
import re
import requests
import dns.resolver
from flask import Flask, request, jsonify, send_file, render_template_string

# -------------------------
# Configuration / Paths
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BLOCKLIST_DIR = os.path.join(BASE_DIR, "blocklist")
BLOCKLIST_FILE = os.path.join(BLOCKLIST_DIR, "blocklist.txt")
CLIENTS_FILE = os.path.join(BASE_DIR, "clients.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(BLOCKLIST_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# -------------------------
# Default configuration
# -------------------------
DEFAULT_CONFIG = {
    "require_api_key": True,
    "rate_limit_per_day": 100,
    "trusted_providers": [
        "gmail.com","googlemail.com","outlook.com","hotmail.com","yahoo.com",
        "icloud.com","protonmail.com","zoho.com","mail.com","yandex.com"
    ],
    "remote_blocklist_urls": [
        "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt",
        "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
        "https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt"
    ],
    "pattern_suspicious": ["mail", "inbox", "temp", "trash", "shark", "gta5", "forex"],
    "mx_check_enabled": True
}

# -------------------------
# Helpers: load/save JSON
# -------------------------
def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # write default
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
    except Exception:
        pass
    return default.copy()

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# -------------------------
# Load config & clients
# -------------------------
CONFIG = load_json(CONFIG_FILE, DEFAULT_CONFIG)

CLIENTS_DEFAULT = {
    "demo": {
        "key": "demo_key_123",
        "name": "Demo Client",
        "limit": CONFIG.get("rate_limit_per_day", 100),
        "usage": {}
    }
}
CLIENTS = load_json(CLIENTS_FILE, CLIENTS_DEFAULT)

# -------------------------
# Blocklist in memory
# -------------------------
BLOCKSET = set()
BLOCKSET_LOCK = threading.Lock()

# If local small sample missing, create with some known disposables
SAMPLE_BLOCKS = [
    "tempmail.com","10minutemail.com","mailinator.com","yopmail.com","getnada.com",
    "guerrillamail.com","sharklasers.com","inilas.com","forexzig.com","gta5hx.com"
]

def write_sample_blocklist():
    if not os.path.exists(BLOCKLIST_FILE) or os.path.getsize(BLOCKLIST_FILE) < 10:
        try:
            with open(BLOCKLIST_FILE, "w", encoding="utf-8") as fh:
                for d in SAMPLE_BLOCKS:
                    fh.write(d + "\n")
            print("[startup] wrote sample blocklist")
        except Exception:
            pass

def load_local_blocklist():
    s = set()
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE, "r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip().lower()
                    if not ln or ln.startswith("#"):
                        continue
                    # if entry contains local part@domain, sanitize
                    if "@" in ln and ln.count("@") == 1:
                        ln = ln.split("@",1)[1]
                    s.add(ln)
        except Exception:
            pass
    return s

def save_blocklist(domains):
    os.makedirs(BLOCKLIST_DIR, exist_ok=True)
    try:
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as fh:
            for d in sorted(domains):
                fh.write(d + "\n")
    except Exception:
        pass

# -------------------------
# Fetch remote blocklists (called by /update-now or manual)
# -------------------------
def fetch_and_merge_remote():
    urls = CONFIG.get("remote_blocklist_urls", [])
    domains = set()
    for u in urls:
        try:
            r = requests.get(u, timeout=30)
            if r.status_code == 200:
                # parse lines or json; take anything that looks like domain
                text = r.text
                for ln in text.splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if "@" in ln and ln.count("@") == 1:
                        ln = ln.split("@",1)[1]
                    ln = ln.lower()
                    # quick sanity filter
                    if "." in ln and len(ln) > 3:
                        domains.add(ln)
        except Exception as e:
            print("fetch fail", u, e)
            continue
    # merge with local
    local = load_local_blocklist()
    domains.update(local)
    save_blocklist(domains)
    return domains

def refresh_blockset():
    global BLOCKSET
    new = fetch_and_merge_remote()
    with BLOCKSET_LOCK:
        BLOCKSET = set(new)
    return len(BLOCKSET)

# -------------------------
# Initial load (startup)
# -------------------------
write_sample_blocklist()
BLOCKSET = load_local_blocklist()
print(f"[startup] Loaded {len(BLOCKSET)} blocklist entries (may be sample).")

# -------------------------
# Background updater (optional, non-blocking)
# -------------------------
def updater_loop(interval_seconds=24*3600):
    while True:
        try:
            n = refresh_blockset()
            print(f"[updater] merged remote lists: {n} domains")
        except Exception as e:
            print("[updater] error:", e)
        time.sleep(interval_seconds)

# Start the background thread but do not block
t = threading.Thread(target=updater_loop, args=(24*3600,), daemon=True)
t.start()

# -------------------------
# Utilities: clients & quotas
# -------------------------
def get_client_by_key(key):
    for cid, info in CLIENTS.items():
        if info.get("key") == key:
            return cid, info
    return None, None

def check_and_consume_quota(client_id):
    now_day = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    client = CLIENTS.get(client_id)
    if not client:
        return False, "invalid client"
    usage = client.setdefault("usage", {})
    cnt = usage.get(now_day, 0)
    if cnt >= client.get("limit", CONFIG.get("rate_limit_per_day", 100)):
        return False, "daily limit exceeded"
    usage[now_day] = cnt + 1
    save_json(CLIENTS_FILE, CLIENTS)
    return True, None

def domain_from_email(email):
    try:
        return email.split("@",1)[1].lower().strip()
    except Exception:
        return ""

def has_mx(domain, timeout=2.0):
    if not CONFIG.get("mx_check_enabled", True):
        return True
    try:
        dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return True
    except Exception:
        return False

# -------------------------
# Pattern suspicious check
# -------------------------
def is_suspicious_by_pattern(domain):
    domain = domain.lower()
    for p in CONFIG.get("pattern_suspicious", []):
        if p in domain:
            return True
    return False

# -------------------------
# Flask app & routes
# -------------------------
app = Flask(__name__)

# Basic HTML template for home form
HOME_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Truemailer — Demo</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;background:#f6f8fa;color:#0b1226;padding:20px}
    .card{max-width:720px;margin:30px auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,0.06)}
    input,button{padding:10px 12px;font-size:15px;border-radius:6px;border:1px solid #ddd}
    button{background:#0b79f7;color:#fff;border:0;margin-left:8px}
    pre{background:#f3f4f6;padding:12px;border-radius:6px}
    .small{color:#666;font-size:13px}
  </style>
</head>
<body>
  <div class="card">
    <h2>Truemailer — Email Verifier (Demo)</h2>
    <p class="small">Enter an email and API key to test. Demo API key: <strong>demo_key_123</strong></p>
    <form method="post" action="/verify">
      <input name="email" placeholder="someone@example.com" style="width:60%" required>
      <input name="api_key" placeholder="API key (demo_key_123)" style="width:30%;margin-left:8px" required>
      <br><br>
      <button type="submit">Verify</button>
    </form>
    <br>
    <pre id="out">{{result}}</pre>
    <p class="small">Status: loaded <strong>{{loaded}}</strong> domains. Use <code>/update-now</code> to refresh blocklist.</p>
  </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    loaded = len(BLOCKSET)
    return render_template_string(HOME_HTML, result="Enter email + key and click Verify", loaded=loaded)

# GET /verify?email=...&api_key=...
@app.route("/verify", methods=["GET"])
def verify_get():
    email = request.args.get("email", "").strip()
    api_key = request.args.get("api_key", "").strip()

    if CONFIG.get("require_api_key", True):
        if not api_key:
            return jsonify({"detail": "API key required (?api_key=...)" }), 401
        cid, info = get_client_by_key(api_key)
        if cid is None:
            return jsonify({"detail":"Invalid API key"}), 401
        ok,msg = check_and_consume_quota(cid)
        if not ok:
            return jsonify({"detail": msg}), 429

    # basic syntax
    if "@" not in email or not re.match(r"^[^@\s]{1,64}@[^@\s]{1,255}$", email):
        return jsonify({"email": email, "valid": False, "reason": "invalid_syntax"})

    domain = domain_from_email(email)
    if not domain:
        return jsonify({"email": email, "valid": False, "reason": "invalid_domain"})

    # trusted providers quick-pass
    if domain in CONFIG.get("trusted_providers", []):
        mx = has_mx(domain)
        return jsonify({"email": email, "valid": True, "reason":"trusted_provider", "mx": mx, "provider": domain})

    # blocklist check
    with BLOCKSET_LOCK:
        is_disposable = domain in BLOCKSET

    # pattern heuristics
    suspected = is_suspicious_by_pattern(domain)

    if is_disposable or suspected:
        return jsonify({"email": email, "valid": False, "reason": "disposable_or_suspicious", "disposable": bool(is_disposable), "suspected": suspected})

    # MX check fallback
    mx = has_mx(domain)
    if not mx:
        return jsonify({"email": email, "valid": False, "reason":"no_mx", "mx": False})

    return jsonify({"email": email, "valid": True, "reason":"valid", "mx": True, "provider": domain})

# POST /verify (form from UI)
@app.route("/verify", methods=["POST"])
def verify_post():
    email = (request.form.get("email") or "").strip()
    api_key = (request.form.get("api_key") or "").strip()
    result = {}
    # reuse GET handler behavior but allow internal call
    # call verify_get by building args - simpler: replicate logic
    if CONFIG.get("require_api_key", True):
        if not api_key:
            return render_template_string(HOME_HTML, result="API key required", loaded=len(BLOCKSET))
        cid, info = get_client_by_key(api_key)
        if cid is None:
            return render_template_string(HOME_HTML, result="Invalid API key", loaded=len(BLOCKSET))
        ok,msg = check_and_consume_quota(cid)
        if not ok:
            return render_template_string(HOME_HTML, result=f"Limit error: {msg}", loaded=len(BLOCKSET))

    # syntax
    if "@" not in email or not re.match(r"^[^@\s]{1,64}@[^@\s]{1,255}$", email):
        return render_template_string(HOME_HTML, result=json.dumps({"email": email, "valid": False, "reason": "invalid_syntax"}, indent=2), loaded=len(BLOCKSET))

    domain = domain_from_email(email)
    if domain in CONFIG.get("trusted_providers", []):
        mx = has_mx(domain)
        return render_template_string(HOME_HTML, result=json.dumps({"email": email, "valid": True, "reason":"trusted_provider", "mx": mx, "provider": domain}, indent=2), loaded=len(BLOCKSET))

    with BLOCKSET_LOCK:
        is_disposable = domain in BLOCKSET
    suspected = is_suspicious_by_pattern(domain)
    if is_disposable or suspected:
        return render_template_string(HOME_HTML, result=json.dumps({"email": email, "valid": False, "reason":"disposable_or_suspicious","disposable": bool(is_disposable), "suspected": suspected}, indent=2), loaded=len(BLOCKSET))

    mx = has_mx(domain)
    if not mx:
        return render_template_string(HOME_HTML, result=json.dumps({"email": email, "valid": False, "reason":"no_mx","mx": False}, indent=2), loaded=len(BLOCKSET))

    return render_template_string(HOME_HTML, result=json.dumps({"email": email, "valid": True, "reason":"valid","mx": True, "provider": domain}, indent=2), loaded=len(BLOCKSET))

# -------------------------
# Admin endpoint to fetch & update remote lists now
# -------------------------
@app.route("/update-now", methods=["POST"])
def update_now():
    # optional api_key check to limit who can trigger
    trigger_key = request.form.get("trigger_key") or request.args.get("trigger_key")
    if trigger_key:
        cid, info = get_client_by_key(trigger_key)
        if cid is None:
            return jsonify({"ok": False, "detail": "Invalid trigger key"}), 401
    # run fetch & merge synchronously
    try:
        domains = fetch_and_merge_remote()
        # refresh in-memory blockset
        with BLOCKSET_LOCK:
            global BLOCKSET
            BLOCKSET = load_local_blocklist()
        return jsonify({"ok": True, "domains_loaded": len(domains)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------
# Status & create-key admin
# -------------------------
@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "ok": True,
        "loaded": len(BLOCKSET),
        "clients": list(CLIENTS.keys()),
        "config": {"require_api_key": CONFIG.get("require_api_key", True)}
    })

@app.route("/create-key", methods=["POST"])
def create_key():
    # Basic admin protection: pass master_key in form or args (change to secure flow later)
    master = request.form.get("master_key") or request.args.get("master_key")
    if master != "MASTER_SECRET_2025":
        return jsonify({"ok": False, "error": "unauthorized"}), 403
    name = request.form.get("name") or f"user{int(time.time())}"
    limit = int(request.form.get("limit") or CONFIG.get("rate_limit_per_day", 100))
    new_key = f"{name}-{int(time.time())}"
    CLIENTS[new_key] = {"key": new_key, "name": name, "limit": limit, "usage": {}}
    save_json(CLIENTS_FILE, CLIENTS)
    return jsonify({"ok": True, "key": new_key, "limit": limit})

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # ensure blocklist exists
    BLOCKSET = load_local_blocklist()
    if len(BLOCKSET) == 0:
        print("[main] blocklist empty -> you should run /update-now or run updater.py to fetch full lists.")
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Truemailer on port {port}")
    app.run(host="0.0.0.0", port=port)
