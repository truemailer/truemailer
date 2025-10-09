# main.py - Truemailer (Full version)
# Features:
# - API key auth (clients.json)
# - Per-key daily rate limits (persisted)
# - Disposable domain blocklist check (blocklist/blocklist.txt + remote merge)
# - MX check (dnspython)
# - GET and POST /verify endpoints
# - Background updater (24h), and manual /update-now trigger
# - /status for quick health

import os
import json
import time
import threading
import re
from typing import Optional
from datetime import datetime
import requests
import dns.resolver

from fastapi import FastAPI, HTTPException, Request, Form, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

# ---------- Config & file paths ----------
APP_NAME = "Truemailer"
CONFIG_FILE = "config.json"
CLIENTS_FILE = "clients.json"
BLOCKLIST_TXT = os.path.join("blocklist", "blocklist.txt")

# Default config (written to config.json if not present)
DEFAULT_CONFIG = {
    "require_api_key": True,
    "rate_limit_per_day": 100,
    "trusted_providers": [
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "icloud.com", "protonmail.com", "zoho.com", "mail.com", "yandex.com"
    ],
    "remote_blocklist_urls": [
        # your two forks + public repo
        "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains/refs/heads/master/domains.txt",
        "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains1/refs/heads/main/disposable_email_blocklist.conf",
        "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt"
    ],
    "update_interval_seconds": 24 * 3600,
    "mx_check_enabled": True
}

# ---------- Utils: load/save config & clients ----------
def load_json_file(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # write default if not exist
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
    except Exception:
        pass
    return default.copy()

CONFIG = load_json_file(CONFIG_FILE, DEFAULT_CONFIG)
CLIENTS = load_json_file(CLIENTS_FILE, {
    "demo": {"key": "demo_key_123", "name": "Demo Client", "limit": CONFIG.get("rate_limit_per_day", 100), "usage": {}}
})

def save_clients():
    try:
        with open(CLIENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(CLIENTS, f, indent=2)
    except Exception:
        pass

# ---------- Blocklist handling (in-memory set) ----------
BLOCKSET = set()
BLOCKSET_LOCK = threading.Lock()

def load_local_blocklist():
    s = set()
    if os.path.exists(BLOCKLIST_TXT):
        try:
            with open(BLOCKLIST_TXT, "r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    ln = ln.strip().lower()
                    if not ln or ln.startswith("#"):
                        continue
                    # handle entries that may include local-part@domain
                    if "@" in ln and ln.count("@") == 1:
                        ln = ln.split("@", 1)[1]
                    s.add(ln)
        except Exception:
            pass
    return s

def save_blocklist(domains):
    os.makedirs(os.path.dirname(BLOCKLIST_TXT), exist_ok=True)
    try:
        with open(BLOCKLIST_TXT, "w", encoding="utf-8") as fh:
            for d in sorted(domains):
                fh.write(d + "\n")
    except Exception:
        pass

def fetch_and_merge_remote():
    urls = CONFIG.get("remote_blocklist_urls", [])
    domains = set()
    for u in urls:
        try:
            r = requests.get(u, timeout=30)
            if r.status_code == 200:
                for ln in r.text.splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if "@" in ln and ln.count("@") == 1:
                        ln = ln.split("@", 1)[1]
                    domains.add(ln.lower())
        except Exception:
            # ignore per-source failures
            continue
    # include local extras
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

# try initial load (best-effort)
try:
    BLOCKSET = load_local_blocklist()
    # start a background thread to fetch remote lists without blocking startup
    threading.Thread(target=refresh_blockset, daemon=True).start()
except Exception:
    BLOCKSET = set()

# background updater thread
def updater_loop():
    interval = CONFIG.get("update_interval_seconds", 24 * 3600)
    while True:
        try:
            refreshed = refresh_blockset()
            print(f"[updater] refreshed blockset; {refreshed} domains")
        except Exception as e:
            print("[updater] error refreshing:", e)
        time.sleep(interval)

threading.Thread(target=updater_loop, daemon=True).start()

# ---------- FastAPI app ----------
app = FastAPI(title=APP_NAME)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

# helper regex for basic syntax check (fast)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")

def get_client_by_key(key: str):
    for cid, info in CLIENTS.items():
        if info.get("key") == key:
            return cid, info
    return None, None

def check_and_consume_quota(client_id: str):
    now_day = datetime.utcnow().strftime("%Y-%m-%d")
    client = CLIENTS.get(client_id)
    if client is None:
        return False, "invalid client"
    usage = client.setdefault("usage", {})
    cnt = usage.get(now_day, 0)
    if cnt >= client.get("limit", CONFIG.get("rate_limit_per_day", 100)):
        return False, "daily limit exceeded"
    usage[now_day] = cnt + 1
    # persist small write
    save_clients()
    return True, None

def domain_from_email(email: str) -> str:
    return email.split("@", 1)[-1].lower().strip()

def has_mx(domain: str, timeout: float = 2.0) -> bool:
    if not CONFIG.get("mx_check_enabled", True):
        return True
    try:
        dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return True
    except Exception:
        return False

# ---------- Endpoints ----------
@app.get("/")
def home():
    p = os.path.join("static", "index.html")
    if os.path.exists(p):
        return FileResponse(p)
    return JSONResponse({"message": "Truemailer is running. Use /verify"}, status_code=200)

@app.get("/status")
def status():
    return {"ok": True, "loaded": len(BLOCKSET), "clients": list(CLIENTS.keys())}

@app.post("/update-now")
def update_now(trigger_key: Optional[str] = Form(None)):
    """
    Manual trigger to refresh the blocklist now.
    If you provide a trigger_key, it must be a valid client key (optional).
    """
    if trigger_key:
        cid, info = get_client_by_key(trigger_key)
        if cid is None:
            raise HTTPException(status_code=401, detail="Invalid trigger key")
    n = refresh_blockset()
    return {"updated": True, "domains": n}

@app.get("/verify")
def verify_get(email: str = Query(..., description="Email to verify"), api_key: Optional[str] = Query(None)):
    """
    GET /verify?email=someone@domain.tld&api_key=KEY
    Useful for quick browser testing.
    """
    # required api key enforcement
    if CONFIG.get("require_api_key", True):
        key = api_key
        if not key:
            raise HTTPException(status_code=401, detail="API key required (?api_key=...)")
        cid, info = get_client_by_key(key)
        if cid is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        ok, msg = check_and_consume_quota(cid)
        if not ok:
            raise HTTPException(status_code=429, detail=msg)
    else:
        cid = "anonymous"

    email = email.strip()
    if not EMAIL_RE.match(email):
        return JSONResponse({"email": email, "valid": False, "reason": "invalid_syntax"})

    domain = domain_from_email(email)

    # trusted provider quick-pass
    if domain in CONFIG.get("trusted_providers", []):
        mx = has_mx(domain)
        return JSONResponse({"email": email, "valid": True, "reason": "trusted_provider", "disposable": False, "mx": mx, "provider": domain})

    # check blocklist
    with BLOCKSET_LOCK:
        is_disposable = domain in BLOCKSET

    if is_disposable:
        return JSONResponse({"email": email, "valid": False, "reason": "disposable_domain", "disposable": True})

    # mx check
    mx = has_mx(domain)
    if not mx:
        return JSONResponse({"email": email, "valid": False, "reason": "no_mx", "disposable": False, "mx": False})
    return JSONResponse({"email": email, "valid": True, "reason": "valid", "disposable": False, "mx": True, "provider": domain})

@app.post("/verify")
def verify_post(email: str = Form(...), api_key: Optional[str] = Form(None)):
    """
    POST /verify (form-data) - used by demo UI.
    Form fields: email, api_key
    """
    if CONFIG.get("require_api_key", True):
        key = api_key
        if not key:
            raise HTTPException(status_code=401, detail="API key required in form 'api_key'")
        cid, info = get_client_by_key(key)
        if cid is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        ok, msg = check_and_consume_quota(cid)
        if not ok:
            raise HTTPException(status_code=429, detail=msg)
    else:
        cid = "anonymous"

    email = (email or "").strip()
    if not EMAIL_RE.match(email):
        return JSONResponse({"email": email, "valid": False, "reason": "invalid_syntax"})

    domain = domain_from_email(email)

    # trusted provider quick-pass
    if domain in CONFIG.get("trusted_providers", []):
        mx = has_mx(domain)
        return JSONResponse({"email": email, "valid": True, "reason": "trusted_provider", "disposable": False, "mx": mx, "provider": domain})

    with BLOCKSET_LOCK:
        is_disposable = domain in BLOCKSET

    if is_disposable:
        return JSONResponse({"email": email, "valid": False, "reason": "disposable_domain", "disposable": True})

    mx = has_mx(domain)
    if not mx:
        return JSONResponse({"email": email, "valid": False, "reason": "no_mx", "disposable": False, "mx": False})

    return JSONResponse({"email": email, "valid": True, "reason": "valid", "disposable": False, "mx": True, "provider": domain})

# ---------- Startup event: ensure blockset loaded ----------
@app.on_event("startup")
def on_startup():
    # ensure blocklist exists locally (updater can create)
    if not os.path.exists(BLOCKLIST_TXT):
        try:
            # attempt a one-time fetch synchronously so first run has something
            refreshed = fetch_and_merge_remote()
            print(f"[startup] fetched {len(refreshed)} domains")
        except Exception as e:
            print("[startup] failed initial fetch:", e)
    else:
        # load the local file to memory
        try:
            global BLOCKSET
            BLOCKSET = load_local_blocklist()
            print(f"[startup] loaded {len(BLOCKSET)} local blocklist entries")
        except Exception:
            BLOCKSET = set()

# ---------- End of main.py ----------
