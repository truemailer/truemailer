# main.py - Truemailer (Full production-ready verifier)
# - API keys (clients.json)
# - Per-key daily limits (persisted)
# - Trusted-provider allowlist
# - Disposable blocklist (local + remote merge)
# - MX checks (dnspython)
# - GET & POST /verify, /update-now (manual), /status
# - Background updater every 24h

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

# ---------- File paths ----------
CONFIG_FILE = "config.json"
CLIENTS_FILE = "clients.json"
BLOCKLIST_TXT = os.path.join("blocklist", "blocklist.txt")

# ---------- Default configuration ----------
DEFAULT_CONFIG = {
    "require_api_key": True,
    "rate_limit_per_day": 100,
    "trusted_providers": [
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "icloud.com", "protonmail.com", "zoho.com", "mail.com", "yandex.com",
        "aol.com", "gmx.com", "fastmail.com", "tutanota.com"
    ],
    "remote_blocklist_urls": [
        "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains/refs/heads/master/domains.txt",
        "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains1/refs/heads/main/disposable_email_blocklist.conf",
        "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt"
    ],
    "update_interval_seconds": 24 * 3600,
    "mx_check_enabled": True
}

# ---------- Helpers to read/write JSON ----------
def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # write default on missing
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

# ---------- Load config & clients ----------
CONFIG = load_json(CONFIG_FILE, DEFAULT_CONFIG)
CLIENTS = load_json(CLIENTS_FILE, {
    "demo": {"key": "demo_key_123", "name": "Demo Client", "limit": CONFIG.get("rate_limit_per_day", 100), "usage": {}}
})

def save_clients():
    save_json(CLIENTS_FILE, CLIENTS)

# ---------- Blocklist (in memory) ----------
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
            continue
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

# initial load (best-effort)
try:
    BLOCKSET = load_local_blocklist()
    # do an async remote fetch in background so startup isn't blocked
    threading.Thread(target=refresh_blockset, daemon=True).start()
except Exception:
    BLOCKSET = set()

# background updater
def updater_loop():
    interval = CONFIG.get("update_interval_seconds", 24 * 3600)
    while True:
        try:
            count = refresh_blockset()
            print(f"[updater] blocklist refreshed: {count} domains")
        except Exception as e:
            print("[updater] error:", e)
        time.sleep(interval)

threading.Thread(target=updater_loop, daemon=True).start()

# ---------- FastAPI app ----------
from fastapi import FastAPI
app = FastAPI(title="Truemailer")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

# email regex (fast & permissive)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")

# helper client functions
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
    return JSONResponse({"message": "Truemailer running. Use /verify"}, status_code=200)

@app.get("/status")
def status():
    return {"ok": True, "loaded": len(BLOCKSET), "clients": list(CLIENTS.keys())}

@app.post("/update-now")
def update_now(trigger_key: Optional[str] = Form(None)):
    """
    Manual trigger to refresh the blocklist now.
    Optional trigger_key must be a valid client key (if provided).
    """
    if trigger_key:
        cid, info = get_client_by_key(trigger_key)
        if cid is None:
            raise HTTPException(status_code=401, detail="Invalid trigger key")
    n = refresh_blockset()
    return {"updated": True, "domains": n}

@app.get("/verify")
def verify_get(email: str = Query(..., description="Email to verify"), api_key: Optional[str] = Query(None)):
    # Auth & quota
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

    email = (email or "").strip()
    if not EMAIL_RE.match(email):
        return JSONResponse({"email": email, "valid": False, "reason": "invalid_syntax"})

    domain = domain_from_email(email)

    # trusted provider allowlist
    if domain in CONFIG.get("trusted_providers", []):
        mx = has_mx(domain)
        return JSONResponse({"email": email, "valid": True, "reason": "trusted_provider", "disposable": False, "mx": mx, "provider": domain})

    # disposable check
    with BLOCKSET_LOCK:
        is_disposable = domain in BLOCKSET

    if is_disposable:
        return JSONResponse({"email": email, "valid": False, "reason": "disposable_domain", "disposable": True})

    # MX check fallback
    mx = has_mx(domain)
    if not mx:
        return JSONResponse({"email": email, "valid": False, "reason": "no_mx", "disposable": False, "mx": False})

    return JSONResponse({"email": email, "valid": True, "reason": "valid", "disposable": False, "mx": True, "provider": domain})

@app.post("/verify")
def verify_post(email: str = Form(...), api_key: Optional[str] = Form(None)):
    # Auth & quota
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

# ---------- Startup: ensure blocklist available ----------
@app.on_event("startup")
def on_startup():
    # load local blocklist if present; otherwise try one-time fetch
    if os.path.exists(BLOCKLIST_TXT):
        try:
            global BLOCKSET
            BLOCKSET = load_local_blocklist()
            print(f"[startup] loaded {len(BLOCKSET)} local blocklist entries")
        except Exception:
            pass
    else:
        try:
            refreshed = fetch_and_merge_remote()
            print(f"[startup] fetched {len(refreshed)} domains")
        except Exception as e:
            print("[startup] initial fetch failed:", e)
