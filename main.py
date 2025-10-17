# main.py - Truemailer final (drop-in replacement)
"""
Truemailer main API (final).

Run (dev):
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Expected repo files (create if missing):
 - blocklist/blocklist.txt        (one domain per line) OR blocklist.json
 - allowlist/allowlist.json      (array) OR allowlist.json (array)
 - keys.json                     (map: client_name -> {key:, expiry:, limit:})
 - client.json                   (usage tracking)
 - mx_cache.json                 (created automatically)
"""

import os, re, json, time, threading
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import dns.resolver

# ---------------- CONFIG ----------------
APP_NAME = "Truemailer"
BLOCKLIST_TXT = "blocklist/blocklist.txt"
BLOCKLIST_JSON = "blocklist.json"
ALLOWLIST_JSON1 = "allowlist/allowlist.json"
ALLOWLIST_JSON2 = "allowlist.json"
KEYS_FILE = "keys.json"
CLIENT_FILE = "client.json"
MX_CACHE_FILE = "mx_cache.json"
DEFAULT_DAILY_LIMIT = 1000
MX_TTL = 7 * 24 * 3600  # 7 days
# ----------------------------------------

app = FastAPI(title=APP_NAME)

# ---------- utilities ----------
def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True) if "/" in path else None
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except Exception:
        return []

# ---------- lists in memory ----------
LIST_LOCK = threading.Lock()
BLOCKSET = set()
ALLOWSET = set()

def load_blockset():
    s = set()
    for p in (BLOCKLIST_TXT, BLOCKLIST_JSON):
        if os.path.exists(p):
            if p.endswith(".txt"):
                for ln in read_lines(p):
                    s.add(ln.strip().lower())
            else:
                v = read_json(p)
                if isinstance(v, list):
                    for ln in v:
                        s.add(str(ln).strip().lower())
    return s

def load_allowset():
    s = set()
    for p in (ALLOWLIST_JSON1, ALLOWLIST_JSON2):
        if os.path.exists(p):
            v = read_json(p)
            if isinstance(v, list):
                for d in v:
                    s.add(str(d).strip().lower())
            elif isinstance(v, dict):
                arr = v.get("trusted") or v.get("allow") or v.get("trusted_domains") or v.get("domains")
                if isinstance(arr, list):
                    for d in arr:
                        s.add(str(d).strip().lower())
    # fallback small allowlist if none provided
    if not s:
        s.update(["gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","zoho.com","protonmail.com"])
    return s

def reload_lists():
    global BLOCKSET, ALLOWSET
    with LIST_LOCK:
        BLOCKSET = load_blockset()
        ALLOWSET = load_allowset()
    return {"block_count": len(BLOCKSET), "allow_count": len(ALLOWSET)}

# initial load
reload_lists()

# ---------- MX cache ----------
MX_CACHE = {}
MX_LOCK = threading.Lock()

def load_mx_cache():
    global MX_CACHE
    d = read_json(MX_CACHE_FILE)
    if isinstance(d, dict):
        MX_CACHE = d
    else:
        MX_CACHE = {}

def save_mx_cache():
    with MX_LOCK:
        try:
            write_json(MX_CACHE_FILE, MX_CACHE)
        except Exception:
            pass

load_mx_cache()

def check_mx(domain: str, timeout=3.0) -> bool:
    domain = domain.lower()
    now = int(time.time())
    with MX_LOCK:
        rec = MX_CACHE.get(domain)
        if rec and now - rec.get("ts", 0) < MX_TTL:
            return bool(rec.get("mx", False))
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        ok = len(answers) > 0
    except Exception:
        ok = False
    with MX_LOCK:
        MX_CACHE[domain] = {"mx": bool(ok), "ts": now}
    # occasionally persist
    if int(time.time()) % 10 == 0:
        save_mx_cache()
    return ok

# ---------- format & heuristics ----------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def is_valid_format(email: str) -> bool:
    return EMAIL_RE.match(email) is not None

def heuristic_suspicious(email: str):
    local, _, domain = email.partition("@")
    reasons = []
    if len(local) <= 1:
        reasons.append("short-local")
    if ".." in email:
        reasons.append("dots")
    digits = sum(ch.isdigit() for ch in local)
    if len(local) and digits / len(local) > 0.6:
        reasons.append("many-digits")
    return {"suspicious": bool(reasons), "reasons": reasons}

# ---------- keys & clients ----------
def read_keys():
    k = read_json(KEYS_FILE)
    return k if isinstance(k, dict) else {}

def read_clients():
    c = read_json(CLIENT_FILE)
    return c if isinstance(c, dict) else {}

def find_client_by_key(api_key: str):
    keys = read_keys()
    for name, info in keys.items():
        if isinstance(info, dict) and info.get("key") == api_key:
            return name, info
        if name == api_key:
            return info.get("client", name), info
    return None, None

def is_key_valid(api_key: str):
    cname, info = find_client_by_key(api_key)
    if not info:
        return False, "invalid", None
    expiry = info.get("expiry")
    if expiry and int(time.time()) > int(expiry):
        return False, "expired", cname
    return True, "ok", cname

def increment_usage(client_name: str):
    clients = read_clients()
    client = clients.get(client_name, {})
    now = int(time.time())
    today = datetime.utcnow().strftime("%Y-%m-%d")
    meta = client.get("_meta", {})
    if meta.get("day") != today:
        meta["day"] = today
        meta["count"] = 0
    meta["count"] = meta.get("count", 0) + 1
    client["_meta"] = meta
    client["last_used"] = now
    clients[client_name] = client
    write_json(CLIENT_FILE, clients)
    return meta["count"]

def get_daily_usage(client_name: str):
    clients = read_clients()
    client = clients.get(client_name, {})
    meta = client.get("_meta", {})
    return meta.get("count", 0)

# ---------- core verify logic ----------
def verify_email_address(email: str):
    email = email.strip()
    if not is_valid_format(email):
        return {"valid": False, "disposable": False, "reason": "invalid_format", "mx": False, "suspicious": False, "suspicious_reasons": []}
    local, _, domain = email.rpartition("@")
    domain = domain.lower().strip()

    # allowlist first
    if domain in ALLOWSET or any(domain.endswith("." + a) for a in ALLOWSET):
        mx_ok = check_mx(domain)
        return {"valid": True, "disposable": False, "reason": "allowlist", "mx": mx_ok, "suspicious": False, "suspicious_reasons": []}

    # blocklist quick match
    if domain in BLOCKSET:
        return {"valid": False, "disposable": True, "reason": "blocklist", "mx": False, "suspicious": False, "suspicious_reasons": []}

    # heuristics
    heur = heuristic_suspicious(email)
    suspicious = heur["suspicious"]
    reasons = heur["reasons"]

    # MX check (if no MX -> treat as disposable/invalid)
    mx_ok = check_mx(domain)
    if not mx_ok:
        return {"valid": False, "disposable": True, "reason": "no_mx", "mx": False, "suspicious": suspicious, "suspicious_reasons": reasons}

    # default allow
    return {"valid": True, "disposable": False, "reason": "valid", "mx": True, "suspicious": suspicious, "suspicious_reasons": reasons}

# ---------- API models ----------
class VerifyRequest(BaseModel):
    email: EmailStr
    api_key: str

class CreateKeyRequest(BaseModel):
    client_name: str
    days: int = 365
    plan: str = "pro"
    limit: int = DEFAULT_DAILY_LIMIT

# ---------- endpoints ----------
@app.get("/status/")
def status():
    return {"service": APP_NAME, "time": int(time.time()), "block_count": len(BLOCKSET), "allow_count": len(ALLOWSET)}

@app.post("/verify")
def verify_post(payload: VerifyRequest):
    vk, msg, cname = is_key_valid(payload.api_key)
    if not vk:
        raise HTTPException(status_code=403, detail=f"api_key {msg}")
    # rate limit
    keys_map = read_keys()
    client_info = None
    for n,i in keys_map.items():
        if isinstance(i, dict) and i.get("key") == payload.api_key:
            client_info = i; cname = n; break
        if n == payload.api_key:
            client_info = i; cname = i.get("client", cname); break
    limit = client_info.get("limit", DEFAULT_DAILY_LIMIT) if client_info else DEFAULT_DAILY_LIMIT
    usage = get_daily_usage(cname)
    if usage >= limit:
        raise HTTPException(status_code=429, detail="Daily limit reached")
    res = verify_email_address(payload.email)
    increment_usage(cname)
    return {"email": payload.email, **res}

@app.get("/verify")
def verify_get(email: str = "", api_key: str = ""):
    if not email:
        raise HTTPException(status_code=400, detail="Please provide ?email=someone@domain.tld")
    if not api_key:
        raise HTTPException(status_code=401, detail="api_key required (use demo key)")
    vk, msg, cname = is_key_valid(api_key)
    if not vk:
        raise HTTPException(status_code=403, detail=f"api_key {msg}")
    # rate limit check
    keys_map = read_keys()
    client_info = None
    for n,i in keys_map.items():
        if isinstance(i, dict) and i.get("key") == api_key:
            client_info = i; cname = n; break
        if n == api_key:
            client_info = i; cname = i.get("client", cname); break
    limit = client_info.get("limit", DEFAULT_DAILY_LIMIT) if client_info else DEFAULT_DAILY_LIMIT
    usage = get_daily_usage(cname)
    if usage >= limit:
        raise HTTPException(status_code=429, detail="Daily limit reached")
    res = verify_email_address(email)
    increment_usage(cname)
    return {"email": email, **res}

@app.post("/create-key")
def create_key(payload: CreateKeyRequest):
    import uuid
    keys = read_json(KEYS_FILE) or {}
    key = str(uuid.uuid4())
    keys[payload.client_name] = {"key": key, "expiry": int(time.time()) + payload.days * 86400, "plan": payload.plan, "limit": payload.limit}
    write_json(KEYS_FILE, keys)
    return {"created": True, "key": key}

@app.post("/update-lists")
def update_lists():
    info = reload_lists()
    return {"updated": True, **info}

# ---------- startup hooks ----------
@app.on_event("startup")
def on_startup():
    if not os.path.exists(KEYS_FILE): write_json(KEYS_FILE, {})
    if not os.path.exists(CLIENT_FILE): write_json(CLIENT_FILE, {})
    reload_lists()
    def persist_mx():
        while True:
            time.sleep(60)
            try:
                save_mx_cache()
            except:
                pass
    t = threading.Thread(target=persist_mx, daemon=True)
    t.start()

@app.on_event("shutdown")
def on_shutdown():
    try:
        save_mx_cache()
    except: pass

# ---------- quick CLI test ----------
if __name__ == "__main__":
    print("Truemailer local test")
    reload_lists()
    while True:
        try:
            s = input("email> ").strip()
            if s in ("quit","exit"): break
            print(json.dumps(verify_email_address(s), indent=2))
        except KeyboardInterrupt:
            break
