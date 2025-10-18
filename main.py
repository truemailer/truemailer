"""
Truemailer - main.py
Final production-ready backend for Render.

Features:
- FastAPI app with CORS enabled for GitHub Pages / Cloudflare UI
- Load local allowlist/blocklist files
- Optionally fetch remote blocklist sources (auto-updater can update local files)
- API key system (clients.json) with per-day usage counting and limits
- /verify endpoint (POST) that returns structured JSON:
    { email, domain, valid, disposable, reason, mx }
- /status endpoint for simple health + blocklist counts
- /admin endpoints (basic) to list clients & usage (for you)
- Defensive coding and clear JSON responses
"""

import os
import re
import json
import time
import socket
import asyncio
import httpx
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# -------------------------
# Configurable constants
# -------------------------
BLOCKLIST_LOCAL = "blocklist.txt"      # local plain list, one domain per line
ALLOWLIST_LOCAL = "allowlist.txt"      # local allowed domains
CLIENTS_FILE = "clients.json"          # client keys + limits + usage
REMOTE_SOURCES = [                      # optional remote sources (kept but not auto-fetched here)
    # Add raw github raw links if you want
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt"
]
# Patterns that strongly indicate disposable providers
TEMP_PATTERNS = [
    "tempmail", "mailinator", "guerrillamail", "10minutemail", "dispostable",
    "trashmail", "sharklasers", "fakeinbox", "getnada", "yopmail",
    "spambox", "maildrop", "disposable", "temporary", "temp-mail",
]

DEFAULT_PORT = int(os.getenv("PORT", 8000))

# -------------------------
# Utilities
# -------------------------
def safe_load_lines(path: str):
    """Load domain lines from a text file into a set of lowercased domains"""
    s = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln: continue
                if ln.startswith("#"): continue
                # lines could be domains or emails; normalize
                if "@" in ln and ln.count("@") == 1:
                    ln = ln.split("@", 1)[1]
                s.add(ln.lower())
    except FileNotFoundError:
        # silent fallback: file may be created later by updater
        pass
    except Exception as e:
        print("Error loading", path, e)
    return s

def safe_load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def safe_write_json(path: str, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def domain_from_email(email: str) -> str:
    return email.split("@", 1)[-1].lower().strip()

def looks_like_email(email: str) -> bool:
    # Pydantic/EmailStr validation could be used, but keep simple
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

# Simple MX check using socket lookup of domain — not full MX but lightweight
def has_a_record(domain: str, timeout: float = 3.0) -> bool:
    try:
        # socket.getaddrinfo may block — keep small timeout via socket timeout
        # Python's socket.gethostbyname_ex uses global resolver; usually OK
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

# Async fallback check using an external tiny disposable check service (non-blocking)
async def remote_disposable_check(domain: str) -> Optional[bool]:
    # NOTE: external service used sparingly; this is a best-effort check.
    # We keep the service optional; if it fails we return None (unknown)
    url = f"https://open.kickbox.com/v1/disposable/{domain}"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(url)
            if r.status_code == 200:
                j = r.json()
                # Kickbox returns {"disposable": true/false}
                return bool(j.get("disposable"))
    except Exception:
        return None
    return None

# -------------------------
# App & middleware
# -------------------------
app = FastAPI(title="Truemailer API - Final")

# Allow CORS for all for now (you can restrict to your GitHub Pages domain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Load lists and keys at startup
# -------------------------
BLOCKSET = safe_load_lines(BLOCKLIST_LOCAL)
ALLOWSET = safe_load_lines(ALLOWLIST_LOCAL)
CLIENTS = safe_load_json(CLIENTS_FILE, {
    "demo": {
        "key": "demo_key_123",
        "name": "Demo Client",
        "limit_per_day": 250,   # demo usage
        "usage": {}             # date -> count
    }
})

print(f"Startup: loaded {len(BLOCKSET)} blocked domains, {len(ALLOWSET)} allowlisted domains, {len(CLIENTS)} clients")

# -------------------------
# Request/response models
# -------------------------
class VerifyRequest(BaseModel):
    email: EmailStr
    api_key: Optional[str] = None

class VerifyResponse(BaseModel):
    email: str
    domain: str
    valid: bool
    disposable: bool
    reason: str
    mx: Optional[bool] = None
    provider: Optional[str] = None

# -------------------------
# Helper: API key & usage
# -------------------------
def get_client_by_key(key: str):
    if not key:
        return None, None
    for cid, data in CLIENTS.items():
        if data.get("key") == key:
            return cid, data
    return None, None

def increment_usage(client_id: str):
    today = time.strftime("%Y-%m-%d")
    data = CLIENTS.get(client_id)
    if data is None:
        return False
    usage = data.setdefault("usage", {})
    usage[today] = usage.get(today, 0) + 1
    # persist to disk
    safe_write_json(CLIENTS_FILE, CLIENTS)
    return True

def usage_for_today(client_id: str) -> int:
    today = time.strftime("%Y-%m-%d")
    return CLIENTS.get(client_id, {}).get("usage", {}).get(today, 0)

# -------------------------
# Verification logic
# -------------------------
async def evaluate_email(email: str) -> Dict[str, Any]:
    email_l = email.strip().lower()
    result = {
        "email": email_l,
        "domain": None,
        "valid": False,
        "disposable": False,
        "reason": "",
        "mx": None,
        "provider": None
    }

    if not looks_like_email(email_l):
        result["reason"] = "Invalid email format"
        return result

    domain = domain_from_email(email_l)
    result["domain"] = domain

    # Allowlist has highest priority
    if domain in ALLOWSET:
        result["valid"] = True
        result["disposable"] = False
        result["reason"] = "Allowlisted domain (trusted provider)"
        result["mx"] = True
        return result

    # Quick pattern match for known disposable words in domain
    for p in TEMP_PATTERNS:
        if p in domain:
            result["valid"] = False
            result["disposable"] = True
            result["reason"] = f"Disposable pattern matched: {p}"
            result["mx"] = False
            return result

    # Local blocklist
    if domain in BLOCKSET:
        result["valid"] = False
        result["disposable"] = True
        result["reason"] = "Domain found in local blocklist"
        result["mx"] = False
        return result

    # Check MX / A - lightweight: see if domain resolves
    has_dns = False
    try:
        has_dns = has_a_record(domain)
    except Exception:
        has_dns = False
    result["mx"] = bool(has_dns)
    if not has_dns:
        result["valid"] = False
        result["disposable"] = True
        result["reason"] = "Domain does not resolve (no DNS/A record)"
        return result

    # Remote disposable check (best-effort; may be slow)
    try:
        remote = await remote_disposable_check(domain)
        if remote is True:
            result["valid"] = False
            result["disposable"] = True
            result["reason"] = "Marked disposable by remote list (kickbox)"
            return result
        if remote is False:
            # remote says not disposable; continue
            pass
    except Exception:
        pass

    # All checks passed — treat as valid
    result["valid"] = True
    result["disposable"] = False
    result["reason"] = "Looks like a genuine domain"
    return result

# -------------------------
# Routes
# -------------------------
@app.get("/status")
async def status():
    return {
        "ok": True,
        "time": int(time.time()),
        "block_count": len(BLOCKSET),
        "allow_count": len(ALLOWSET),
        "clients": len(CLIENTS)
    }

@app.post("/verify")
async def verify_endpoint(req: Request, x_api_key: Optional[str] = Header(None)):
    """
    Accepts JSON body: { "email": "someone@domain.tld" }
    Optional header 'x-api-key' or client may include "api_key" in body.
    """
    payload = await req.json()
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="email is required")

    # API key: prefer header then body
    key = x_api_key or payload.get("api_key") or payload.get("key")
    client_id, client_data = get_client_by_key(key) if key else (None, None)

    # If client provided a key, enforce usage limit
    if client_id:
        limit = client_data.get("limit_per_day", 250)
        used = usage_for_today(client_id)
        if used >= limit:
            raise HTTPException(status_code=429, detail="daily limit exceeded")
        # increment after verification (so failed calls don't count? here we increment after success)
    # If no key, allow but limited (demo behaviour)
    else:
        # treat as demo user — but rate-limit by IP can be added later
        pass

    # Run evaluation
    try:
        res = await evaluate_email(email)
    except Exception as e:
        # unexpected error — return structured message
        return {"email": email, "valid": False, "disposable": True, "reason": f"internal error: {str(e)}"}

    # if client exists, increment usage count now
    if client_id:
        increment_usage(client_id)

    # Structure response object
    out = {
        "email": res["email"],
        "domain": res["domain"],
        "valid": res["valid"],
        "is_disposable": res["disposable"],
        "reason": res["reason"],
        "mx": res["mx"]
    }
    return out

# Simple admin-ish endpoint to list clients (not secured — remove or add auth in prod)
@app.get("/admin/clients")
async def list_clients():
    # careful: don't return secret keys publicly if you keep this deployed live
    return CLIENTS

# -------------------------
# Helper: Allow updating blocklist/allowlist via POST (simple)
# -------------------------
@app.post("/admin/update-lists")
async def update_lists(payload: Dict[str, Any]):
    """
    Accepts JSON: { "allow": ["domain1","domain2"], "block": ["bad1","bad2"] }
    This writes local allowlist/blocklist files (overwrites) — intended for you (owner)
    """
    allow = payload.get("allow", [])
    block = payload.get("block", [])
    # write files
    try:
        with open(ALLOWLIST_LOCAL, "w", encoding="utf-8") as f:
            for d in sorted(set(allow)):
                f.write(d.strip().lower() + "\n")
        with open(BLOCKLIST_LOCAL, "w", encoding="utf-8") as f:
            for d in sorted(set(block)):
                f.write(d.strip().lower() + "\n")
        # reload sets
        global ALLOWSET, BLOCKSET
        ALLOWSET = safe_load_lines(ALLOWLIST_LOCAL)
        BLOCKSET = safe_load_lines(BLOCKLIST_LOCAL)
        return {"updated": True, "allow_count": len(ALLOWSET), "block_count": len(BLOCKSET)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------
# Run dev server (not used on Render)
# -------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=DEFAULT_PORT, reload=False)
