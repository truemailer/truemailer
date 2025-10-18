from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os, re, json, aiohttp

app = FastAPI(title="Truemailer API Edge", version="3.0")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load files
def load_list(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r", encoding="utf-8") as f:
        lines = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    return set(lines)

blocklist = load_list("blocklist-data/blocklist.txt")
suspicious_tlds = load_list("blocklist-data/suspicious_tlds.txt")
disposable_providers = load_list("blocklist-data/disposable_providers.txt")

# Allowlist
allowlist = set()
if os.path.exists("allowlist.json"):
    with open("allowlist.json", "r", encoding="utf-8") as f:
        allowlist = set(json.load(f))

# Config file with allowed API keys
if os.path.exists("config.json"):
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
        API_KEYS = set(config.get("api_keys", []))
else:
    API_KEYS = {"public-demo-key"}

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

@app.get("/")
async def root():
    return {"service": "Truemailer API Edge", "status": "Running ✅", "source": "Render + Cloudflare"}

@app.get("/verify")
async def verify_email(request: Request):
    api_key = request.headers.get("x-api-key")
    if not api_key or api_key not in API_KEYS:
        return JSONResponse({"error": "Invalid or missing API key"}, status_code=403)

    email = request.query_params.get("email")
    if not email:
        return JSONResponse({"error": "email required"}, status_code=400)

    email = email.strip().lower()
    if not EMAIL_REGEX.match(email):
        return JSONResponse({"email": email, "valid_format": False, "is_disposable": True})

    domain = email.split("@")[-1]

    # Allowlist check
    if domain in allowlist:
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": False,
            "reason": "Domain in allowlist ✅"
        })

    # Blocklist check
    if domain in blocklist:
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": True,
            "reason": "Domain found in blocklist 🚫"
        })

    # Suspicious or disposable pattern
    tld = domain.split(".")[-1]
    if tld in suspicious_tlds or any(x in domain for x in disposable_providers):
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": True,
            "reason": "Disposable/suspicious domain ⚠️"
        })

    # Rotating pattern (random daily domains)
    if re.search(r"[a-z0-9]{8,}\.(xyz|fun|info|live|site|icu)$", domain):
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": True,
            "reason": "Likely daily generated domain ⚙️"
        })

    # DNS check
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://dns.google/resolve?name={domain}&type=MX") as r:
                data = await r.json()
                if "Answer" not in data:
                    return JSONResponse({
                        "email": email,
                        "domain": domain,
                        "valid_format": True,
                        "is_disposable": True,
                        "reason": "No MX record found ❌"
                    })
    except Exception:
        pass

    return JSONResponse({
        "email": email,
        "domain": domain,
        "valid_format": True,
        "is_disposable": False,
        "reason": "Clean domain ✅"
    })


@app.get("/status")
async def status():
    return {
        "status": "Operational ✅",
        "version": "3.0",
        "allowlist_count": len(allowlist),
        "blocklist_count": len(blocklist),
        "active_keys": len(API_KEYS)
    }
