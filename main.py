from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os, re, json, aiohttp

app = FastAPI(title="Truemailer API Edge", version="2.0")

# Allow CORS for all (for frontend and API usage)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load blocklist and allowlist
def load_list(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r", encoding="utf-8") as f:
        lines = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    return set(lines)

blocklist = load_list("blocklist-data/blocklist.txt")
suspicious_tlds = load_list("blocklist-data/suspicious_tlds.txt")
disposable_providers = load_list("blocklist-data/disposable_providers.txt")

# Load allowlist
if os.path.exists("allowlist.json"):
    with open("allowlist.json", "r", encoding="utf-8") as f:
        allowlist = set(json.load(f))
else:
    allowlist = set()

# Regex for validation
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

@app.get("/")
async def root():
    return {"service": "Truemailer API Edge", "status": "Running ✅", "source": "Render + Cloudflare Worker"}

@app.get("/verify")
async def verify_email(request: Request):
    email = request.query_params.get("email")
    if not email:
        return JSONResponse({"error": "email required"}, status_code=400)

    email = email.strip().lower()
    if not EMAIL_REGEX.match(email):
        return JSONResponse({"email": email, "valid_format": False, "is_disposable": True})

    domain = email.split("@")[-1]

    # Allowlist override
    if domain in allowlist:
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": False,
            "reason": "Domain in allowlist"
        })

    # Check blocklist
    if domain in blocklist:
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": True,
            "reason": "Domain found in blocklist"
        })

    # Check disposable and suspicious TLDs
    tld = domain.split(".")[-1]
    if tld in suspicious_tlds or any(x in domain for x in disposable_providers):
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": True,
            "reason": "Domain uses disposable/suspicious provider"
        })

    # Check known daily-rotating patterns
    if re.search(r"[a-z0-9]{8,}\.(com|xyz|fun|info|live)$", domain):
        return JSONResponse({
            "email": email,
            "domain": domain,
            "valid_format": True,
            "is_disposable": True,
            "reason": "Domain pattern matches daily generator"
        })

    # Optional DNS Check (async)
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
                        "reason": "No MX record found"
                    })
    except Exception:
        pass

    # Passed all filters
    return JSONResponse({
        "email": email,
        "domain": domain,
        "valid_format": True,
        "is_disposable": False,
        "reason": "Clean domain ✅"
    })


@app.get("/status")
async def service_status():
    return {
        "status": "Operational ✅",
        "version": "2.0",
        "blocklist_entries": len(blocklist),
        "allowlist_entries": len(allowlist),
        "source": "https://github.com/truemailer/truemailer"
    }
