from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import aiohttp
import asyncio
import os
import re
import dns.resolver

app = FastAPI(title="Truemailer API", version="2.0")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# File paths
BASE_DIR = Path(__file__).resolve().parent
BLOCKLIST_FILE = BASE_DIR / "blocklist" / "blocklist.txt"
os.makedirs(BLOCKLIST_FILE.parent, exist_ok=True)

# Blocklist sources
REMOTE_URLS = [
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
    "https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt",
]

# Trusted email providers (always valid)
TRUSTED_PROVIDERS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "icloud.com", "protonmail.com", "zoho.com", "yandex.com", "aol.com"
]

blocklist = set()

# ----------------------- UTILITIES -----------------------
async def fetch_blocklists():
    global blocklist
    merged = set()
    async with aiohttp.ClientSession() as session:
        for url in REMOTE_URLS:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        domains = re.findall(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
                        merged.update([d.strip().lower() for d in domains])
                        print(f"✅ Loaded {len(domains)} domains from {url}")
            except Exception as e:
                print(f"⚠️ Failed to fetch from {url}: {e}")

    blocklist = merged
    with open(BLOCKLIST_FILE, "w") as f:
        f.write("\n".join(sorted(merged)))
    print(f"💾 Saved total {len(merged)} domains to {BLOCKLIST_FILE}")


def load_local_blocklist():
    global blocklist
    if BLOCKLIST_FILE.exists():
        with open(BLOCKLIST_FILE, "r") as f:
            blocklist = set(line.strip().lower() for line in f if line.strip())
            print(f"📦 Loaded {len(blocklist)} domains from local blocklist")


def domain_has_mx(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False


# ----------------------- VERIFICATION -----------------------
@app.on_event("startup")
async def startup_event():
    if not BLOCKLIST_FILE.exists() or os.path.getsize(BLOCKLIST_FILE) < 10000:
        await fetch_blocklists()
    else:
        load_local_blocklist()


def check_disposable(domain: str) -> bool:
    domain = domain.lower()
    if domain in blocklist:
        return True

    # Pattern-based detection
    suspect_patterns = ["mail", "inbox", "temp", "trash", "airmail", "guerrillamail", "dispostable", "gta5", "forex"]
    if any(p in domain for p in suspect_patterns):
        return True

    return False


@app.get("/")
async def home():
    return {"message": "✅ Server is running properly on Render & Replit"}


@app.get("/verify")
async def verify_get(email: str):
    if "@" not in email:
        return JSONResponse({"email": email, "valid": False, "reason": "invalid_format"})

    domain = email.split("@")[-1].lower()

    if domain in TRUSTED_PROVIDERS:
        return JSONResponse({"email": email, "valid": True, "reason": "trusted_provider"})

    disposable = check_disposable(domain)
    mx = domain_has_mx(domain)

    if disposable:
        return JSONResponse({"email": email, "valid": False, "reason": "disposable_domain", "mx": mx})
    elif not mx:
        return JSONResponse({"email": email, "valid": False, "reason": "no_mx_record"})
    else:
        return JSONResponse({"email": email, "valid": True, "reason": "valid", "mx": True})


@app.post("/verify")
async def verify_post(email: str = Form(...)):
    return await verify_get(email=email)


@app.get("/status")
async def status():
    return {
        "status": "running",
        "loaded_domains": len(blocklist),
        "source_count": len(REMOTE_URLS),
        "trusted_providers": len(TRUSTED_PROVIDERS)
                            }
