from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import aiohttp
import asyncio
import os

app = FastAPI(title="Truemailer API")

# Mount static folder
app.mount("/static", StaticFiles(directory="static"), name="static")

# ----- SETTINGS -----
API_KEYS = {"client1-key": {"limit": 1000, "used": 0},
            "client2-key": {"limit": 500, "used": 0}}

TRUSTED_PROVIDERS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
    "zoho.com", "protonmail.com", "aol.com", "gmx.com", "tutanota.com"
]

BLOCKLIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blacklist.conf"

# Store blocklist in memory
BLOCKED_DOMAINS = set()


# ----- FETCH BLOCKLIST -----
async def update_blocklist():
    global BLOCKED_DOMAINS
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(BLOCKLIST_URL) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    BLOCKED_DOMAINS = set(line.strip().lower() for line in text.splitlines() if line.strip())
                    print(f"✅ Blocklist updated: {len(BLOCKED_DOMAINS)} domains blocked")
                else:
                    print("⚠️ Failed to fetch blocklist")
    except Exception as e:
        print("⚠️ Error updating blocklist:", e)


@app.on_event("startup")
async def startup_event():
    await update_blocklist()


# ----- ROUTES -----
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
        <head><title>Truemailer</title></head>
        <body style="font-family:sans-serif;text-align:center;">
            <h2>✅ Truemailer API is running</h2>
            <p>Use POST /verify with <b>email</b> and <b>api_key</b></p>
        </body>
    </html>
    """


@app.post("/verify")
async def verify_email(email: str = Form(...), api_key: str = Form(...)):
    # --- Check API key ---
    if api_key not in API_KEYS:
        return JSONResponse({"error": "Invalid API key"}, status_code=401)

    client = API_KEYS[api_key]
    if client["used"] >= client["limit"]:
        return JSONResponse({"error": "API limit exceeded"}, status_code=403)

    client["used"] += 1

    domain = email.split("@")[-1].lower()

    # --- Checks ---
    if domain in BLOCKED_DOMAINS:
        return {"email": email, "valid": False, "reason": "disposable domain"}

    if domain not in TRUSTED_PROVIDERS:
        return {"email": email, "valid": False, "reason": "untrusted provider"}

    # --- Passed ---
    return {"email": email, "valid": True, "reason": "trusted", "provider": domain}


@app.get("/status")
async def status():
    return {"message": "✅ Truemailer API live", "total_keys": len(API_KEYS), "blocked_domains": len(BLOCKED_DOMAINS)}
