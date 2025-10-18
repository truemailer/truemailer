from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import requests

app = FastAPI(title="TrueMailer API")

# ✅ Allow CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Load lists
def load_list(filename):
    try:
        with open(filename, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

blocklist = load_list("blocklist.txt")
allowlist = load_list("allowlist.txt")

# ✅ Health check
@app.get("/")
async def home():
    return {
        "message": "Truemailer API is running successfully",
        "project": "TrueMailer",
        "status": "Active ✅",
        "pricing": {
            "Free": "50 verifications/day",
            "Starter": "₹199/month - 2,000 verifications",
            "Pro": "₹499/month - 10,000 verifications + priority API",
        },
    }

# ✅ Email validation endpoint
@app.post("/verify")
async def verify_email(request: Request):
    data = await request.json()
    email = data.get("email")

    if not email:
        return JSONResponse({"error": "email required"}, status_code=400)

    domain = email.split("@")[-1].lower()

    # ✅ Allowlist first
    if domain in allowlist:
        return {"email": email, "valid": True, "reason": "Domain in allowlist"}

    # ✅ Blocklist next
    if domain in blocklist:
        return {"email": email, "valid": False, "reason": "Disposable domain blocked"}

    # ✅ External check fallback (for accuracy)
    try:
        resp = requests.get(f"https://truemailer-api.onrender.com/check/{domain}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("disposable") is True:
                return {"email": email, "valid": False, "reason": "Detected via external source"}
    except Exception:
        pass

    return {"email": email, "valid": True, "reason": "Looks good"}

# ✅ Optional GET check
@app.get("/check/{domain}")
async def check_domain(domain: str):
    domain = domain.lower()
    disposable = domain in blocklist
    return {"domain": domain, "disposable": disposable}
