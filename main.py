from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import re
import json
import httpx

app = FastAPI()

# --- ✅ CORS so frontend UI (GitHub Pages) can call Render API ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can later restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load local blocklists / allowlists ---
try:
    with open("allowlist.json", "r") as f:
        allowlist = json.load(f)
except:
    allowlist = {"domains": ["zoho.in", "proton.me", "gmail.com", "outlook.com"]}

# Simple known disposable patterns
TEMP_PATTERNS = [
    "tempmail", "guerrillamail", "10minutemail", "mailinator",
    "fakeinbox", "trashmail", "getnada", "yopmail", "sharklasers",
    "maildrop", "dispostable", "instantemailaddress", "spamgourmet",
]

@app.get("/")
async def home():
    return {"message": "Truemailer API is running successfully", "project": "Truemailer", "status": "Active"}

@app.post("/")
async def check_email(request: Request):
    try:
        data = await request.json()
        email = data.get("email", "").strip().lower()
        if not email or "@" not in email:
            return {"valid": False, "is_disposable": True, "reason": "Invalid email format", "email": email}

        domain = email.split("@")[-1]

        # --- ✅ Allowlist override ---
        if domain in allowlist.get("domains", []):
            return {"valid": True, "is_disposable": False, "reason": "Allowlisted domain", "email": email}

        # --- Check for obvious disposable patterns ---
        for p in TEMP_PATTERNS:
            if p in domain:
                return {"valid": False, "is_disposable": True, "reason": f"Disposable domain pattern: {p}", "email": email}

        # --- External disposable API fallback ---
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                res = await client.get(f"https://open.kickbox.com/v1/disposable/{domain}")
                if res.status_code == 200:
                    data = res.json()
                    if data.get("disposable"):
                        return {"valid": False, "is_disposable": True, "reason": "Disposable (Kickbox list)", "email": email}
            except Exception:
                pass

        # --- MX check ---
        if not re.search(r"\.[a-z]{2,}$", domain):
            return {"valid": False, "is_disposable": True, "reason": "Invalid domain structure", "email": email}

        # --- Default: considered valid ---
        return {"valid": True, "is_disposable": False, "reason": "Valid", "email": email}

    except Exception as e:
        return {"valid": False, "is_disposable": True, "reason": f"Error: {str(e)}", "email": None}
