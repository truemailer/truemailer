# Truemailer - Final Full Version
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import re, json, os, aiohttp

app = FastAPI(title="Truemailer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BLOCKLIST_FILE = "blocklist.json"
API_KEYS = {"demo_key_123": {"limit": 100, "used": 0}}
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com",
    "protonmail.com", "zoho.com", "icloud.com"
]

if not os.path.exists(BLOCKLIST_FILE):
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump({"disposable_domains": []}, f)

async def load_blocklist():
    with open(BLOCKLIST_FILE) as f:
        return json.load(f)

@app.get("/", response_class=HTMLResponse)
async def home():
    return '''<html><body>
    <h2>✅ Truemailer — Email Verifier (Final)</h2>
    <form id="verifyForm">
      <input name="email" placeholder="Enter email"><br>
      <input name="api_key" placeholder="API key"><br>
      <button type="submit">Verify</button>
    </form>
    <pre id="result"></pre>
    <script>
    document.getElementById('verifyForm').onsubmit = async (e) => {
      e.preventDefault();
      const data = new FormData(e.target);
      const res = await fetch('/verify', {method:'POST', body:data});
      document.getElementById('result').textContent = await res.text();
    };
    </script>
    </body></html>'''

@app.post("/verify")
async def verify(email: str = Form(...), api_key: str = Form(...)):
    if api_key not in API_KEYS:
        return JSONResponse({"error": "Invalid API key"}, status_code=401)
    key_data = API_KEYS[api_key]
    if key_data["used"] >= key_data["limit"]:
        return JSONResponse({"error": "API limit reached"}, status_code=403)
    key_data["used"] += 1

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"email": email, "valid": False, "reason": "invalid_format"}

    domain = email.split("@")[-1].lower()
    blocklist = await load_blocklist()

    if domain in blocklist["disposable_domains"]:
        return {"email": email, "valid": False, "reason": "disposable"}
    if domain in TRUSTED_DOMAINS:
        return {"email": email, "valid": True, "reason": "trusted"}
    if any(domain.endswith(tld) for tld in [".com", ".in", ".net", ".org"]):
        return {"email": email, "valid": True, "reason": "generic_domain"}
    return {"email": email, "valid": False, "reason": "unknown_domain"}

@app.get("/status")
async def status():
    return {"message": "✅ Truemailer API running", "keys": len(API_KEYS)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
