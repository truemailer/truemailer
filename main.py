from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import dns.resolver

app = FastAPI(title="Truemailer - Email Verifier")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_index():
    return FileResponse("static/index.html")

@app.get("/verify")
def verify_email(email: str = Query(..., description="Email address to verify")):
    if "@" not in email:
        return {"valid": False, "reason": "Invalid email format"}

    domain = email.split("@")[-1]
    try:
        dns.resolver.resolve(domain, "MX")
        return {"valid": True, "reason": "Valid email domain"}
    except Exception:
        return {"valid": False, "reason": "Domain has no MX records"}

    return {"valid": True, "reason": "Valid email"}

@app.get("/")
async def index():
    with open("static/index.html") as f:
        return HTMLResponse(content=f.read())

@app.get("/verify")
async def verify_get(email: str = Query(...)):
    return is_valid_email(email)

@app.post("/verify")
async def verify_post(email: str = Form(...)):
    return is_valid_email(email)
