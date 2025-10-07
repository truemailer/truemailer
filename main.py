from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
import dns.resolver, smtplib, socket, os, json

app = FastAPI(title="Truemailer API", description="Verify emails easily", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def home():
    return FileResponse("static/index.html")

# -------------------------------
# Email Verification Logic
# -------------------------------
class EmailRequest(BaseModel):
    email: EmailStr
    api_key: str | None = None

@app.post("/verify")
def verify_email(request: EmailRequest):
    email = request.email
    domain = email.split("@")[-1]

    # Allow only known providers
    trusted = ["gmail.com", "outlook.com", "yahoo.com", "protonmail.com"]
    if domain not in trusted:
        return {"valid": False, "reason": "Untrusted or temporary domain"}

    try:
        dns.resolver.resolve(domain, "MX")
    except Exception:
        return {"valid": False, "reason": "Domain has no MX records"}

    try:
        server = smtplib.SMTP(timeout=5)
        server.connect("gmail-smtp-in.l.google.com")
        server.quit()
    except (socket.error, smtplib.SMTPException):
        return {"valid": False, "reason": "SMTP connection failed"}

    return {"valid": True, "reason": "Valid email address"}
