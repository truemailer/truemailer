from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import re
import dns.resolver
from email_validator import validate_email, EmailNotValidError

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

# Simple blocklist for testing — we’ll replace later with full 70k+
blocked_domains = {"tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com"}

def is_valid_email(email: str) -> dict:
    """Validates email format, domain, MX record, and blocklist"""
    try:
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError:
        return {"valid": False, "reason": "Invalid email format"}

    domain = email.split('@')[-1]
    if domain in blocked_domains:
        return {"valid": False, "reason": "Disposable or temp email"}

    try:
        dns.resolver.resolve(domain, 'MX')
    except Exception:
        return {"valid": False, "reason": "No MX record found"}

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
