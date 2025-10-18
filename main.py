import json
import re
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Load configuration
with open("config.json", "r") as f:
    CONFIG = json.load(f)

# Load blocklist and allowlist
try:
    with open("blocklist.json", "r") as f:
        BLOCKLIST = set(json.load(f))
except:
    BLOCKLIST = set()

try:
    with open("allowlist.json", "r") as f:
        ALLOWLIST = set(json.load(f))
except:
    ALLOWLIST = set()

# Basic email pattern
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.route("/")
def index():
    return jsonify({"status": "OK", "message": "Truemailer API live"})

@app.route("/verify", methods=["POST"])
def verify_email():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "email required"}), 400

    email = data["email"].lower().strip()
    if not EMAIL_PATTERN.match(email):
        return jsonify({"valid": False, "reason": "Invalid email format"})

    domain = email.split("@")[1]

    # Allowlist check
    if domain in ALLOWLIST:
        return jsonify({
            "email": email,
            "domain": domain,
            "valid": True,
            "reason": "Domain in allowlist"
        })

    # Blocklist check
    if domain in BLOCKLIST:
        return jsonify({
            "email": email,
            "domain": domain,
            "valid": False,
            "reason": "Temporary or blocked domain"
        })

    # Remote check via GitHub Blocklist Data (Verifalia-style)
    try:
        gh_data = requests.get(
            CONFIG["blocklist_source"], timeout=5
        ).text.lower()
        if domain in gh_data:
            return jsonify({
                "email": email,
                "domain": domain,
                "valid": False,
                "reason": "Detected in blocklist-data"
            })
    except Exception:
        pass

    # Generic pattern-based detection (for tempmail)
    if any(word in domain for word in ["tempmail", "mailinator", "guerrillamail", "10minutemail", "dispostable", "trashmail", "sharklasers"]):
        return jsonify({
            "email": email,
            "domain": domain,
            "valid": False,
            "reason": "Temporary mail pattern detected"
        })

    return jsonify({
        "email": email,
        "domain": domain,
        "valid": True,
        "reason": "Genuine domain"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
