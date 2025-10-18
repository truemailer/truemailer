from fastapi.middleware.cors import CORSMiddleware

import json
import re
import requests
from flask import Flask, request, jsonify

# -----------------------------------------------------------
# Truemailer API — Final Stable Version (Render + Cloudflare)
# -----------------------------------------------------------
# Author: Ashish
# Description:
# This API verifies emails by:
# - Checking syntax validity
# - Using allowlist and blocklist
# - Matching against GitHub remote blocklist-data
# - Filtering temporary/disposable patterns
# -----------------------------------------------------------

app = Flask(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["https://your-github-username.github.io"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Configuration
with open("config.json", "r") as f:
    CONFIG = json.load(f)

# Load Blocklist and Allowlist
def load_json_file(filename):
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

ALLOWLIST = load_json_file("allowlist.json")
BLOCKLIST = load_json_file("blocklist.json")

# Email validation regex
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.route("/")
def index():
    return jsonify({
        "project": CONFIG.get("project_name", "Truemailer"),
        "status": "Active",
        "message": "Truemailer API is running successfully"
    })


@app.route("/verify", methods=["POST"])
def verify_email():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "email required"}), 400

    email = data["email"].lower().strip()

    # Step 1: Syntax check
    if not EMAIL_PATTERN.match(email):
        return jsonify({"email": email, "valid": False, "reason": "Invalid format"})

    domain = email.split("@")[1]

    # Step 2: Allowlist check
    if domain in ALLOWLIST:
        return jsonify({
            "email": email,
            "domain": domain,
            "valid": True,
            "reason": "Allowed domain"
        })

    # Step 3: Blocklist check (local)
    if domain in BLOCKLIST:
        return jsonify({
            "email": email,
            "domain": domain,
            "valid": False,
            "reason": "Blocked domain (local)"
        })

    # Step 4: Remote GitHub blocklist lookup
    try:
        resp = requests.get(CONFIG["blocklist_source"], timeout=5)
        if resp.status_code == 200 and domain in resp.text.lower():
            return jsonify({
                "email": email,
                "domain": domain,
                "valid": False,
                "reason": "Blocked domain (remote)"
            })
    except Exception:
        pass

    # Step 5: Keyword-based temporary detection
    temp_patterns = [
        "tempmail", "mailinator", "guerrillamail", "10minutemail",
        "dispostable", "trashmail", "sharklasers", "fakemail",
        "yopmail", "fakeinbox"
    ]
    if any(word in domain for word in temp_patterns):
        return jsonify({
            "email": email,
            "domain": domain,
            "valid": False,
            "reason": "Temporary email detected"
        })

    # Step 6: Genuine email
    return jsonify({
        "email": email,
        "domain": domain,
        "valid": True,
        "reason": "Genuine domain"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
