# ==============================================================
# EMAIL VALIDATION API - FULL VERSION (Render + Replit compatible)
# ==============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import re
import datetime
import os
import logging

# ---------------------------------------------------------------
# APP SETUP
# ---------------------------------------------------------------

app = Flask(__name__)
CORS(app)

# Setup logging
if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    filename="logs/server.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s]: %(message)s",
)

# ---------------------------------------------------------------
# API CONFIGURATION
# ---------------------------------------------------------------

API_KEYS = {
    "ashish-key": {"limit": 10000, "used": 0, "owner": "Ashish"},
    "demo-key": {"limit": 100, "used": 0, "owner": "Demo"},
}

# Trusted email domains
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com",
    "zoho.com", "icloud.com", "mail.com", "gmx.com", "tutanota.com"
]

# Common disposable email domains
DISPOSABLE_DOMAINS = [
    "tempmail.com", "10minutemail.com", "guerrillamail.com", "sharklasers.com",
    "mailinator.com", "inilas.com", "forexzig.com", "getnada.com", "trashmail.com",
    "yopmail.com", "dispostable.com", "fakeinbox.com", "maildrop.cc", "mintemail.com",
    "gta5hx.com", "tempmailer.com", "nobugmail.com", "spambog.com"
]

# ---------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------

def is_valid_email(email: str) -> bool:
    """Validate email format"""
    pattern = r"^[^@\s]+@[^@\s]+\.[a-zA-Z0-9]+$"
    return bool(re.match(pattern, email))

def check_mx_record(domain: str) -> bool:
    """Check for MX record existence"""
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except:
        return False

def classify_email(email: str) -> str:
    """Classify email as trusted, disposable, valid, or invalid"""
    domain = email.split("@")[-1].lower()

    if domain in TRUSTED_DOMAINS:
        return "trusted"
    elif domain in DISPOSABLE_DOMAINS:
        return "disposable"
    elif check_mx_record(domain):
        return "valid"
    else:
        return "invalid"

def api_key_valid(key: str) -> bool:
    """Check if API key is valid and within limit"""
    if key not in API_KEYS:
        return False
    return API_KEYS[key]["used"] < API_KEYS[key]["limit"]

def increment_api_usage(key: str):
    """Increase API usage count"""
    if key in API_KEYS:
        API_KEYS[key]["used"] += 1
        logging.info(f"API key '{key}' used ({API_KEYS[key]['used']}/{API_KEYS[key]['limit']})")

# ---------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------

@app.route("/")
def home():
    return jsonify({
        "message": "✅ Email Verification API is live and running!",
        "docs": "/verify (POST) | /status (GET)",
        "total_keys": len(API_KEYS)
    })

@app.route("/verify", methods=["POST"])
def verify_email():
    try:
        api_key = request.headers.get("X-API-Key")

        if not api_key or not api_key_valid(api_key):
            return jsonify({"error": "Invalid or missing API key"}), 403

        data = request.get_json()
        if not data or "email" not in data:
            return jsonify({"error": "Missing 'email' field"}), 400

        email = data["email"].strip().lower()

        if not is_valid_email(email):
            logging.warning(f"Invalid format: {email}")
            return jsonify({
                "email": email,
                "valid": False,
                "reason": "invalid_format"
            }), 400

        classification = classify_email(email)
        domain = email.split("@")[-1]
        result = {
            "email": email,
            "domain": domain,
            "classification": classification,
            "trusted": classification == "trusted",
            "disposable": classification == "disposable",
            "valid": classification in ["trusted", "valid"],
            "checked_on": datetime.datetime.utcnow().isoformat() + "Z"
        }

        # Update API usage
        increment_api_usage(api_key)
        logging.info(f"[{api_key}] {email} classified as {classification}")

        return jsonify(result)

    except Exception as e:
        logging.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/status", methods=["GET"])
def status():
    """Health check route"""
    active_keys = {
        k: {"used": v["used"], "limit": v["limit"], "owner": v["owner"]}
        for k, v in API_KEYS.items()
    }

    return jsonify({
        "message": "✅ Server running successfully",
        "platform": "Render or Replit",
        "keys": active_keys,
        "time": datetime.datetime.utcnow().isoformat() + "Z"
    })

@app.route("/create-key", methods=["POST"])
def create_key():
    """Admin route: create a new API key"""
    try:
        master_key = request.headers.get("X-Master-Key")
        if master_key != "ashish-master-2025":
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()
        name = data.get("name", "user")
        limit = int(data.get("limit", 100))

        new_key = f"{name}-{int(datetime.datetime.utcnow().timestamp())}"
        API_KEYS[new_key] = {"limit": limit, "used": 0, "owner": name}

        logging.info(f"New API key created for {name}: {new_key}")

        return jsonify({
            "message": "API key created successfully",
            "key": new_key,
            "limit": limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logs", methods=["GET"])
def view_logs():
    """Admin: View last 20 log entries"""
    try:
        master_key = request.headers.get("X-Master-Key")
        if master_key != "ashish-master-2025":
            return jsonify({"error": "Unauthorized"}), 403

        if not os.path.exists("logs/server.log"):
            return jsonify({"message": "No logs yet."})

        with open("logs/server.log", "r") as file:
            lines = file.readlines()[-20:]
        return jsonify({"logs": lines})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ---------------------------------------------------------------
# SERVER STARTUP
# ---------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Server running on port {port}")
    logging.info(f"Server started on port {port}")
    app.run(host="0.0.0.0", port=port)
