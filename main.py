from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import re
import datetime
import os

app = Flask(__name__)
CORS(app)

# -------------------------------
# CONFIG
# -------------------------------

API_KEYS = {
    "demo-key": {"limit": 100, "used": 0},
    "ashish-key": {"limit": 10000, "used": 0},
}

# Trusted domains
TRUSTED_DOMAINS = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com",
    "zoho.com", "icloud.com", "mail.com", "gmx.com", "tutanota.com"
]

# Disposable email domain list (add more here)
DISPOSABLE_DOMAINS = [
    "tempmail.com", "10minutemail.com", "guerrillamail.com", "gta5hx.com",
    "mailinator.com", "inilas.com", "forexzig.com", "sharklasers.com",
    "yopmail.com", "getnada.com", "trashmail.com"
]

# -------------------------------
# FUNCTIONS
# -------------------------------

def is_valid_email(email):
    """Basic email format validation"""
    pattern = r'^[^@\s]+@[^@\s]+\.[a-zA-Z0-9]+$'
    return re.match(pattern, email)

def check_mx_record(domain):
    """Check if domain has MX record"""
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def classify_email(email):
    """Classify the email as trusted, disposable, or unknown"""
    domain = email.split('@')[-1].lower()
    if domain in TRUSTED_DOMAINS:
        return "trusted"
    elif domain in DISPOSABLE_DOMAINS:
        return "disposable"
    elif check_mx_record(domain):
        return "valid"
    else:
        return "invalid"

# -------------------------------
# ROUTES
# -------------------------------

@app.route('/')
def home():
    return jsonify({"message": "✅ Email verification API is running!"})

@app.route('/verify', methods=['POST'])
def verify_email():
    try:
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in API_KEYS:
            return jsonify({"error": "Invalid or missing API key"}), 403

        client = API_KEYS[api_key]
        if client['used'] >= client['limit']:
            return jsonify({"error": "API limit exceeded"}), 429

        data = request.get_json()
        email = data.get('email', '').strip().lower()

        if not is_valid_email(email):
            return jsonify({"email": email, "valid": False, "reason": "invalid_format"}), 400

        result = classify_email(email)
        domain = email.split('@')[-1]

        response = {
            "email": email,
            "domain": domain,
            "classification": result,
            "checked_on": datetime.datetime.utcnow().isoformat() + "Z"
        }

        client['used'] += 1
        print(f"[{datetime.datetime.now()}] {email} -> {result}")

        return jsonify(response)

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "message": "✅ Server is running properly",
        "render": os.getenv('RENDER', 'false'),
        "replit": os.getenv('REPLIT', 'false'),
        "keys_active": len(API_KEYS)
    })

# -------------------------------
# START SERVER
# -------------------------------

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Server running on port {port}")
    app.run(host='0.0.0.0', port=port)
