# api_gate.py
from flask import Flask, request, jsonify
import json, time, subprocess, os

app = Flask(__name__)

def load_json(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

# --- Check if key valid ---
def valid_key(api_key):
    clients = load_json("client.json")
    for client_name, info in clients.items():
        if info.get("key") == api_key:
            # simple expiry rule for demo — can extend later
            return client_name, True
    return None, False

# --- Log usage ---
def log_usage(client_name):
    clients = load_json("client.json")
    client = clients.get(client_name, {})
    client["calls"] = client.get("calls", 0) + 1
    client["last_used"] = int(time.time())
    clients[client_name] = client
    save_json("client.json", clients)

@app.route("/api/check", methods=["POST"])
def api_entry():
    api_key = request.headers.get("X-API-Key")
    client_name, is_valid = valid_key(api_key)

    if not is_valid:
        return jsonify({"error": "Invalid or expired API key"}), 403

    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Missing email"}), 400

    log_usage(client_name)

    try:
        result = subprocess.run(
            ["python3", "main.py", email],
            capture_output=True,
            text=True
        )
        return jsonify({
            "client": client_name,
            "email_checked": email,
            "result": result.stdout.strip()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
