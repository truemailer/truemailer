# api_gate.py
from flask import Flask, request, jsonify
import json, time, subprocess

app = Flask(__name__)

def load_keys():
    with open("keys.json", "r") as f:
        return json.load(f)

def valid_key(api_key):
    keys = load_keys()
    for client, data in keys.items():
        if data["key"] == api_key and time.time() < data["expiry"]:
            return True
    return False

@app.route("/api/check", methods=["POST"])
def api_entry():
    api_key = request.headers.get("X-API-Key")
    if not valid_key(api_key):
        return jsonify({"error": "Invalid or expired API key"}), 403

    # ✅ If valid, forward to your main backend
    email = request.json.get("email")

    # Example: use subprocess to call your main.py as a command line checker
    # Replace with your actual check logic if you have a function import
    try:
        result = subprocess.run(
            ["python3", "main.py", email],
            capture_output=True, text=True
        )
        return jsonify({"result": result.stdout.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
