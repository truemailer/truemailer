import json
from urllib.parse import urlparse

# Load your local blocklist and allowlist
with open("blocklist.json") as f:
    blocklist = set(json.load(f))

with open("allowlist.json") as f:
    allowlist = set(json.load(f)["trusted"])

def is_allowed(email):
    """Check if email domain is trusted or blocked"""
    domain = email.split("@")[-1].lower().strip()

    # ✅ Always allow trusted ones
    if any(domain.endswith(a) for a in allowlist):
        return True

    # 🚫 Block if in blocklist
    if domain in blocklist:
        return False

    # ✅ Otherwise allow by default
    return True
