import json
import re

# Load your existing disposable domain list (if stored in disposable_domains.json)
with open("disposable_domains.json", "r") as f:
    disposable_domains = set(json.load(f))

# Add college, company, and trusted providers you want always allowed
WHITELISTED_DOMAINS = {
    "gec.ac.in", "iitb.ac.in", "bits-pilani.ac.in", 
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com"
}

def is_valid_email(email: str) -> bool:
    """Checks format, disposable status, and whitelist."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False  # invalid format
    
    domain = email.split("@")[-1].lower()

    # Always allow whitelisted
    if domain in WHITELISTED_DOMAINS:
        return True

    # Check disposable
    if domain in disposable_domains:
        return False  # Block disposable

    # Default allow
    return True

# Example test
if __name__ == "__main__":
    emails = [
        "ashish@gec.ac.in", "test@tempmail.com", 
        "user@gmail.com", "demo@trashmail.org"
    ]
    for e in emails:
        print(e, "=>", is_valid_email(e))
