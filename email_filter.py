import json

def is_allowed_domain(domain):
    try:
        # Load allowlist
        allow = json.load(open("allowlist.json"))["trusted_domains"]

        # Load blocklist (the one generated daily)
        with open("blocklist/blocklist.txt", "r", encoding="utf-8") as f:
            blocked = set([ln.strip().lower() for ln in f if ln.strip()])
    except Exception as e:
        print("⚠️ Failed to load lists:", e)
        return True  # if file missing, allow all to prevent crash

    # If domain in allowlist → always allow
    if domain in allow:
        return True

    # If domain in blocklist → block
    if domain in blocked:
        return False

    # Otherwise → allow (new or private domain)
    return True
