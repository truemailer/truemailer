import requests, json, time

LIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"

def update_disposable_list():
    try:
        print("🔄 Updating disposable domains list...")
        resp = requests.get(LIST_URL)
        domains = [d.strip() for d in resp.text.split("\n") if d and not d.startswith("#")]
        with open("disposable_domains.json", "w") as f:
            json.dump(domains, f, indent=2)
        print(f"✅ Updated {len(domains)} domains.")
    except Exception as e:
        print("❌ Update failed:", e)

if __name__ == "__main__":
    update_disposable_list()
