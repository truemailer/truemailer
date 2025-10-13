## auto_updater.py
import requests, json, time, os

DATA_URL = "https://raw.githubusercontent.com/truemailer/blocklist-data/refs/heads/main/public_blocklist.json"
KEYS_URL = "https://raw.githubusercontent.com/truemailer/blocklist-data/refs/heads/main/keys.json"

def auto_update():
    try:
        print("🔄 Updating public list & keys…")
        blocklist = requests.get(DATA_URL).json()
        keys = requests.get(KEYS_URL).json()

        # save locally for main.py to use
        with open("blocklist.json", "w") as f:
            json.dump(blocklist, f, indent=2)
        with open("keys.json", "w") as f:
            json.dump(keys, f, indent=2)

        print("✅ Updated successfully")
    except Exception as e:
        print("❌ Update failed:", e)

if __name__ == "__main__":
    while True:
        auto_update()
        time.sleep(86400)  # run every 24 h
