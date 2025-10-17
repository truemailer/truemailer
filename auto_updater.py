# auto_updater.py
import requests, json, time, os

DATA_URL = "https://raw.githubusercontent.com/truemailer/blocklist-data/refs/heads/main/public_blocklist.json"
KEYS_URL = "https://raw.githubusercontent.com/truemailer/blocklist-data/refs/heads/main/keys.json"

def auto_update():
    try:
        print("🔄 Updating public list & keys…")
        bl = requests.get(DATA_URL, timeout=30)
        if bl.status_code == 200:
            # save raw text to blocklist/blocklist.txt
            os.makedirs("blocklist", exist_ok=True)
            open("blocklist/blocklist.txt","w",encoding="utf-8").write(bl.text)
        # keys.json (optional)
        k = requests.get(KEYS_URL, timeout=30)
        if k.status_code == 200:
            try:
                js = k.json()
                open("keys.json","w",encoding="utf-8").write(json.dumps(js, indent=2))
            except:
                pass
        print("✅ Updated successfully")
    except Exception as e:
        print("❌ Update failed:", e)

if __name__ == "__main__":
    while True:
        auto_update()
        time.sleep(24*3600)
