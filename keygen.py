# keygen.py
import uuid, time, json, os

def load_keys():
    if os.path.exists("keys.json"):
        with open("keys.json", "r") as f:
            return json.load(f)
    return {}

def save_keys(keys):
    with open("keys.json", "w") as f:
        json.dump(keys, f, indent=2)

def generate_key(client_name, plan_days, plan_type):
    keys = load_keys()
    key = str(uuid.uuid4())
    expiry = int(time.time()) + plan_days * 86400
    data = {
        "key": key,
        "expiry": expiry,
        "plan": plan_type
    }
    keys[client_name] = data
    save_keys(keys)
    print(f"✅ Key created for {client_name} ({plan_type}): {key}")
    print(f"⏳ Valid for {plan_days} days")
    return key

def renew_key(client_name, extra_days):
    keys = load_keys()
    if client_name in keys:
        keys[client_name]["expiry"] += extra_days * 86400
        save_keys(keys)
        print(f"♻️ Renewed {client_name} for {extra_days} days more")
    else:
        print("⚠️ Client not found!")

def show_keys():
    keys = load_keys()
    for name, data in keys.items():
        print(f"{name}: {data}")

if __name__ == "__main__":
    print("""
1️⃣ Generate new key
2️⃣ Renew existing key
3️⃣ Show all keys
""")
    choice = input("Choose: ")
    if choice == "1":
        name = input("Client name: ")
        days = int(input("Valid for (days): "))
        plan = input("Plan type (demo/full): ")
        generate_key(name, days, plan)
    elif choice == "2":
        name = input("Client name to renew: ")
        days = int(input("Add days: "))
        renew_key(name, days)
    elif choice == "3":
        show_keys()
