import os, requests

urls = [
    "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains/refs/heads/master/domains.txt",
    "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains1/refs/heads/main/disposable_email_blocklist.conf",
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt",
]

os.makedirs("blocklist", exist_ok=True)
domains = set()

for url in urls:
    print(f"Fetching {url} ...")
    try:
        res = requests.get(url, timeout=30)
        if res.status_code == 200:
            for line in res.text.splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    if "@" in line and line.count("@") == 1:
                        line = line.split("@", 1)[1]
                    domains.add(line)
    except Exception as e:
        print("Error:", e)

print(f"Fetched {len(domains)} domains total")
with open("blocklist/blocklist.txt", "w", encoding="utf-8") as f:
    for d in sorted(domains):
        f.write(d + "\n")
print("Saved -> blocklist/blocklist.txt")
