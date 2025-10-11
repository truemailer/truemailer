# updater.py
import requests, os
urls = [
 "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt",
 "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
 "https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt"
]
out = set()
os.makedirs("blocklist", exist_ok=True)
for u in urls:
    try:
        r = requests.get(u, timeout=30)
        if r.status_code == 200:
            for ln in r.text.splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"): continue
                if "@" in ln and ln.count("@") == 1:
                    ln = ln.split("@",1)[1]
                out.add(ln.lower())
    except Exception as e:
        print("fail", u, e)
with open("blocklist/blocklist.txt","w",encoding="utf-8") as f:
    for d in sorted(out):
        f.write(d + "\\n")
print("wrote", len(out))
