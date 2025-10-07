# updater.py - can be run to force update blocklist immediately
import requests, os, json, time
from datetime import datetime
BLOCK_DIR = 'blocklist'
os.makedirs(BLOCK_DIR,exist_ok=True)
urls = [
  "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains/refs/heads/master/domains.txt",
  "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains1/refs/heads/main/disposable_email_blocklist.conf",
  "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt"
]
out = set()
for u in urls:
    try:
        r = requests.get(u, timeout=20)
        if r.status_code==200:
            for ln in r.text.splitlines():
                ln=ln.strip()
                if not ln or ln.startswith('#'): continue
                if '@' in ln and ln.count('@')==1:
                    ln=ln.split('@',1)[1]
                out.add(ln.lower())
    except Exception as e:
        print('fail',u,e)
# save
with open(os.path.join(BLOCK_DIR,'blocklist.txt'),'w',encoding='utf-8') as f:
    for d in sorted(out):
        f.write(d+'\\n')
print('wrote',len(out),'domains at',datetime.now())
