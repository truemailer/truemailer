# main.py - Truemailer final
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import re, os, time, threading, json
import dns.resolver, requests

APP_NAME = "Truemailer"
app = FastAPI(title=APP_NAME)
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

# Config files
CLIENTS_FILE = "clients.json"
CONFIG_FILE = "config.json"
BLOCKLIST_TXT = os.path.join("blocklist","blocklist.txt")

# load config (or defaults)
DEFAULT_CONFIG = {
  "require_api_key": True,
  "rate_limit_per_day": 100,
  "trusted_providers": ["gmail.com","googlemail.com","outlook.com","hotmail.com","yahoo.com","icloud.com","protonmail.com","zoho.com","mail.com","yandex.com"],
  "remote_blocklist_urls": [
    "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains/refs/heads/master/domains.txt",
    "https://raw.githubusercontent.com/ashishnaikbackup-sketch/disposable-email-domains1/refs/heads/main/disposable_email_blocklist.conf",
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/domains.txt"
  ],
  "update_interval_seconds": 24*3600,
  "mx_check_enabled": True
}

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE,'r') as f:
        CONFIG = json.load(f)
else:
    CONFIG = DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE,'w') as f:
        json.dump(CONFIG,f,indent=2)

# load clients or create demo
if os.path.exists(CLIENTS_FILE):
    with open(CLIENTS_FILE,'r') as f:
        CLIENTS = json.load(f)
else:
    CLIENTS = {"demo": {"key":"demo_key_123","name":"Demo Client","limit": CONFIG.get("rate_limit_per_day",100), "usage": {}}}
    with open(CLIENTS_FILE,'w') as f:
        json.dump(CLIENTS,f,indent=2)

# in-memory blockset
BLOCKSET = set()
BLOCKSET_LOCK = threading.Lock()

EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,255}$')

def load_local_blocklist():
    s=set()
    try:
        if os.path.exists(BLOCKLIST_TXT):
            with open(BLOCKLIST_TXT,'r',encoding='utf-8',errors='ignore') as fh:
                for ln in fh:
                    ln=ln.strip().lower()
                    if not ln or ln.startswith('#'): continue
                    if '@' in ln and ln.count('@')==1:
                        ln=ln.split('@',1)[1]
                    s.add(ln)
    except Exception:
        pass
    return s

def save_blocklist(domains):
    try:
        with open(BLOCKLIST_TXT,'w',encoding='utf-8') as fh:
            for d in sorted(domains):
                fh.write(d+'\n')
    except Exception:
        pass

def fetch_and_merge_remote():
    urls = CONFIG.get("remote_blocklist_urls",[])
    domains=set()
    for u in urls:
        try:
            r = requests.get(u, timeout=20)
            if r.status_code==200:
                for ln in r.text.splitlines():
                    ln=ln.strip()
                    if not ln or ln.startswith('#'): continue
                    if '@' in ln and ln.count('@')==1:
                        ln=ln.split('@',1)[1]
                    domains.add(ln.lower())
        except Exception:
            continue
    # include local extra
    local = load_local_blocklist()
    domains.update(local)
    save_blocklist(domains)
    return domains

def refresh_blockset():
    global BLOCKSET
    new = fetch_and_merge_remote()
    with BLOCKSET_LOCK:
        BLOCKSET = set(new)
    return len(BLOCKSET)

# initial load (best-effort)
try:
    BLOCKSET = load_local_blocklist()
    # try remote merge but don't block startup
    threading.Thread(target=refresh_blockset,daemon=True).start()
except Exception:
    BLOCKSET=set()

# background updater
def updater_loop():
    while True:
        try:
            refresh_blockset()
        except Exception:
            pass
        time.sleep(CONFIG.get("update_interval_seconds",24*3600))

t = threading.Thread(target=updater_loop,daemon=True)
t.start()

# helper functions: api key, rate limits
def get_client_by_key(key):
    for cid,info in CLIENTS.items():
        if info.get("key")==key:
            return cid,info
    return None,None

def check_and_consume_quota(client_id):
    now_day = time.strftime("%Y-%m-%d")
    client = CLIENTS.get(client_id)
    if client is None: return False, "invalid client"
    usage = client.setdefault("usage",{})
    cnt = usage.get(now_day,0)
    if cnt >= client.get("limit", CONFIG.get("rate_limit_per_day",100)):
        return False, "daily limit exceeded"
    usage[now_day] = cnt+1
    # persist small write
    try:
        with open(CLIENTS_FILE,'w',encoding='utf-8') as fh:
            json.dump(CLIENTS,fh,indent=2)
    except Exception:
        pass
    return True, None

def domain_from_email(email):
    return email.split('@',1)[-1].lower().strip()

def has_mx(domain,timeout=2.0):
    if not CONFIG.get("mx_check_enabled", True):
        return True
    try:
        dns.resolver.resolve(domain,'MX',lifetime=timeout)
        return True
    except Exception:
        return False

# endpoints
@app.get('/verify')
def verify_get(email: str=None, api_key: str=None, request: Request=None):
    if not email:
        raise HTTPException(status_code=400,detail="Provide ?email=someone@domain.tld")
    # API key enforcement
    if CONFIG.get("require_api_key",True):
        key = api_key or (request.headers.get('x-api-key') if request else None)
        if not key:
            raise HTTPException(status_code=401,detail="API key required")
        cid,info = get_client_by_key(key)
        if cid is None:
            raise HTTPException(status_code=401,detail="Invalid API key")
        ok,msg = check_and_consume_quota(cid)
        if not ok:
            raise HTTPException(status_code=429,detail=msg)
    else:
        cid='anon'
    email=email.strip()
    if not EMAIL_RE.match(email):
        return JSONResponse({"email":email,"valid":False,"reason":"invalid_syntax","disposable":False,"mx":False})
    domain = domain_from_email(email)
    # trusted providers quick allow
    if domain in CONFIG.get("trusted_providers",[]):
        mx = has_mx(domain) if CONFIG.get("mx_check_enabled",True) else True
        return JSONResponse({"email":email,"valid":True,"reason":"trusted_provider","disposable":False,"mx":mx,"provider":domain})
    # blocklist check
    if domain in BLOCKSET:
        return JSONResponse({"email":email,"valid":False,"reason":"disposable_domain","disposable":True,"mx":False})
    # mx check
    mx = has_mx(domain) if CONFIG.get("mx_check_enabled",True) else True
    if not mx:
        return JSONResponse({"email":email,"valid":False,"reason":"no_mx","disposable":False,"mx":False})
    return JSONResponse({"email":email,"valid":True,"reason":"valid","disposable":False,"mx":True,"provider":domain})

@app.post('/update-now')
def update_now(api_key: str=None):
    # allow admin trigger if demo key provided; skip auth for simplicity
    n = refresh_blockset()
    return {"updated":True,"domains":n}

@app.get('/status')
def status():
    return {"ok":True,"loaded":len(BLOCKSET),"clients":list(CLIENTS.keys())}

@app.get('/')
def home():
    p = os.path.join('static','index.html')
    if os.path.exists(p):
        return FileResponse(p)
    return JSONResponse({'detail':'index not found'},status_code=500)
