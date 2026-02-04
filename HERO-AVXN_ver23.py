#!/usr/bin/env python3
"""
Kali Sage Termux AV - Complete Fixed Version
Enhanced with better network error handling and VPN support
"""

from __future__ import annotations
import argparse, base64, hashlib, json, logging, os, pickle, random, shutil, stat
import subprocess, sys, threading, time, atexit, signal
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Set
from logging.handlers import RotatingFileHandler
from collections import defaultdict

# Force unbuffered output
class Unbuffered:
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)
sys.stderr = Unbuffered(sys.stderr)
os.environ['PYTHONUNBUFFERED'] = '1'

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import dotenv
    dotenv.load_dotenv()
except Exception as e:
    print("Install: pkg install python -y && pip install requests python-dotenv")
    raise

VT_API_KEY = os.getenv("VT_API_KEY")
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "quarantine_dir": "./quarantine",
    "log_file": "./kali_sage_termux_av.log",
    "log_max_bytes": 10485760,
    "log_backup_count": 3,
    "default_scan_dirs": [os.path.expanduser("~/storage/shared"), os.path.expanduser("~/downloads")],
    "scan_exceptions": ["./kali_sage_termux_av.log", "./.env", "./config.json"],
    "local_malware_hashes_file": "./malware_hashes.txt",
    "whitelist_hashes_file": "./whitelist_hashes.txt",
    "max_file_size_mb": 32,
    "default_scan_file_types": ["apk","sh","py","zip","tar","gz","rar","exe","pdf","dex","so"],
    "default_vpn_config_dir": os.path.join(os.path.expanduser("~"), "vpn"),
    "vpn_monitor_interval": 8,
    "threat_feeds": [
        {"name": "MalwareBazaar", "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/", "enabled": True},
        {"name": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/text/", "enabled": True}
    ]
}

CONFIG, LOG = {}, logging.getLogger("KaliSageAV")
LOCAL_MALWARE_HASHES, WHITELIST_HASHES = {}, set()
QUARANTINE_MANIFEST = "quarantine_manifest.json"
FIM_DB_FILE = "kali_sage_fim_db.json"
VPN_PROCESS, VPN_PROCESS_LOCK = None, threading.Lock()
SCRIPT_NETWORK_GATED = False
NETWORK_ERROR_COUNT, MAX_NETWORK_ERRORS = 0, 5

class Colors:
    HEADER, OKBLUE, OKCYAN, OKGREEN = '\033[95m', '\033[94m', '\033[96m', '\033[92m'
    WARNING, FAIL, ENDC, BOLD = '\033[93m', '\033[91m', '\033[0m', '\033[1m'

def create_requests_session():
    s = requests.Session()
    r = Retry(total=3, backoff_factor=2, status_forcelist=(429,500,502,503,504), raise_on_status=False)
    s.mount("https://", HTTPAdapter(max_retries=r, pool_connections=10, pool_maxsize=10))
    s.mount("http://", HTTPAdapter(max_retries=r, pool_connections=10, pool_maxsize=10))
    return s

HTTP = create_requests_session()

def setup_logging():
    global LOG
    lp = CONFIG.get("log_file", DEFAULT_CONFIG["log_file"])
    os.makedirs(os.path.dirname(os.path.abspath(lp)) or ".", exist_ok=True)
    LOG.setLevel(logging.INFO)
    LOG.handlers.clear()
    fh = RotatingFileHandler(lp, maxBytes=CONFIG.get("log_max_bytes",10485760), backupCount=3)
    ch = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(fmt); ch.setFormatter(fmt)
    LOG.addHandler(fh); LOG.addHandler(ch)
    LOG.info("Kali Sage AV Started")

def load_config():
    global CONFIG
    CONFIG = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f: CONFIG.update(json.load(f))
        except: pass
    for k in ["quarantine_dir","log_file","local_malware_hashes_file","whitelist_hashes_file","default_vpn_config_dir"]:
        if k in CONFIG: CONFIG[k] = os.path.abspath(os.path.expanduser(CONFIG[k]))
    os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
    os.makedirs(CONFIG["default_vpn_config_dir"], exist_ok=True)

def calc_hash(fp):
    try:
        h = hashlib.sha256()
        with open(fp, "rb") as f:
            while chunk := f.read(65536): h.update(chunk)
        return h.hexdigest()
    except: return None

def load_whitelist():
    global WHITELIST_HASHES
    p = CONFIG.get("whitelist_hashes_file")
    if p and os.path.exists(p):
        with open(p) as f:
            WHITELIST_HASHES = {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}

def load_malware_hashes():
    global LOCAL_MALWARE_HASHES
    p = CONFIG.get("local_malware_hashes_file")
    if p and os.path.exists(p):
        with open(p) as f:
            for ln in f:
                if not ln.strip() or ln.startswith("#"): continue
                parts = ln.split(None, 1)
                LOCAL_MALWARE_HASHES[parts[0].lower()] = parts[1] if len(parts)>1 else "Unknown"

def update_hashes_online():
    global NETWORK_ERROR_COUNT
    if SCRIPT_NETWORK_GATED:
        print(f"{Colors.WARNING}Network gated{Colors.ENDC}"); return False
    print(f"\n{Colors.HEADER}=== Updating Hash Database ==={Colors.ENDC}\n")
    new_hashes, total = {}, 0
    for feed in CONFIG.get("threat_feeds", []):
        if not feed.get("enabled"): continue
        name, url = feed["name"], feed["url"]
        print(f"{Colors.OKCYAN}Fetching: {name}...{Colors.ENDC}")
        try:
            r = HTTP.get(url, timeout=30); r.raise_for_status()
            count = 0
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                parts = line.split()
                for p in parts:
                    if len(p)==64 and all(c in '0123456789abcdefABCDEF' for c in p):
                        new_hashes[p.lower()] = f"{name}"; count += 1; break
            print(f"  {Colors.OKGREEN}✓ Added {count} hashes{Colors.ENDC}")
            total += count; NETWORK_ERROR_COUNT = 0
        except Exception as e:
            print(f"  {Colors.FAIL}✗ Error: {type(e).__name__}{Colors.ENDC}")
    LOCAL_MALWARE_HASHES.update(new_hashes)
    p = CONFIG.get("local_malware_hashes_file")
    with open(p, "w") as f:
        f.write(f"# Updated: {datetime.now().isoformat()}\n# Total: {len(LOCAL_MALWARE_HASHES)}\n\n")
        for h, d in sorted(LOCAL_MALWARE_HASHES.items()): f.write(f"{h} {d}\n")
    print(f"\n{Colors.OKGREEN}✓ Total: {len(LOCAL_MALWARE_HASHES)}, New: {total}{Colors.ENDC}")
    return True

def scan_local_hash(fp):
    h = calc_hash(fp)
    if not h or h.lower() in WHITELIST_HASHES: return {"malicious": False}
    desc = LOCAL_MALWARE_HASHES.get(h.lower())
    return {"malicious": bool(desc), "details": f"Local: {desc}", "hash": h} if desc else {"malicious": False}

def scan_virustotal(fp, timeout=30):
    global NETWORK_ERROR_COUNT
    if SCRIPT_NETWORK_GATED or not VT_API_KEY or NETWORK_ERROR_COUNT >= MAX_NETWORK_ERRORS: return None
    h = calc_hash(fp)
    if not h or h.lower() in WHITELIST_HASHES: return {"malicious": False}
    if os.path.getsize(fp)/(1024*1024) > CONFIG.get("max_file_size_mb",32): return {"malicious": False}
    try:
        r = HTTP.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey":VT_API_KEY}, timeout=timeout)
        if r.status_code==200:
            NETWORK_ERROR_COUNT = 0
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            mal = stats.get("malicious",0)
            return {"malicious": mal>0, "details": f"VT: {mal} detections"}
    except: NETWORK_ERROR_COUNT += 1
    return None

def quarantine(fp, reason="detected"):
    if not os.path.exists(fp): return False, "Not found"
    qdir = CONFIG["quarantine_dir"]
    qpath = os.path.join(qdir, f"{os.path.basename(fp)}.q_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    try:
        os.rename(fp, qpath)
        return True, qpath
    except Exception as e: return False, str(e)

def scan_storage(paths, method="both", action="ask", ftypes=None):
    if not isinstance(paths, list): paths = [paths]
    ftypes = set((ftypes or CONFIG.get("default_scan_file_types",[])))
    total, mal_files = 0, []
    print(f"\n{Colors.BOLD}=== Scanning ==={Colors.ENDC}\n")
    for path in paths:
        ap = os.path.abspath(os.path.expanduser(path))
        if not os.path.isdir(ap): continue
        for root, _, files in os.walk(ap):
            for fname in files:
                fp = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lstrip(".").lower()
                if ftypes and ext and ext not in ftypes: continue
                total += 1
                if total % 10 == 0: print(f"\n{Colors.BOLD}>>> Progress: {total} files{Colors.ENDC}")
                print(f"  [{total}] {fp if len(fp)<=70 else '...'+fp[-67:]}")
                local = scan_local_hash(fp)
                vt = scan_virustotal(fp) if method in ("virustotal","both") and not local.get("malicious") else None
                if local.get("malicious") or (vt and vt.get("malicious")):
                    mal_files.append(fp)
                    print(f"      {Colors.FAIL}⚠ THREAT{Colors.ENDC}")
                    if action=="quarantine": quarantine(fp)
                    elif action=="delete":
                        try: os.remove(fp)
                        except: pass
    print(f"\n{Colors.BOLD}Complete: {total} scanned, {len(mal_files)} threats{Colors.ENDC}\n")

def _has_root():
    try:
        r = subprocess.run(["id","-u"], capture_output=True, text=True)
        if r.returncode==0 and r.stdout.strip()=="0": return True
    except: pass
    return bool(shutil.which("tsu"))

def _get_ovpn_list():
    cfgdir = CONFIG.get("default_vpn_config_dir")
    possible_dirs = [
        cfgdir, 
        "/data/data/com.termux/files/termux_distro/vpn",
        os.path.join(os.path.expanduser("~"), "vpn"),
        "/sdcard/vpn",
        "/sdcard/Download"
    ]
    for check_dir in possible_dirs:
        if not os.path.exists(check_dir): continue
        try:
            files = [os.path.join(check_dir, f) for f in os.listdir(check_dir) if f.lower().endswith('.ovpn')]
            if files:
                print(f"{Colors.OKGREEN}Found configs in: {check_dir}{Colors.ENDC}")
                return files
        except: pass
    return []

def start_vpn(cfg):
    global VPN_PROCESS
    if not os.path.exists(cfg):
        print(f"{Colors.FAIL}Config not found{Colors.ENDC}"); return
    has_root = _has_root()
    if not has_root:
        print(f"\n{Colors.WARNING}No root - OpenVPN likely won't work{Colors.ENDC}")
        print(f"Try: OpenVPN for Android app (works without root)")
        choice = input(f"Continue anyway? (yes/no): ").lower()
        if choice != "yes": return
    if not shutil.which("openvpn"):
        print(f"{Colors.FAIL}OpenVPN not installed{Colors.ENDC}"); return
    logpath = os.path.join(os.path.dirname(CONFIG.get("log_file")), "vpn.log")
    try:
        vpn_log = open(logpath, "a")
        VPN_PROCESS = subprocess.Popen(["openvpn", "--config", cfg], stdout=vpn_log, stderr=vpn_log)
        print(f"{Colors.OKGREEN}VPN started (PID {VPN_PROCESS.pid}){Colors.ENDC}")
        time.sleep(5)
        if VPN_PROCESS.poll() is not None:
            print(f"{Colors.FAIL}VPN died - check log: {logpath}{Colors.ENDC}")
            VPN_PROCESS = None
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

def stop_vpn():
    global VPN_PROCESS
    if not VPN_PROCESS:
        print(f"{Colors.WARNING}Not running{Colors.ENDC}"); return
    try:
        VPN_PROCESS.terminate()
        VPN_PROCESS.wait(timeout=5)
        print(f"{Colors.OKGREEN}Stopped{Colors.ENDC}")
    except: pass
    VPN_PROCESS = None

def vpn_status():
    if VPN_PROCESS and VPN_PROCESS.poll() is None:
        print(f"{Colors.OKGREEN}VPN RUNNING (PID {VPN_PROCESS.pid}){Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}VPN NOT RUNNING{Colors.ENDC}")

def main_menu():
    while True:
        print(f"\n{Colors.HEADER}╔═══════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.HEADER}║   Kali Sage Termux AV Menu       ║{Colors.ENDC}")
        print(f"{Colors.HEADER}╚═══════════════════════════════════╝{Colors.ENDC}\n")
        print("1. Scan file")
        print("2. Scan storage")
        print("3. Update hash database")
        print("4. VPN menu")
        print("5. Quarantine management")
        print("0. Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice=="1":
            fp = input("File path: ").strip()
            if fp:
                local = scan_local_hash(fp)
                vt = scan_virustotal(fp)
                if local.get("malicious") or (vt and vt.get("malicious")):
                    print(f"{Colors.FAIL}MALICIOUS{Colors.ENDC}")
                    act = input("Action? (q=quarantine d=delete s=skip): ").lower()
                    if act=="q": quarantine(fp)
                    elif act=="d":
                        try: os.remove(fp)
                        except: pass
                else:
                    print(f"{Colors.OKGREEN}Clean{Colors.ENDC}")
        
        elif choice=="2":
            method = input("Method (local/virustotal/both) [both]: ").strip() or "both"
            dirs = CONFIG["default_scan_dirs"]
            scan_storage(dirs, method, "ask")
        
        elif choice=="3":
            update_hashes_online()
        
        elif choice=="4":
            print(f"\n{Colors.BOLD}VPN Menu:{Colors.ENDC}")
            print("1. Connect VPN")
            print("2. Disconnect VPN")
            print("3. VPN Status")
            print("4. List configs")
            print("0. Back")
            
            c = input("\nChoice: ").strip()
            
            if c=="1":
                ovpns = _get_ovpn_list()
                if not ovpns:
                    print(f"{Colors.FAIL}No .ovpn files found{Colors.ENDC}")
                    print(f"Place .ovpn files in ~/vpn/")
                else:
                    print(f"\n{Colors.OKGREEN}Available VPN Configs:{Colors.ENDC}\n")
                    for i, f in enumerate(ovpns):
                        name = os.path.basename(f).replace('.ovpn','').replace('-',' ').replace('_',' ')
                        print(f"  {i+1}. {name}")
                    print(f"  r. Random")
                    sel = input("\nSelect: ").strip().lower()
                    if sel=="r":
                        start_vpn(random.choice(ovpns))
                    else:
                        try:
                            idx = int(sel)-1
                            if 0 <= idx < len(ovpns): start_vpn(ovpns[idx])
                        except: pass
            elif c=="2":
                stop_vpn()
            elif c=="3":
                vpn_status()
            elif c=="4":
                ovpns = _get_ovpn_list()
                if ovpns:
                    for f in ovpns: print(f"  • {os.path.basename(f)}")
                else:
                    print(f"No configs found")
        
        elif choice=="5":
            qdir = CONFIG["quarantine_dir"]
            items = sorted(os.listdir(qdir)) if os.path.exists(qdir) else []
            if items:
                for i,f in enumerate(items): print(f"{i+1}. {f}")
            else:
                print("Empty")
        
        elif choice=="0":
            break
        
        input("\nPress Enter...")

def main():
    load_config()
    setup_logging()
    load_malware_hashes()
    load_whitelist()
    if not VT_API_KEY:
        print(f"{Colors.WARNING}VT_API_KEY not set{Colors.ENDC}")
    main_menu()

if __name__ == "__main__":
    main()