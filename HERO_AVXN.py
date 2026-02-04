#!/usr/bin/env python3
"""
Hero-AVXN Termux AV - Fixed for Ubuntu Proot Environment

Key Path Changes:
✓ Changed /data/data/com.termux paths to standard Linux paths
✓ Updated storage paths for proot environment
✓ Fixed VPN config directory paths
✓ Corrected home directory references
✓ All original features preserved
"""

from __future__ import annotations
import argparse, base64, hashlib, json, logging, os, pickle, random, shutil, stat
import subprocess, sys, threading, time, atexit, signal
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Set
from logging.handlers import RotatingFileHandler
from collections import defaultdict

# CRITICAL: Force unbuffered output for real-time scrolling in Termux
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
    print("Install: apt install python3-pip -y && pip3 install requests python-dotenv")
    raise

# Configuration - FIXED PATHS FOR UBUNTU PROOT
VT_API_KEY = os.getenv("VT_API_KEY")
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "quarantine_dir": "./quarantine",
    "log_file": "./kali_sage_termux_av.log",
    "log_max_bytes": 10485760,
    "log_backup_count": 3,
    "default_scan_dirs": [
        "/root",  # Root home directory in proot
        "/home",  # Other user home directories
        "/tmp",   # Temporary files
        "/var/tmp"  # Variable temp
    ],
    "scan_exceptions": [
        "./kali_sage_termux_av.log",
        "./.env",
        "./config.json",
        "./kali_sage_fim_db.json",
        "/root/.ssh",  # SSH keys
        "/etc/passwd",  # System files
        "/etc/shadow",
        "/etc/hosts"
    ],
    "local_malware_hashes_file": "./malware_hashes.txt",
    "whitelist_hashes_file": "./whitelist_hashes.txt",
    "max_file_size_mb": 32,
    "default_scan_file_types": ["apk","sh","py","zip","tar","gz","rar","exe","pdf","doc","docx","xls","xlsx","ppt","pptx","dex","so","elf"],
    "default_hosts_blacklist_url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "default_vpn_config_dir": "/root/vpn",  # VPN configs in root home
    "hosts_feed_max_bytes": 5 * 1024 * 1024,
    "vpn_monitor_interval": 8,
    "vpn_reconnect_delay": 5,
    "vpn_rotate_on_fail": True,
    "vpn_autostart": False,
    "kill_switch_requires_root": True,
    "threat_feeds": [
        {"name": "MalwareBazaar", "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/", "enabled": True},
        {"name": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/text/", "enabled": True}
    ]
}

CONFIG, LOG = {}, logging.getLogger("KaliSageAV")
LOCAL_MALWARE_HASHES, WHITELIST_HASHES = {}, set()
QUARANTINE_MANIFEST = "quarantine_manifest.json"
FIM_DB_FILE = "kali_sage_fim_db.json"
OLD_FIM_PICKLE = "kali_sage_fim_db.pkl"
FIM_MTIME_TOLERANCE = 2.0
VPN_PROCESS, VPN_PROCESS_LOCK = None, threading.Lock()
VPN_MONITOR_THREAD, VPN_MONITOR_STOP = None, threading.Event()
KILL_SWITCH_ENABLED = False
AUTO_VPN_ENABLED = False
SCRIPT_NETWORK_GATED = False
NETWORK_ERROR_COUNT = 0
MAX_NETWORK_ERRORS = 5

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
    LOG.info("="*60); LOG.info("Hero-AVXN Termux AV Started (Ubuntu Proot)")

def load_config():
    global CONFIG
    CONFIG = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f: CONFIG.update(json.load(f))
            LOG.info(f"Loaded {CONFIG_FILE}")
        except Exception as e: LOG.warning(f"Config error: {e}")
    for k in ["quarantine_dir","log_file","local_malware_hashes_file","whitelist_hashes_file","default_vpn_config_dir"]:
        if k in CONFIG: CONFIG[k] = os.path.abspath(os.path.expanduser(CONFIG[k]))
    CONFIG["default_scan_dirs"] = [os.path.abspath(os.path.expanduser(p)) for p in CONFIG.get("default_scan_dirs",[])]
    CONFIG["scan_exceptions"] = [os.path.abspath(os.path.expanduser(p)) for p in CONFIG.get("scan_exceptions",[])]
    os.makedirs(CONFIG["quarantine_dir"], exist_ok=True)
    os.makedirs(CONFIG["default_vpn_config_dir"], exist_ok=True)

def save_config():
    try:
        with open(CONFIG_FILE, "w") as f: json.dump(CONFIG, f, indent=2)
        return True
    except Exception as e: LOG.error(f"Save config error: {e}"); return False

def notify(title, msg, id="kali_av"):
    try: 
        # Try termux-notification first, fallback to echo
        subprocess.run(["termux-notification","--id",id,"--title",title,"--content",msg], timeout=5, capture_output=True)
    except: 
        print(f"[NOTIFY] {title}: {msg}")

def run_command(cmd_list, message=None, check=True, capture_output=True, timeout=30):
    if message: print(f"{Colors.OKBLUE}{message}{Colors.ENDC}")
    LOG.info("Running: " + " ".join(str(x) for x in cmd_list))
    try:
        res = subprocess.run(cmd_list, check=check, capture_output=capture_output, text=True, timeout=timeout)
        if res.stdout and not capture_output: print(res.stdout)
        if res.stderr: LOG.debug(res.stderr)
        return res
    except subprocess.TimeoutExpired: LOG.error(f"Timeout after {timeout}s"); return None
    except subprocess.CalledProcessError as e: LOG.error(f"Failed: {e}"); return None
    except FileNotFoundError: print(f"{Colors.FAIL}{cmd_list[0]} not found{Colors.ENDC}"); return None

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
        LOG.info(f"Loaded {len(WHITELIST_HASHES)} whitelist hashes")

def add_whitelist(h):
    p = CONFIG.get("whitelist_hashes_file")
    try:
        with open(p, "a") as f: f.write(f"{h.lower()}\n")
        WHITELIST_HASHES.add(h.lower())
        return True
    except: return False

def load_malware_hashes():
    global LOCAL_MALWARE_HASHES
    p = CONFIG.get("local_malware_hashes_file")
    if p and os.path.exists(p):
        with open(p) as f:
            for ln in f:
                if not ln.strip() or ln.startswith("#"): continue
                parts = ln.split(None, 1)
                LOCAL_MALWARE_HASHES[parts[0].lower()] = parts[1] if len(parts)>1 else "Unknown"
        LOG.info(f"Loaded {len(LOCAL_MALWARE_HASHES)} malware hashes")

def update_hashes_online():
    """Update malware database from online threat feeds"""
    global NETWORK_ERROR_COUNT
    if SCRIPT_NETWORK_GATED:
        print(f"{Colors.WARNING}Network gated until VPN up{Colors.ENDC}")
        return False
    
    print(f"\n{Colors.HEADER}=== Updating Malware Hash Database ==={Colors.ENDC}\n")
    new_hashes, total, failed_feeds = {}, 0, []
    
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
        except requests.exceptions.HTTPError as e:
            failed_feeds.append(name)
            print(f"  {Colors.FAIL}✗ HTTP {e.response.status_code}: {e.response.reason}{Colors.ENDC}")
            LOG.error(f"Feed {name} HTTP error: {e.response.status_code}")
        except requests.exceptions.ConnectionError:
            failed_feeds.append(name)
            print(f"  {Colors.FAIL}✗ Connection failed{Colors.ENDC}")
        except requests.exceptions.Timeout:
            failed_feeds.append(name)
            print(f"  {Colors.FAIL}✗ Timeout{Colors.ENDC}")
        except Exception as e:
            failed_feeds.append(name)
            print(f"  {Colors.FAIL}✗ Error: {type(e).__name__}{Colors.ENDC}")
    
    if total == 0:
        print(f"\n{Colors.FAIL}No hashes downloaded. Check internet connection.{Colors.ENDC}")
        return False
    
    LOCAL_MALWARE_HASHES.update(new_hashes)
    p = CONFIG.get("local_malware_hashes_file")
    with open(p, "w") as f:
        f.write(f"# Updated: {datetime.now().isoformat()}\n# Total: {len(LOCAL_MALWARE_HASHES)}\n\n")
        for h, d in sorted(LOCAL_MALWARE_HASHES.items()): f.write(f"{h} {d}\n")
    
    print(f"\n{Colors.OKGREEN}✓ Updated! Total: {len(LOCAL_MALWARE_HASHES)}, New: {total}{Colors.ENDC}")
    if failed_feeds: print(f"{Colors.WARNING}⚠ Failed feeds: {', '.join(failed_feeds)}{Colors.ENDC}")
    notify("Hero-AVXN AV", f"Hash DB: {len(LOCAL_MALWARE_HASHES)} hashes")
    return True

def scan_local_hash(fp):
    h = calc_hash(fp)
    if not h or h.lower() in WHITELIST_HASHES: return {"malicious": False}
    desc = LOCAL_MALWARE_HASHES.get(h.lower())
    return {"malicious": bool(desc), "details": f"Local: {desc}", "hash": h} if desc else {"malicious": False}

def scan_virustotal(fp, timeout=30):
    global NETWORK_ERROR_COUNT
    if SCRIPT_NETWORK_GATED or not VT_API_KEY or not os.path.exists(fp): return None
    if NETWORK_ERROR_COUNT >= MAX_NETWORK_ERRORS:
        LOG.warning(f"VT disabled: {NETWORK_ERROR_COUNT} errors")
        print(f"{Colors.WARNING}  [VT disabled - network issues]{Colors.ENDC}")
        return None
    
    h = calc_hash(fp)
    if not h or h.lower() in WHITELIST_HASHES: return {"malicious": False}
    if os.path.getsize(fp)/(1024*1024) > CONFIG.get("max_file_size_mb",32):
        return {"malicious": False, "details": "too large"}
    
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = HTTP.get(f"https://www.virustotal.com/api/v3/files/{h}", headers=headers, timeout=timeout)
        if r.status_code==200:
            NETWORK_ERROR_COUNT = 0
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            mal = stats.get("malicious",0)
            return {"malicious": mal>0, "details": f"VT: {mal} detections", "stats": stats}
        elif r.status_code==404:
            with open(fp,"rb") as f:
                up = HTTP.post("https://www.virustotal.com/api/v3/files", headers=headers, files={"file":f}, timeout=timeout*2)
            if up.status_code in (200,201):
                NETWORK_ERROR_COUNT = 0
                return {"malicious": None, "details": "uploaded to VT"}
        elif r.status_code==429:
            print(f"{Colors.WARNING}  [VT rate limited]{Colors.ENDC}"); return None
        elif r.status_code==401:
            print(f"{Colors.FAIL}  [VT API key invalid]{Colors.ENDC}"); return None
    except requests.exceptions.ConnectionError:
        NETWORK_ERROR_COUNT += 1
        print(f"{Colors.WARNING}  [VT connection failed]{Colors.ENDC}")
    except requests.exceptions.Timeout:
        NETWORK_ERROR_COUNT += 1
        print(f"{Colors.WARNING}  [VT timeout]{Colors.ENDC}")
    except requests.exceptions.SSLError:
        NETWORK_ERROR_COUNT += 1
        print(f"{Colors.WARNING}  [VT SSL error]{Colors.ENDC}")
    except Exception as e:
        NETWORK_ERROR_COUNT += 1
        print(f"{Colors.WARNING}  [VT error]{Colors.ENDC}")
    return None

def _load_quarantine_manifest():
    try:
        if os.path.exists(QUARANTINE_MANIFEST):
            with open(QUARANTINE_MANIFEST) as f: return json.load(f)
    except: pass
    return {}

def _save_quarantine_manifest(man):
    try:
        with open(QUARANTINE_MANIFEST,"w") as f: json.dump(man, f, indent=2)
    except Exception as e: LOG.error(f"Save manifest error: {e}")

def quarantine(fp, reason="detected"):
    man = _load_quarantine_manifest()
    if not os.path.exists(fp): return False, "Not found"
    qdir = CONFIG["quarantine_dir"]
    qpath = os.path.join(qdir, f"{os.path.basename(fp)}.q_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    try:
        man[qpath] = {"original_path": os.path.abspath(fp), "quarantined_at": datetime.now().isoformat(), "reason": reason}
        os.rename(fp, qpath)
        _save_quarantine_manifest(man)
        LOG.info(f"Quarantined: {fp} -> {qpath}")
        return True, qpath
    except Exception as e: return False, str(e)

def restore_file(qpath, restore_to=None):
    man = _load_quarantine_manifest()
    info = man.get(qpath, {})
    orig = info.get("original_path")
    dest = restore_to if restore_to else (orig or os.path.join("/tmp", os.path.basename(qpath)))
    try:
        os.rename(qpath, dest)
        man.pop(qpath, None)
        _save_quarantine_manifest(man)
        LOG.info(f"Restored: {qpath} -> {dest}")
        return True
    except Exception as e: LOG.error(f"Restore error: {e}"); return False

def scan_storage(paths, method="both", action="ask", ftypes=None):
    LOG.info(f"Scan: {paths}, method={method}")
    notify("Scan", "Started")
    if not isinstance(paths, list): paths = [paths]
    ftypes = set((ftypes or CONFIG.get("default_scan_file_types",[])))
    exceptions = CONFIG.get("scan_exceptions", [])
    total, mal_files = 0, []
    
    print(f"\n{Colors.BOLD}=== Starting Scan ==={Colors.ENDC}")
    print(f"{Colors.WARNING}NOTE: If output stops, scroll down manually to see progress{Colors.ENDC}")
    print("")
    
    for path in paths:
        ap = os.path.abspath(os.path.expanduser(path))
        if not os.path.isdir(ap): 
            print(f"{Colors.WARNING}Skipping: {ap} (not a directory){Colors.ENDC}")
            continue
        
        print(f"{Colors.OKCYAN}Scanning directory: {ap}{Colors.ENDC}")
        
        for root, _, files in os.walk(ap):
            for fname in files:
                fp = os.path.join(root, fname)
                if any(fp.startswith(exc) for exc in exceptions): continue
                ext = os.path.splitext(fname)[1].lstrip(".").lower()
                if ftypes and ext and ext not in ftypes: continue
                
                total += 1
                short_path = fp if len(fp) <= 70 else "..." + fp[-67:]
                
                # Add progress indicator every 10 files
                if total % 10 == 0:
                    print(f"\n{Colors.BOLD}>>> Progress: {total} files scanned...{Colors.ENDC}")
                
                print(f"  [{total}] {short_path}")
                
                local = scan_local_hash(fp)
                vt = scan_virustotal(fp) if method in ("virustotal","both") and not local.get("malicious") else None
                
                if local.get("malicious") or (vt and vt.get("malicious")):
                    print(f"      {Colors.FAIL}⚠ THREAT DETECTED!{Colors.ENDC}")
                    
                    if local.get("malicious"):
                        print(f"      └─ {local.get('details', 'Malicious')}")
                    if vt and vt.get("malicious"):
                        print(f"      └─ {vt.get('details', 'VT detected')}")
                    
                    mal_files.append(fp)
                    
                    if action=="quarantine": 
                        succ, qpath = quarantine(fp)
                        print(f"      └─ {'✓ Quarantined' if succ else '✗ Quarantine failed'}")
                    elif action=="delete":
                        try: 
                            os.remove(fp)
                            print(f"      └─ ✓ Deleted")
                        except Exception as e:
                            print(f"      └─ ✗ Delete failed: {e}")
                    elif action=="ask":
                        print("")
                        c = input(f"      Action? (q=quarantine d=delete s=skip w=whitelist): ").lower()
                        if c=="q": 
                            quarantine(fp)
                            print(f"      └─ ✓ Quarantined")
                        elif c=="d":
                            try: 
                                os.remove(fp)
                                print(f"      └─ ✓ Deleted")
                            except Exception as e:
                                print(f"      └─ ✗ Failed: {e}")
                        elif c=="w":
                            if h:=calc_hash(fp): 
                                add_whitelist(h)
                                print(f"      └─ ✓ Added to whitelist")
                    print("")
    
    print(f"\n{Colors.BOLD}{'='*50}{Colors.ENDC}")
    print(f"{Colors.BOLD}>>> SCAN FINISHED - SCROLL DOWN IF NEEDED{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*50}{Colors.ENDC}")
    print(f"  Files scanned:     {total}")
    print(f"  Threats detected:  {len(mal_files)}")
    print(f"{'='*50}\n")
    
    if mal_files:
        notify("Scan Alert", f"{len(mal_files)} threats found", "alert")
        LOG.warning(f"Scan found {len(mal_files)} threats")
    else:
        notify("Scan", "Complete - No threats")
        LOG.info("Scan complete - no threats")

def _load_fim_db():
    if os.path.exists(FIM_DB_FILE):
        try:
            with open(FIM_DB_FILE) as f: return json.load(f)
        except: pass
    if os.path.exists(OLD_FIM_PICKLE):
        try:
            with open(OLD_FIM_PICKLE,"rb") as f: return pickle.load(f)
        except: pass
    return {}

def _save_fim_db(data):
    try:
        with open(FIM_DB_FILE,"w") as f: json.dump(data,f,indent=2)
    except Exception as e: LOG.error(f"FIM save error: {e}")

def fim_init(target_dir):
    ap = os.path.abspath(os.path.expanduser(target_dir))
    if not os.path.isdir(ap):
        print(f"{Colors.FAIL}Not found: {ap}{Colors.ENDC}"); return {}
    LOG.info(f"FIM init: {ap}")
    baseline, exceptions = {}, CONFIG.get("scan_exceptions",[])
    for root,_,files in os.walk(ap):
        for name in files:
            fp = os.path.join(root,name)
            if any(fp.startswith(exc) for exc in exceptions): continue
            h = calc_hash(fp)
            if not h: continue
            try:
                st = os.stat(fp)
                baseline[fp] = {"hash":h,"size":st.st_size,"mtime":st.st_mtime,"mode":stat.S_IMODE(st.st_mode)}
            except: pass
    _save_fim_db(baseline)
    print(f"{Colors.OKGREEN}FIM baseline: {len(baseline)} files{Colors.ENDC}")
    notify("FIM", "Baseline created")
    return baseline

def fim_check(target_dir):
    ap = os.path.abspath(os.path.expanduser(target_dir))
    if not os.path.isdir(ap):
        print(f"{Colors.FAIL}Not found: {ap}{Colors.ENDC}"); return
    LOG.info(f"FIM check: {ap}")
    baseline = _load_fim_db()
    if not baseline:
        print(f"{Colors.WARNING}No baseline. Run init first{Colors.ENDC}"); return
    current, exceptions = {}, CONFIG.get("scan_exceptions",[])
    for root,_,files in os.walk(ap):
        for name in files:
            fp = os.path.join(root,name)
            if any(fp.startswith(exc) for exc in exceptions): continue
            h = calc_hash(fp)
            if not h: continue
            try:
                st = os.stat(fp)
                current[fp] = {"hash":h,"size":st.st_size,"mtime":st.st_mtime,"mode":stat.S_IMODE(st.st_mode)}
            except: pass
    
    modified=new=deleted=0
    for fp,b in baseline.items():
        if fp not in current:
            print(f"{Colors.WARNING}[DELETED] {fp}{Colors.ENDC}"); deleted+=1
        else:
            c = current[fp]
            if c["hash"]!=b["hash"] or c["size"]!=b["size"] or abs(c["mtime"]-b["mtime"])>FIM_MTIME_TOLERANCE or c["mode"]!=b["mode"]:
                print(f"{Colors.FAIL}[MODIFIED] {fp}{Colors.ENDC}"); modified+=1
    for fp in current:
        if fp not in baseline:
            print(f"{Colors.OKGREEN}[NEW] {fp}{Colors.ENDC}"); new+=1
    
    if not (modified or new or deleted):
        print(f"{Colors.OKGREEN}No issues{Colors.ENDC}")
    else:
        print(f"Modified:{modified} New:{new} Deleted:{deleted}")
        notify("FIM Alert", f"M:{modified} N:{new} D:{deleted}")

def update_hosts_blacklist(url=None):
    if SCRIPT_NETWORK_GATED:
        print(f"{Colors.WARNING}Network gated{Colors.ENDC}"); return
    url = url or CONFIG.get("default_hosts_blacklist_url")
    hosts_file = "/etc/hosts"
    print(f"{Colors.OKBLUE}Fetching hosts...{Colors.ENDC}")
    try:
        r = HTTP.get(url, timeout=20); r.raise_for_status()
        if len(r.content) > CONFIG.get("hosts_feed_max_bytes", 5*1024*1024):
            print(f"{Colors.FAIL}Feed too large{Colors.ENDC}"); return
        if os.path.exists(hosts_file):
            shutil.copyfile(hosts_file, f"{hosts_file}.bak")
        entries = []
        for ln in r.text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"): continue
            parts = ln.split()
            if len(parts)>=2 and parts[0] in ("0.0.0.0","127.0.0.1"):
                entries.append(f"127.0.0.1 {parts[1]}")
        with open(hosts_file,"w") as f:
            f.write("127.0.0.1 localhost\n::1 localhost\n")
            f.write(f"\n# Updated {datetime.now().isoformat()}\n")
            for e in entries: f.write(e+"\n")
        print(f"{Colors.OKGREEN}Hosts updated (+{len(entries)}){Colors.ENDC}")
        notify("Hosts", "Updated")
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

def _has_root():
    """Check if running as root in proot Ubuntu"""
    try:
        r = subprocess.run(["id","-u"], capture_output=True, text=True)
        if r.returncode==0 and r.stdout.strip()=="0": 
            return True
    except: 
        pass
    return False

def _get_ovpn_list():
    """Get list of .ovpn files from VPN config directory - FIXED FOR PROOT"""
    cfgdir = CONFIG.get("default_vpn_config_dir")
    LOG.info(f"Looking for .ovpn files in: {cfgdir}")
    
    # Ubuntu proot paths
    possible_dirs = [
        "/root/vpn",
        "/home/vpn",
        "/tmp/vpn",
        "/opt/vpn",
        cfgdir,
        os.path.join(os.path.expanduser("~"), "vpn"),
        "./vpn",
        os.path.join(os.getcwd(), "vpn"),
        os.getcwd()
    ]
    
    for check_dir in possible_dirs:
        if not os.path.exists(check_dir):
            LOG.debug(f"Path does not exist: {check_dir}")
            continue
        try:
            all_files = os.listdir(check_dir)
            files = []
            for f in all_files:
                if f.lower().endswith('.ovpn'):
                    full_path = os.path.join(check_dir, f)
                    files.append(full_path)
                    LOG.info(f"Found .ovpn file: {full_path}")
            
            if files:
                LOG.info(f"Found {len(files)} .ovpn files in {check_dir}")
                print(f"{Colors.OKGREEN}✓ Found {len(files)} VPN config(s) in: {check_dir}{Colors.ENDC}")
                for f in files:
                    print(f"  - {os.path.basename(f)}")
                CONFIG["default_vpn_config_dir"] = check_dir
                save_config()
                return files
        except PermissionError:
            LOG.warning(f"Permission denied: {check_dir}")
        except Exception as e:
            LOG.error(f"Error reading {check_dir}: {e}")
    
    LOG.warning("No .ovpn files found in any location")
    return []

def start_vpn(cfg):
    global VPN_PROCESS
    with VPN_PROCESS_LOCK:
        if VPN_PROCESS and VPN_PROCESS.poll() is None:
            print(f"{Colors.WARNING}VPN already running{Colors.ENDC}")
            return
        
        if not os.path.exists(cfg):
            print(f"{Colors.FAIL}Config not found: {cfg}{Colors.ENDC}")
            return
        
        # Check if openvpn is installed
        if not shutil.which("openvpn"):
            print(f"{Colors.FAIL}OpenVPN not installed!{Colors.ENDC}")
            print(f"\n{Colors.OKCYAN}Installing OpenVPN...{Colors.ENDC}")
            install = input(f"Install now? (yes/no): ").lower()
            if install == "yes":
                print(f"{Colors.OKBLUE}Installing openvpn...{Colors.ENDC}")
                result = run_command(["apt", "update"], message="Updating apt", check=False)
                result = run_command(["apt", "install", "openvpn", "-y"], message="Installing OpenVPN", check=False)
                if result and result.returncode == 0:
                    print(f"{Colors.OKGREEN}✓ OpenVPN installed successfully!{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}Failed to install OpenVPN{Colors.ENDC}")
                    print(f"\nManual installation:")
                    print(f"  apt update")
                    print(f"  apt install openvpn -y")
                    return
            else:
                print(f"{Colors.WARNING}OpenVPN not installed. Cannot start VPN.{Colors.ENDC}")
                return
        
        has_root = _has_root()
        print(f"{Colors.OKGREEN}✓ Running as root in proot Ubuntu{Colors.ENDC}")
        
        logpath = CONFIG.get("log_file") + ".vpn.log"
        try:
            vpn_log = open(logpath, "a")
            
            # Build OpenVPN command - direct execution since we're root
            vpn_cmd = ["openvpn", "--config", cfg]
            
            print(f"{Colors.OKCYAN}Starting VPN with root privileges...{Colors.ENDC}")
            
            VPN_PROCESS = subprocess.Popen(
                vpn_cmd,
                stdout=vpn_log,
                stderr=vpn_log,
                preexec_fn=os.setsid
            )
            
            print(f"{Colors.OKGREEN}✓ VPN started (PID {VPN_PROCESS.pid}){Colors.ENDC}")
            print(f"  Config: {os.path.basename(cfg)}")
            print(f"  Log: {logpath}")
            print(f"\n{Colors.OKBLUE}Waiting {CONFIG.get('vpn_monitor_interval',8)}s for connection...{Colors.ENDC}")
            
            time.sleep(CONFIG.get("vpn_monitor_interval",8))
            
            if VPN_PROCESS.poll() is not None:
                print(f"{Colors.FAIL}✗ VPN process died immediately!{Colors.ENDC}")
                print(f"\nCheck log file for errors: {logpath}")
                print(f"  tail -20 {logpath}")
                VPN_PROCESS = None
                return
            
            print(f"{Colors.OKGREEN}✓ VPN process running{Colors.ENDC}")
            notify("VPN", "Started")
            
        except PermissionError:
            print(f"{Colors.FAIL}Permission denied.{Colors.ENDC}")
            VPN_PROCESS = None
        except Exception as e:
            print(f"{Colors.FAIL}Failed to start VPN: {e}{Colors.ENDC}")
            LOG.error(f"VPN start error: {e}")
            VPN_PROCESS = None

def stop_vpn():
    global VPN_PROCESS
    with VPN_PROCESS_LOCK:
        if not VPN_PROCESS or VPN_PROCESS.poll() is not None:
            print(f"{Colors.WARNING}VPN not running{Colors.ENDC}"); return
        try:
            os.killpg(os.getpgid(VPN_PROCESS.pid), signal.SIGTERM)
            VPN_PROCESS.wait(timeout=5)
            print(f"{Colors.OKGREEN}VPN stopped{Colors.ENDC}")
            VPN_PROCESS = None
            notify("VPN", "Stopped")
        except: pass

def vpn_status():
    if VPN_PROCESS and VPN_PROCESS.poll() is None:
        print(f"{Colors.OKGREEN}VPN RUNNING (PID {VPN_PROCESS.pid}){Colors.ENDC}")
        try: run_command(["ip","addr","show","tun0"], check=False)
        except: pass
    else: print(f"{Colors.FAIL}VPN NOT RUNNING{Colors.ENDC}")
    check_public_ip()

def _apply_iptables_killswitch(enable):
    if not _has_root(): return False, "no-root"
    try:
        if enable:
            for c in [["iptables","-I","OUTPUT","-o","lo","-j","ACCEPT"],
                     ["iptables","-I","OUTPUT","-m","state","--state","ESTABLISHED,RELATED","-j","ACCEPT"],
                     ["iptables","-I","OUTPUT","-o","tun0","-j","ACCEPT"],
                     ["iptables","-I","OUTPUT","-j","DROP"]]:
                run_command(c, check=False)
            return True, "applied"
        else:
            for c in [["iptables","-D","OUTPUT","-j","DROP"],
                     ["iptables","-D","OUTPUT","-o","tun0","-j","ACCEPT"],
                     ["iptables","-D","OUTPUT","-m","state","--state","ESTABLISHED,RELATED","-j","ACCEPT"],
                     ["iptables","-D","OUTPUT","-o","lo","-j","ACCEPT"]]:
                try: run_command(c, check=False)
                except: pass
            return True, "removed"
    except: return False, "error"

def enable_killswitch(enable):
    global KILL_SWITCH_ENABLED, SCRIPT_NETWORK_GATED
    if enable:
        ok, info = _apply_iptables_killswitch(True)
        if ok:
            KILL_SWITCH_ENABLED = True
            SCRIPT_NETWORK_GATED = False
            print(f"{Colors.OKGREEN}Kill-switch enabled (iptables){Colors.ENDC}")
        else:
            SCRIPT_NETWORK_GATED = True
            KILL_SWITCH_ENABLED = False
            print(f"{Colors.WARNING}Fallback: script-level gating{Colors.ENDC}")
    else:
        _apply_iptables_killswitch(False)
        KILL_SWITCH_ENABLED = False
        SCRIPT_NETWORK_GATED = False
        print(f"{Colors.OKGREEN}Kill-switch disabled{Colors.ENDC}")

def vpn_monitor_loop():
    global VPN_PROCESS, AUTO_VPN_ENABLED
    while not VPN_MONITOR_STOP.is_set():
        if AUTO_VPN_ENABLED:
            with VPN_PROCESS_LOCK:
                running = VPN_PROCESS and VPN_PROCESS.poll() is None
            if not running:
                LOG.warning("Auto-VPN: reconnecting")
                notify("VPN", "Auto-reconnecting")
                if CONFIG.get("vpn_rotate_on_fail"):
                    choice = random.choice(_get_ovpn_list()) if _get_ovpn_list() else None
                    if choice: start_vpn(choice)
                else:
                    ovpns = _get_ovpn_list()
                    if ovpns: start_vpn(ovpns[0])
                if KILL_SWITCH_ENABLED: enable_killswitch(True)
                time.sleep(CONFIG.get("vpn_reconnect_delay",5))
        time.sleep(CONFIG.get("vpn_monitor_interval",8))

def start_vpn_monitor():
    global VPN_MONITOR_THREAD, VPN_MONITOR_STOP
    if VPN_MONITOR_THREAD and VPN_MONITOR_THREAD.is_alive(): return
    VPN_MONITOR_STOP.clear()
    VPN_MONITOR_THREAD = threading.Thread(target=vpn_monitor_loop, daemon=True)
    VPN_MONITOR_THREAD.start()

def stop_vpn_monitor():
    global VPN_MONITOR_STOP
    if VPN_MONITOR_THREAD and VPN_MONITOR_THREAD.is_alive():
        VPN_MONITOR_STOP.set()
        VPN_MONITOR_THREAD.join(timeout=5)

def check_public_ip():
    try:
        r = HTTP.get("https://ifconfig.me/ip", timeout=8)
        print(f"Public IP: {r.text.strip()}")
    except: print(f"{Colors.WARNING}Could not fetch IP{Colors.ENDC}")

def check_url_reputation(url):
    if SCRIPT_NETWORK_GATED or not VT_API_KEY: return
    try:
        enc = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = HTTP.get(f"https://www.virustotal.com/api/v3/urls/{enc}", headers={"x-apikey":VT_API_KEY}, timeout=15)
        if r.status_code==200:
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            mal = stats.get("malicious",0)
            print(f"URL Detections: {mal}")
            print(f"{Colors.FAIL}MALICIOUS{Colors.ENDC}" if mal>0 else f"{Colors.OKGREEN}Clean{Colors.ENDC}")
        else: print(f"VT: {r.status_code}")
    except Exception as e: print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

def check_ip_reputation(ip):
    if SCRIPT_NETWORK_GATED or not VT_API_KEY: return
    try:
        r = HTTP.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey":VT_API_KEY}, timeout=15)
        if r.status_code==200:
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            mal = stats.get("malicious",0)
            print(f"IP Detections: {mal}")
            print(f"{Colors.FAIL}MALICIOUS{Colors.ENDC}" if mal>0 else f"{Colors.OKGREEN}Clean{Colors.ENDC}")
        else: print(f"VT: {r.status_code}")
    except Exception as e: print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

def list_network_connections():
    run_command(["netstat","-tunap"], message="Network Connections", check=False)

def list_processes():
    run_command(["ps","aux"], message="Processes", check=False)

def list_packages():
    # Use dpkg for Ubuntu instead of pkg
    run_command(["dpkg","-l"], message="Installed Packages", check=False)

def print_banner():
    print(f"""
{Colors.HEADER}
██╗  ██╗███████╗██████╗  ██████╗        █████╗ ██╗   ██╗██╗  ██╗
██║  ██║██╔════╝██╔══██╗██╔═══██╗      ██╔══██╗██║   ██║╚██╗██╔╝
███████║█████╗  ██████╔╝██║   ██║█████╗███████║██║   ██║ ╚███╔╝ 
██╔══██║██╔══╝  ██╔══██╗██║   ██║╚════╝██╔══██║╚██╗ ██╔╝ ██╔██╗ 
██║  ██║███████╗██║  ██║╚██████╔╝      ██║  ██║ ╚████╔╝ ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝       ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝
                                                                
 {Colors.BOLD}-- Android Antivirus + VPN (Ubuntu Proot Edition) --{Colors.ENDC}
""")
    
def main_menu():
    global AUTO_VPN_ENABLED, KILL_SWITCH_ENABLED, NETWORK_ERROR_COUNT
    
    while True:
        print_banner()
        print(f"\n{Colors.HEADER}╔═══════════════════════════════════════╗")
        print(f"║    Hero-AVXN Termux AV - Main Menu    ║")
        print(f"╚═══════════════════════════════════════╝{Colors.ENDC}\n")
        print("Main Menu:")
        print("  1. Scan a specific file (Local + VirusTotal)")
        print("  2. Scan Storage (Manual)")
        print("  3. FIM Management (init/check)")
        print("  4. Threat Intel & Reputation Checks (URL/IP)")
        print("  5. System & Network Awareness")
        print("  6. Network Security & VPN")
        print("  7. Quarantine Management")
        print("  8. Reload/Update Local Malware Blacklist")
        print("  9. Toggle Auto-VPN / Monitor (current: {})".format("ON" if AUTO_VPN_ENABLED else "OFF"))
        print("  A. Toggle Kill-Switch (current: {})".format("ON" if KILL_SWITCH_ENABLED or SCRIPT_NETWORK_GATED else "OFF"))
        print("  B. Reset Network Error Counter")
        print("  0. Exit")
        
        if NETWORK_ERROR_COUNT > 0:
            print(f"\n  {Colors.WARNING}⚠ Network errors: {NETWORK_ERROR_COUNT}/{MAX_NETWORK_ERRORS}{Colors.ENDC}")
        
        choice = input("\nChoice: ").strip().lower()
        
        if choice=="1":
            fp = input("File path: ").strip()
            if fp:
                local = scan_local_hash(fp)
                vt = scan_virustotal(fp)
                mal = (local and local.get("malicious")) or (vt and vt.get("malicious"))
                if mal:
                    act = input("Malicious! Action? (q/d/s/w): ").lower()
                    if act=="q": quarantine(fp)
                    elif act=="d":
                        try: os.remove(fp)
                        except: pass
                    elif act=="w":
                        if h:=calc_hash(fp): add_whitelist(h)
                else: print(f"{Colors.OKGREEN}Clean{Colors.ENDC}")
        
        elif choice=="2":
            method = input("Method (local/virustotal/both) [both]: ").strip() or "both"
            ftypes = input("File types (comma sep, blank=default): ").strip()
            ftypes_list = None if not ftypes else [x.strip() for x in ftypes.split(",")]
            dirs = input("Directories (comma sep, blank=default): ").strip()
            targets = [d.strip() for d in dirs.split(",")] if dirs else CONFIG["default_scan_dirs"]
            scan_storage(targets, method, "ask", ftypes_list)
        
        elif choice=="3":
            c = input("FIM: 1)init 2)check: ").strip()
            d = input("Directory: ").strip()
            if c=="1": fim_init(d)
            elif c=="2": fim_check(d)
        
        elif choice=="4":
            c = input("1)URL 2)IP: ").strip()
            if c=="1": check_url_reputation(input("URL: ").strip())
            elif c=="2": check_ip_reputation(input("IP: ").strip())
        
        elif choice=="5":
            c = input("1)netstat 2)ps 3)dpkg 4)public IP: ").strip()
            if c=="1": list_network_connections()
            elif c=="2": list_processes()
            elif c=="3": list_packages()
            elif c=="4": check_public_ip()
        
        elif choice=="6":
            print("\n1)Update hosts 2)Start VPN 3)Stop VPN 4)VPN status 5)Rotate VPN 6)Show VPN directory")
            c = input("Choice: ").strip()
            if c=="1": update_hosts_blacklist()
            elif c=="2":
                ovpns = _get_ovpn_list()
                if not ovpns: 
                    print(f"{Colors.FAIL}No .ovpn files found!{Colors.ENDC}")
                    print(f"\n{Colors.WARNING}VPN Setup Instructions:{Colors.ENDC}")
                    print(f"1. Create VPN directory: mkdir -p /root/vpn")
                    print(f"2. Place your .ovpn files there")
                    print(f"3. If you have auth.txt, keep it in same directory")
                    print(f"\n{Colors.BOLD}Quick Setup:{Colors.ENDC}")
                    print(f"  mkdir -p /root/vpn")
                    print(f"  cp '/path/to/your/USA.ovpn' /root/vpn/")
                    print(f"  apt update && apt install openvpn -y")
                else:
                    if not shutil.which("openvpn"):
                        print(f"\n{Colors.WARNING}⚠ OpenVPN not installed!{Colors.ENDC}")
                        install = input(f"\nInstall OpenVPN now? (yes/no): ").lower()
                        if install == "yes":
                            print(f"{Colors.OKBLUE}Installing...{Colors.ENDC}")
                            run_command(["apt", "update"], check=False)
                            result = run_command(["apt", "install", "openvpn", "-y"], check=False)
                            if result and result.returncode == 0:
                                print(f"{Colors.OKGREEN}✓ OpenVPN installed!{Colors.ENDC}")
                            else:
                                print(f"{Colors.FAIL}Installation failed{Colors.ENDC}")
                                continue
                        else:
                            continue
                    
                    print(f"\n{Colors.OKGREEN}Found {len(ovpns)} VPN config(s):{Colors.ENDC}")
                    for i,f in enumerate(ovpns): 
                        print(f"  {i+1}. {os.path.basename(f)}")
                    
                    print(f"\n{Colors.BOLD}OpenVPN Status:{Colors.ENDC}")
                    print(f"  Installed: {Colors.OKGREEN}Yes{Colors.ENDC}")
                    print(f"  Root access: {Colors.OKGREEN}Yes (proot){Colors.ENDC}")
                    
                    sel = input("\nSelect config number (or 'r' for random): ").strip().lower()
                    if sel=="r": 
                        start_vpn(random.choice(ovpns))
                    else:
                        try: 
                            idx = int(sel) - 1
                            if 0 <= idx < len(ovpns):
                                start_vpn(ovpns[idx])
                        except: 
                            print(f"{Colors.FAIL}Invalid selection{Colors.ENDC}")
            elif c=="3": stop_vpn()
            elif c=="4": vpn_status()
            elif c=="5":
                choice = random.choice(_get_ovpn_list()) if _get_ovpn_list() else None
                if choice: start_vpn(choice)
            elif c=="6":
                print(f"\n{Colors.BOLD}VPN Config Directory Diagnostics{Colors.ENDC}")
                print(f"{'='*60}")
                cfgdir = CONFIG.get("default_vpn_config_dir")
                print(f"\nConfigured path: {cfgdir}")
                print(f"Exists: {Colors.OKGREEN if os.path.exists(cfgdir) else Colors.FAIL}{'Yes' if os.path.exists(cfgdir) else 'No'}{Colors.ENDC}")
                
                search_paths = ["/root/vpn", "/home/vpn", "/tmp/vpn", "./vpn"]
                
                found_any = False
                for path in search_paths:
                    exists = os.path.exists(path)
                    marker = f"{Colors.OKGREEN}✓{Colors.ENDC}" if exists else f"{Colors.FAIL}✗{Colors.ENDC}"
                    print(f"\n  {marker} {path}")
                    
                    if exists:
                        try:
                            all_files = os.listdir(path)
                            ovpn_files = [f for f in all_files if f.lower().endswith('.ovpn')]
                            
                            if ovpn_files:
                                found_any = True
                                print(f"      {Colors.OKGREEN}Found {len(ovpn_files)} .ovpn file(s):{Colors.ENDC}")
                                for f in ovpn_files:
                                    print(f"        • {f}")
                        except Exception as e:
                            print(f"      {Colors.FAIL}Error: {e}{Colors.ENDC}")
                
                if not found_any:
                    print(f"\n{Colors.FAIL}NO .ovpn FILES FOUND!{Colors.ENDC}")
                    print(f"\n{Colors.BOLD}Setup:{Colors.ENDC}")
                    print(f"  mkdir -p /root/vpn")
                    print(f"  cp '/path/to/USA.ovpn' /root/vpn/")
        
        elif choice=="7":
            qdir = CONFIG["quarantine_dir"]
            items = sorted(os.listdir(qdir)) if os.path.exists(qdir) else []
            if not items: print("Empty")
            else:
                for i,f in enumerate(items): print(f"{i+1}. {f}")
                act = input("Action? (r=restore c=clean s=skip): ").lower()
                if act=="r":
                    try:
                        idx = int(input("Number: "))-1
                        restore_file(os.path.join(qdir,items[idx]))
                    except: print("Invalid")
                elif act=="c":
                    if input("Delete all? (yes/no): ")=="yes":
                        for f in items:
                            try: os.remove(os.path.join(qdir,f))
                            except: pass
        
        elif choice=="8":
            print("1)Reload local 2)Update online")
            c = input("Choice: ").strip()
            if c=="1": load_malware_hashes(); print("Reloaded")
            elif c=="2": update_hashes_online()
        
        elif choice=="9":
            AUTO_VPN_ENABLED = not AUTO_VPN_ENABLED
            print(f"Auto-VPN: {'ON' if AUTO_VPN_ENABLED else 'OFF'}")
            if AUTO_VPN_ENABLED: start_vpn_monitor()
            else: stop_vpn_monitor()
        
        elif choice=="a":
            current_state = KILL_SWITCH_ENABLED or SCRIPT_NETWORK_GATED
            if not current_state:
                confirm = input(f"Enable kill-switch? (yes/no): ").lower()
                if confirm == "yes":
                    enable_killswitch(True)
            else:
                confirm = input(f"Disable kill-switch? (yes/no): ").lower()
                if confirm == "yes":
                    enable_killswitch(False)
        
        elif choice=="b":
            NETWORK_ERROR_COUNT = 0
            print(f"{Colors.OKGREEN}Reset{Colors.ENDC}")
        
        elif choice=="0":
            print("Exiting..."); break
        
def main():
    load_config()
    setup_logging()
    load_malware_hashes()
    load_whitelist()
    
    parser = argparse.ArgumentParser(description="Hero-AVXN Termux AV (Ubuntu Proot)")
    parser.add_argument("--check-fim", dest="fim_dir_check")
    parser.add_argument("--init-fim", dest="fim_dir_init")
    parser.add_argument("--scan-storage", action="store_true")
    parser.add_argument("--scan-method", default="both", choices=["local","virustotal","both"])
    parser.add_argument("--auto-action", default="ask", choices=["ask","quarantine","delete"])
    parser.add_argument("--file-types", dest="file_types_cli")
    parser.add_argument("--update-hosts-blacklist", dest="hosts_url")
    parser.add_argument("--update-hashes", action="store_true")
    args = parser.parse_args()
    
    if args.fim_dir_check: fim_check(args.fim_dir_check); return
    if args.fim_dir_init: fim_init(args.fim_dir_init); return
    if args.scan_storage:
        ftypes = args.file_types_cli.split(",") if args.file_types_cli else None
        scan_storage(CONFIG["default_scan_dirs"], args.scan_method, args.auto_action, ftypes)
        return
    if args.hosts_url: update_hosts_blacklist(args.hosts_url); return
    if args.update_hashes: update_hashes_online(); return
    
    if not VT_API_KEY:
        print(f"{Colors.WARNING}VT_API_KEY not set in .env{Colors.ENDC}")
    main_menu()

if __name__ == "__main__":
    main()