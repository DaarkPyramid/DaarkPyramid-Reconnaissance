#!/usr/bin/env python3
import requests
import os
import importlib
import threading
import socket
import json
import hashlib
import re
from urllib.parse import urlparse
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings("ignore")

init(autoreset=True)

# -----------------------------------------
# Plugin Loader
# -----------------------------------------
def load_plugins():
    plugins = []
    plugin_dir = "plugins/"

    if not os.path.exists(plugin_dir):
        return plugins

    for file in os.listdir(plugin_dir):
        if file.endswith(".py"):
            module_name = file[:-3]
            module_path = f"plugins.{module_name}"
            try:
                module = importlib.import_module(module_path)
                if hasattr(module, "run"):
                    plugins.append(module.run)
            except Exception as e:
                print(Fore.RED + f"[Plugin Error] {file}: {e}")

    return plugins

# -----------------------------------------
# Banner
# -----------------------------------------
def banner():
    print(Fore.CYAN + r""" 
    _______                                 __        _______                                              __        __ 
/       \                               /  |      /       \                                            /  |      /  |
$$$$$$$  |  ______    ______    ______  $$ |   __ $$$$$$$  | __    __   ______   ______   _____  ____  $$/   ____$$ |
$$ |  $$ | /      \  /      \  /      \ $$ |  /  |$$ |__$$ |/  |  /  | /      \ /      \ /     \/    \ /  | /    $$ |
$$ |  $$ | $$$$$$  | $$$$$$  |/$$$$$$  |$$ |_/$$/ $$    $$/ $$ |  $$ |/$$$$$$  |$$$$$$  |$$$$$$ $$$$  |$$ |/$$$$$$$ |
$$ |  $$ | /    $$ | /    $$ |$$ |  $$/ $$   $$<  $$$$$$$/  $$ |  $$ |$$ |  $$/ /    $$ |$$ | $$ | $$ |$$ |$$ |  $$ |
$$ |__$$ |/$$$$$$$ |/$$$$$$$ |$$ |      $$$$$$  \ $$ |      $$ \__$$ |$$ |     /$$$$$$$ |$$ | $$ | $$ |$$ |$$ \__$$ |
$$    $$/ $$    $$ |$$    $$ |$$ |      $$ | $$  |$$ |      $$    $$ |$$ |     $$    $$ |$$ | $$ | $$ |$$ |$$    $$ |
$$$$$$$/   $$$$$$$/  $$$$$$$/ $$/       $$/   $$/ $$/        $$$$$$$ |$$/       $$$$$$$/ $$/  $$/  $$/ $$/  $$$$$$$/ 
                                                            /  \__$$ |                                               
                                                            $$    $$/                                                
                                                             $$$$$$/
       DaarkPyramid Framework – v1
            by Kareem
""")

# -----------------------------------------
# Helper: Extract domain name
# -----------------------------------------
def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc

# -----------------------------------------
# Resolve IP + ASN
# -----------------------------------------
def resolve_ip(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        return None

# -----------------------------------------
# Favicon Hash
# -----------------------------------------
def favicon_hash(url):
    try:
        if not url.endswith("/"):
            url += "/"
        response = requests.get(url + "favicon.ico", timeout=6, verify=False)
        if response.status_code == 200:
            return hashlib.md5(response.content).hexdigest()
    except:
        return None

# -----------------------------------------
# Detect WAF
# -----------------------------------------
def detect_waf(headers, body):
    waf_signatures = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "Akamai": ["akamai"],
        "Sucuri": ["sucuri"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "F5 BigIP": ["bigip", "asm"],
    }

    text = str(headers).lower() + body.lower()

    for waf, sigs in waf_signatures.items():
        for s in sigs:
            if s in text:
                return waf
    return None

# -----------------------------------------
# Detect CMS
# -----------------------------------------
def detect_cms(body):
    cms_fps = {
        "WordPress": ["wp-content", "wp-json", "wp-includes"],
        "Joomla": ["joomla"],
        "Drupal": ["drupal"],
        "Magento": ["mage", "magento"],
        "OpenCart": ["opencart"],
    }

    b = body.lower()
    for cms, sigs in cms_fps.items():
        for s in sigs:
            if s in b:
                return cms

    return None

# -----------------------------------------
# Detect CDN
# -----------------------------------------
def detect_cdn(headers):
    cdn_headers = {
        "Cloudflare": "cloudflare",
        "Akamai": "akamai",
        "Fastly": "fastly",
        "Sucuri": "sucuri",
    }

    h = str(headers).lower()
    for cdn, sig in cdn_headers.items():
        if sig in h:
            return cdn

    return None

# -----------------------------------------
# Detect Technologies
# -----------------------------------------
def detect_stack(headers, body):
    tech = []

    h = str(headers).lower()
    b = body.lower()

    if "php" in h or "php" in b:
        tech.append("PHP")
    if "asp.net" in h:
        tech.append("ASP.NET")
    if "nodejs" in h or "express" in h:
        tech.append("Node.js")
    if "python" in h:
        tech.append("Python")
    if "nginx" in h:
        tech.append("Nginx")
    if "apache" in h:
        tech.append("Apache")

    return tech

# -----------------------------------------
# Extract Title
# -----------------------------------------
def get_title(body):
    try:
        match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    except:
        pass
    return None

# -----------------------------------------
# Redirect Chain
# -----------------------------------------
def check_redirects(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=8, verify=False)
        chain = [resp.url for resp in r.history]
        return chain
    except:
        return []
        
        # -----------------------------------------
# GeoIP + ASN lookup
# -----------------------------------------
def geoip_lookup(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if resp.get("status") == "success":
            return {
                "country": resp.get("country"),
                "region": resp.get("regionName"),
                "city": resp.get("city"),
                "org": resp.get("org"),
                "isp": resp.get("isp"),
                "asn": resp.get("as")
            }
    except:
        pass
    return None

# -----------------------------------------
# TCP Port Scan
# -----------------------------------------
def port_scan(ip, ports=[21,22,25,53,80,443,3306,6379,8080,8443]):
    open_ports = []

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except:
            pass

    threads = []
    for p in ports:
        t = threading.Thread(target=scan_port, args=(p,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return open_ports

# -----------------------------------------
# MAIN FUNCTION
# -----------------------------------------
def scan(url):
    target = extract_domain(url)
    ip = resolve_ip(target)

    print(Fore.YELLOW + f"\n[+] Target: {url}")
    if ip:
        print(Fore.GREEN + f"[+] IP: {ip}")

    # GeoIP Lookup
    geo = geoip_lookup(ip)
    if geo:
        print(Fore.CYAN + "[+] GeoIP / ASN Info:")
        print(f"    Country: {geo.get('country')}")
        print(f"    Region: {geo.get('region')}")
        print(f"    City: {geo.get('city')}")
        print(f"    Org: {geo.get('org')}")
        print(f"    ISP: {geo.get('isp')}")
        print(f"    ASN: {geo.get('asn')}")

    # Port Scan
    open_ports = port_scan(ip)
    if open_ports:
        print(Fore.LIGHTMAGENTA_EX + f"[+] Open Ports: {', '.join(map(str, open_ports))}")
    else:
        print(Fore.LIGHTMAGENTA_EX + "[+] No common ports open")

    redirects = check_redirects(url)
    if redirects:
        print(Fore.CYAN + "[+] Redirect Chain:")
        for r in redirects:
            print("   → " + r)

    try:
        r = requests.get(url, timeout=10, verify=False)
    except Exception as e:
        print(Fore.RED + f"[-] Request failed: {e}")
        return

    print(Fore.YELLOW + f"[+] Status Code: {r.status_code}")

    # Title
    title = get_title(r.text)
    if title:
        print(Fore.LIGHTGREEN_EX + f"[+] Title: {title}")

    # Server & Cookies
    server = r.headers.get("Server")
    if server:
        print(Fore.MAGENTA + f"[+] Server: {server}")

    print(Fore.LIGHTBLUE_EX + "[+] Cookies:")
    cookies = r.cookies.get_dict()
    if cookies:
        for k, v in cookies.items():
            print(f"    {k} = {v}")
    else:
        print("    None")

    # Security headers
    sec_headers = ["X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy"]
    print(Fore.CYAN + "[+] Security Headers:")
    for h in sec_headers:
        val = r.headers.get(h)
        if val:
            print(f"    {h}: {val}")

    # CMS Detection
    cms = detect_cms(r.text)
    if cms:
        print(Fore.GREEN + f"[+] CMS Detected: {cms}")

    # WAF
    waf = detect_waf(r.headers, r.text)
    if waf:
        print(Fore.RED + f"[+] WAF Detected: {waf}")

    # CDN
    cdn = detect_cdn(r.headers)
    if cdn:
        print(Fore.CYAN + f"[+] CDN: {cdn}")

    # Tech Stack
    techs = detect_stack(r.headers, r.text)
    if techs:
        print(Fore.LIGHTBLUE_EX + f"[+] Technologies: {', '.join(techs)}")

    # Assets Discovery (JS / CSS / Images)
    js_files = re.findall(r'<script[^>]+src="([^"]+)"', r.text, re.IGNORECASE)
    css_files = re.findall(r'<link[^>]+href="([^"]+\.css)"', r.text, re.IGNORECASE)
    images = re.findall(r'<img[^>]+src="([^"]+)"', r.text, re.IGNORECASE)

    print(Fore.YELLOW + "[+] JS Files:")
    if js_files:
        for f in js_files:
            print(f"    {f}")
    else:
        print("    None")

    print(Fore.YELLOW + "[+] CSS Files:")
    if css_files:
        for f in css_files:
            print(f"    {f}")
    else:
        print("    None")

    print(Fore.YELLOW + "[+] Images:")
    if images:
        for f in images:
            print(f"    {f}")
    else:
        print("    None")

    # Favicon hash
    fav = favicon_hash(url)
    if fav:
        print(Fore.YELLOW + f"[+] Favicon MD5: {fav}")

    # Plugins
    plugins = load_plugins()
    if plugins:
        print(Fore.BLUE + f"[+] Loaded {len(plugins)} plugins")
        for plugin in plugins:
            try:
                result = plugin(url, r.headers, r.text)
                if result:
                    print(Fore.GREEN + f"[PLUGIN] {result}")
            except Exception as e:
                print(Fore.RED + f"[PLUGIN ERROR] {e}")

# -----------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 webxscanner.py <url>")
        exit()
    banner()
    scan(sys.argv[1])
