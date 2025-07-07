import subprocess
import requests
import re
import random
import ipaddress
import os
from datetime import datetime

# ----------------------------- Configs -----------------------------
SUBDOMAINS = ["www", "mail", "ftp", "test", "api", "admin", "dev"]
RISKY_CIDRS = ["185.100.87.0/24", "45.134.20.0/24", "198.96.155.0/24"]
BAD_COUNTRIES = ["china", "russia", "iran", "north korea"]
BAD_ISP_KEYWORDS = ["tor", "unknown", "proxy", "vpn"]
BAD_ASNS = ["AS9009", "AS14061", "AS202425", "AS62240", "AS29182"]
RISKY_CNAME_PROVIDERS = ["github.io", "herokuapp.com", "amazonaws.com", "cloudfront.net", "fastly.net"]
RECORDS = ["A", "TXT", "AAAA", "MX"]
SELECTORS = ["default", "google", "selector1", "selector2", "m1", "s1024", "s2048", "k1", "zoho"]

# Threat score ranges as explicit checks
LOW_MIN, LOW_MAX = 1, 9
MID_MIN, MID_MAX = 10, 19

# -------------------------- Functions -----------------------------

def log(msg):
    with open(LOGFILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")
    print(msg)

def get_geo_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        return data.get("country", "").lower(), data.get("city", ""), data.get("isp", "").lower()
    except:
        return "unknown", "unknown", "unknown"

def get_asn_info(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        org = r.json().get("org", "")
        asn = org.split()[0] if org else None
        return asn, org
    except:
        return None, None

def check_cidr_threat(ip):
    ip_obj = ipaddress.ip_address(ip)
    for cidr in RISKY_CIDRS:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return False

def run_nmap(ip):
    try:
        log(f"Running NMAP scan on {ip} (may trigger alerts)...")
        result = subprocess.run(
            ["nmap", "-Pn", "-T4", "-sV", "-O", "--script", "vuln", ip],
            capture_output=True, text=True, check=True
        )
        nmap_dir = f"{domain}_nmap"
        os.makedirs(nmap_dir, exist_ok=True)
        with open(f"{nmap_dir}/{ip}.txt", "w") as f:
            f.write(result.stdout)
        log(f"[NMAP SCAN for {ip}] saved to {nmap_dir}/{ip}.txt")
    except Exception as e:
        log(f"NMAP ERROR for {ip}: {e}")

# -------------------------- Main -----------------------------

def main():
    global LOGFILE, domain
    domain = input("DOMAIN: ").strip()
    LOGFILE = f"{domain}_log.txt"
    threat_score = 0

    log(f"\n=== DNS RECORDS (A, TXT, AAAA, MX) CHECK ===\n")
    for ty in RECORDS:
        try:
            result = subprocess.run(["dig", ty, domain, "+short"], capture_output=True, check=True, text=True)
            rev_out = result.stdout.strip()
            if rev_out:
                log(f"{ty} record(s): {rev_out}")
                if ty == "TXT":
                    for line in rev_out.splitlines():
                        if "v=spf1" in line.lower():
                            if "~all" in line:
                                log("SPF uses softfail (~all)")
                            elif "-all" in line:
                                log("SPF uses hardfail (-all)")
                            elif "+all" in line:
                                threat_score += 5
                                log("SPF allows all (+all) — RISK")
                            else:
                                log("SPF has no explicit fail mechanism — RISK")
                                threat_score += 3
                        if "v=dmarc1" in line.lower():
                            if "p=none" in line.lower():
                                threat_score += 3
                                log("DMARC policy is NONE — Weak")
                            elif "p=reject" in line.lower() or "p=quarantine" in line.lower():
                                log("DMARC policy is set strictly — Good")
        except Exception:
            log(f"Error fetching {ty} record")

    log("\n=== DKIM CHECK ===")
    for s in SELECTORS:
        sel = f"{s}._domainkey.{domain}"
        try:
            dkim = subprocess.run(["dig", "TXT", sel, "+short"], capture_output=True, check=True, text=True)
            out = dkim.stdout.strip().replace('"', '').replace(' ', '')
            if out:
                log(f"{s} DKIM → {out}")
                match = re.search(r"p=([A-Za-z0-9+/=]+)", out)
                if match:
                    pub = match.group(1)
                    if len(pub) < 1024:
                        threat_score += 5
                        log("DKIM key too short (<1024) — RISK")
        except Exception:
            pass

    log("\n=== SUBDOMAIN ENUMERATION ===")
    for sub in SUBDOMAINS:
        target = f"{sub}.{domain}"
        try:
            result = subprocess.run(["dig", "+short", target], capture_output=True, check=True, text=True)
            output = result.stdout.strip()
            if output:
                match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
                if match:
                    ip = match.group()
                    country, city, isp = get_geo_info(ip)
                    asn, org = get_asn_info(ip)
                    cidr_flag = check_cidr_threat(ip)

                    log(f"{target} → {ip}")
                    log(f"  ➤ GEO: {country}, {city}, {isp}")
                    log(f"  ➤ ASN: {asn} ({org})")
                    log(f"  ➤ CIDR RISK: {'YES' if cidr_flag else 'NO'}")

                    if country in BAD_COUNTRIES:
                        threat_score += 5
                        log("Country flagged as suspicious")
                    if any(bad in isp for bad in BAD_ISP_KEYWORDS):
                        threat_score += 5
                        log("ISP flagged")
                    if cidr_flag:
                        threat_score += 5
                        log("CIDR matched blacklist")
                    if asn in BAD_ASNS:
                        threat_score += 5
                        log("ASN flagged")

                    run_nmap(ip)
                    threat_score += 1
        except Exception as e:
            log(f"ERROR with {target}: {e}")

    log("\n=== CNAME CHECK ===")
    try:
        cname = subprocess.run(["dig", "CNAME", domain, "+short"], capture_output=True, check=True, text=True)
        cname_out = cname.stdout.strip()
        if cname_out:
            log(f"CNAME: {cname_out}")
            if any(provider in cname_out for provider in RISKY_CNAME_PROVIDERS):
                threat_score += 3
                log("CNAME points to risky third-party provider")
        else:
            log("No CNAME record.")
    except Exception:
        log("CNAME check failed.")

    log("\n=== WILDCARD DNS CHECK ===")
    wildcard = f"{random.randint(1000,9999)}.{domain}"
    try:
        wild = subprocess.run(["dig", "+short", wildcard], capture_output=True, check=True, text=True)
        if wild.stdout.strip():
            threat_score += 5
            log(f"Wildcard DNS detected: {wildcard} resolves to {wild.stdout.strip()}")
        else:
            log("No wildcard DNS.")
    except Exception:
        log("Wildcard DNS check failed.")

    log("\n=== FINAL THREAT SCORE ===")
    if LOW_MIN <= threat_score <= LOW_MAX:
        log(f"LOW THREAT ({threat_score} points)")
    elif MID_MIN <= threat_score <= MID_MAX:
        log(f"MID THREAT ({threat_score} points)")
    else:
        log(f"HIGH THREAT ({threat_score} points)")

# -------------------------- Entry Point -----------------------------

if __name__ == "__main__":
    main()
