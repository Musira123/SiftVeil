#!/usr/bin/env python3
"""
SiftVeil - automatic email phishing / social-engineering scanner

What it does
  1. Reads emails from .eml files or live from an IMAP mailbox (auto-scan loop)
  2. Detects phishing / social-engineering patterns in headers, body, attachments
  3. Extracts every link and checks it with:
       - VirusTotal        (URL reputation)
       - urlscan.io        (live scan + verdict + screenshot)
       - Joe Sandbox       (sandbox submission)
       - WannaBrowser-style fetch (custom User-Agent, no JS, redirect chain,
                                   login-form / obfuscation analysis)
  4. Checks sender domain legitimacy: SPF/DKIM/DMARC results, DNS records,
     RDAP domain age, VirusTotal domain reputation, lookalike-brand detection

Install:  pip install requests beautifulsoup4 dnspython

API keys (all optional, each is free to get). SiftVeil looks for them in:
  1. environment variables  VT_API_KEY, URLSCAN_API_KEY, JOE_API_KEY
  2. a file  ~/.siftveil.env   (or .env next to this script), one per line:
         VT_API_KEY=your_key
         URLSCAN_API_KEY=your_key
  3. command-line flags  --vt-key  --urlscan-key  --joe-key
IMAP (env vars): IMAP_HOST, IMAP_USER, IMAP_PASS

Usage:
  python siftveil.py keys                       # test that your API keys work
  python siftveil.py scan suspicious.eml
  python siftveil.py scan *.eml --json report.json
  python siftveil.py scan mail.eml --simple     # plain-English report
  python siftveil.py watch --interval 120 --quarantine Phishing

WARNING: --fetch contacts the suspicious site directly from YOUR IP.
Run inside a VM / behind a VPN, or use --no-fetch.
"""
import argparse
import base64
import difflib
import email
import imaplib
import json
import os
import re
import sys
import time
from email import policy
from email.utils import parseaddr
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver
except ImportError:
    dns = None

VT_KEY = os.getenv("VT_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
JOE_KEY = os.getenv("JOE_API_KEY")
JOE_URL = os.getenv("JOE_API_URL", "https://jbxcloud.joesecurity.org/api")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
TIMEOUT = 20


KEY_SOURCE = {}


def load_keys():
    """Find API keys in: environment variables, ~/.siftveil.env, or a .env next to the script."""
    global VT_KEY, URLSCAN_KEY, JOE_KEY
    names = ("VT_API_KEY", "URLSCAN_API_KEY", "JOE_API_KEY")
    for n in names:
        if os.getenv(n):
            KEY_SOURCE[n] = "environment variable"
    here = os.path.dirname(os.path.abspath(__file__))
    for fp in (os.path.expanduser("~/.siftveil.env"), os.path.join(here, ".env"), ".env"):
        try:
            with open(fp) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    if k.startswith("export "):
                        k = k[7:].strip()
                    v = v.strip().strip('"').strip("'")
                    if k in names and v and not os.getenv(k):
                        os.environ[k] = v
                        KEY_SOURCE[k] = fp
        except OSError:
            pass

    def clean(name):
        return (os.getenv(name) or "").strip().strip('"').strip("'") or None

    VT_KEY, URLSCAN_KEY, JOE_KEY = clean("VT_API_KEY"), clean("URLSCAN_API_KEY"), clean("JOE_API_KEY")


load_keys()

# Hardcoded keys - override anything found above. Keep these private!
VT_KEY = None #put your api key here
URLSCAN_KEY = None #your api key
JOE_KEY = None



# ------------------------------------------------------------------ look & feel
if os.name == "nt":
    os.system("")  # enables ANSI colours in Windows terminals
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")
PURPLE = "\033[38;2;150;60;255m"
PINK = "\033[1;38;2;255;105;180m"
WHITE = "\033[1;97m"
DIM = "\033[2;37m"
RESET = "\033[0m"


def c(text, color):
    return f"{color}{text}{RESET}" if USE_COLOR else str(text)


BANNER = r"""
███████╗██╗███████╗████████╗██╗   ██╗███████╗██╗██╗     
██╔════╝██║██╔════╝╚══██╔══╝██║   ██║██╔════╝██║██║     
███████╗██║█████╗     ██║   ██║   ██║█████╗  ██║██║     
╚════██║██║██╔══╝     ██║   ╚██╗ ██╔╝██╔══╝  ██║██║     
███████║██║██║        ██║    ╚████╔╝ ███████╗██║███████╗
╚══════╝╚═╝╚═╝        ╚═╝     ╚═══╝  ╚══════╝╚═╝╚══════╝"""


def show_banner():
    print(c(BANNER, PURPLE))
    print(c("   lift the veil off suspicious email  |  phishing • social engineering • bad links\n", DIM))


def show_key_status(offline=False):
    if offline:
        print(c("  Mode: offline (no online services will be used)\n", DIM))
        return
    def part(name, key, optional=False):
        if key:
            return c(f"{name} ✔", GREEN)
        return c(f"{name} ✘ no key" + (" (optional)" if optional else ""), RED if not optional else DIM)
    print("  " + c("Online scanners:", PINK) + " " + " | ".join(
        [part("VirusTotal", VT_KEY), part("urlscan.io", URLSCAN_KEY), part("Joe Sandbox", JOE_KEY, True)]) + "\n")


def heading(text):
    print("\n" + c(f"▌ {text}", PINK))


def kv(key, val):
    print(f"  {c(key + ':', PINK)} {c(val, WHITE)}")


# ------------------------------------------------------------------ patterns
URGENCY = ["urgent", "immediately", "within 24 hours", "act now", "final notice",
           "last warning", "account will be suspended", "account suspended",
           "verify your account", "unusual activity", "suspicious activity",
           "limited time", "expires today", "action required", "security alert",
           "unusual activit", "has been blocked", "been blocked", "account blocked",
           "has been locked", "temporarily limited", "unauthorized", "restricted", "will be closed"]
CREDENTIALS = ["password", "login", "log in", "sign in", "verify your identity",
               "confirm your", "update your payment", "credit card", "ssn",
               "social security", "one-time code", "otp", "2fa code", "bank details"]
SOCIAL_ENG = ["gift card", "wire transfer", "bitcoin", "crypto", "invoice attached",
              "ceo", "kindly", "do not tell", "confidential", "keep this between us",
              "i am travelling", "are you available", "need a favor", "lottery",
              "you have won", "inheritance", "refund", "payment overdue"]
BAD_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".iso",
           ".img", ".lnk", ".hta", ".docm", ".xlsm", ".html", ".htm", ".one", ".zip", ".rar")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
              "rb.gy", "shorturl.at", "buff.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml",
                   "cf", "ga", "work", "support", "rest", "icu", "cam", "live"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
             "protonmail.com", "aol.com", "mail.com", "gmx.com"}
BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "google", "netflix",
          "facebook", "instagram", "linkedin", "dhl", "fedex", "ups", "binance",
          "coinbase", "chase", "wellsfargo", "bankofamerica", "hsbc", "docusign",
          "dropbox", "adobe", "whatsapp", "telegram", "meezan", "hbl", "jazzcash",
          "easypaisa", "nadra"]


def defang(u):
    return u.replace("http", "hxxp").replace(".", "[.]")


def reg_domain(host):
    if re.fullmatch(r"[\d.]+", host or ""):
        return host  # raw IP address
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ------------------------------------------------------------------ parsing
def parse_email(raw):
    msg = email.message_from_bytes(raw, policy=policy.default)
    html = plain = ""
    for part in msg.walk():
        ctype = part.get_content_type()
        try:
            if ctype == "text/html" and not part.get_filename():
                html += part.get_content()
            elif ctype == "text/plain" and not part.get_filename():
                plain += part.get_content()
        except Exception:
            pass
    links = []  # (href, visible_text)
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            links.append((a["href"].strip(), a.get_text(" ", strip=True)))
        text = soup.get_text(" ", strip=True)
    else:
        text = plain
    for u in re.findall(r"https?://[^\s<>\"')\]]+", plain):
        if u not in [l[0] for l in links]:
            links.append((u, ""))
    links = [(h, t) for h, t in links if h.lower().startswith(("http://", "https://"))]
    atts = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    return {
        "msg": msg,
        "subject": str(msg.get("Subject", "")),
        "from": parseaddr(str(msg.get("From", ""))),
        "reply_to": parseaddr(str(msg.get("Reply-To", ""))),
        "return_path": parseaddr(str(msg.get("Return-Path", ""))),
        "auth_count": len(msg.get_all("Authentication-Results", []) or []),
        "auth_results": " ".join(msg.get_all("Authentication-Results", []) or []).lower(),
        "text": text,
        "links": links,
        "attachments": atts,
    }


# ------------------------------------------------------------------ content heuristics
def analyze_content(p):
    findings = []
    blob = (p["subject"] + " " + p["text"]).lower()

    def hits(words):
        return [w for w in words if w in blob]

    h = hits(URGENCY)
    if h:
        findings.append((min(10 + 3 * len(h), 25), f"Urgency/pressure language: {', '.join(h[:5])}"))
    h = hits(CREDENTIALS)
    if h:
        weak = len(h) == 1 and h[0] in ("login", "log in", "sign in", "confirm your")
        findings.append((4 if weak else min(10 + 3 * len(h), 25), f"Credential/financial request: {', '.join(h[:5])}"))
    h = hits(SOCIAL_ENG)
    if h:
        findings.append((min(8 + 3 * len(h), 20), f"Social-engineering cues: {', '.join(h[:5])}"))
    for name in p["attachments"]:
        if name.lower().endswith(BAD_EXT):
            findings.append((25, f"Risky attachment type: {name}"))
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat|lnk)$", name.lower()):
            findings.append((30, f"Double-extension attachment: {name}"))
    if len(p["text"]) < 200 and p["links"]:
        findings.append((8, "Very short body that mostly pushes a link"))
    return findings


# ------------------------------------------------------------------ sender / domain checks
def dns_txt(name):
    if not dns:
        return []
    try:
        return [b"".join(r.strings).decode() for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
    except Exception:
        return []


def dns_has(name, rtype):
    if not dns:
        return None
    try:
        dns.resolver.resolve(name, rtype, lifetime=5)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        return None  # DNS problem on this machine: don't blame the sender


_dns_works = None


def dns_working():
    """True only if this machine's DNS can resolve a well-known domain (avoids blaming senders for our own DNS problems)."""
    global _dns_works
    if _dns_works is None:
        _dns_works = bool(dns) and dns_has("example.com", "A") is True
    return _dns_works


def rdap_age_days(domain):
    from datetime import datetime, timezone
    urls = [f"https://rdap.org/domain/{domain}"]
    tld = domain.rsplit(".", 1)[-1]
    if tld in ("com", "net"):
        urls.append(f"https://rdap.verisign.com/{tld}/v1/domain/{domain}")
    for u in urls:
        try:
            r = requests.get(u, timeout=TIMEOUT, headers={"User-Agent": UA})
            if r.ok:
                for ev in r.json().get("events", []):
                    if ev.get("eventAction") == "registration":
                        d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                        return (datetime.now(timezone.utc) - d).days
        except Exception:
            continue
    return None


def vt_domain(domain):
    if not VT_KEY:
        return None
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                         headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
        if r.ok:
            a = r.json()["data"]["attributes"]
            return {"stats": a.get("last_analysis_stats"), "reputation": a.get("reputation"),
                    "registrar": a.get("registrar")}
    except Exception:
        pass
    return None


def lookalike(domain):
    label = reg_domain(domain).split(".")[0].replace("-", "").replace("0", "o").replace("1", "l")
    for b in BRANDS:
        if label == b:
            return None  # exact brand label; legitimacy decided by other checks
        if b in label:
            return f"contains brand '{b}' but is not the brand's own domain"
        if difflib.SequenceMatcher(None, label, b).ratio() >= 0.85:
            return f"looks like '{b}' (typosquat)"
    return None


def analyze_sender(p):
    findings, info = [], {}
    name, addr = p["from"]
    domain = addr.split("@")[-1].lower() if "@" in addr else ""
    info["from"] = addr
    if not domain:
        return [(15, "Missing/invalid From address")], info
    rd = reg_domain(domain)
    info["domain"] = rd

    # Authentication-Results from receiving server
    ar = p["auth_results"]
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", ar)
        info[mech] = m.group(1) if m else "none"
        if m and m.group(1) in ("fail", "softfail", "permerror"):
            findings.append((15, f"{mech.upper()} {m.group(1)} for sender"))
        elif m and m.group(1) in ("timeout", "temperror"):
            findings.append((4, f"{mech.upper()} could not be verified ({m.group(1)})"))
        elif not m:
            findings.append((4, f"No {mech.upper()} result in headers"))
    if p.get("auth_count", 0) > 1:
        findings.append((5, "Multiple Authentication-Results headers (attackers sometimes inject fake ones)"))

    # DNS posture of the sender domain
    spf = [t for t in dns_txt(rd) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in dns_txt(f"_dmarc.{rd}") if t.lower().startswith("v=dmarc1")]
    info["spf_record"], info["dmarc_record"] = bool(spf), bool(dmarc)
    dns_ok = dns_working()
    if dns_ok and not spf and not dmarc:
        findings.append((8, "Sender domain publishes neither SPF nor DMARC"))
    if dns_ok and dns_has(rd, "MX") is False and dns_has(rd, "A") is False:
        findings.append((8, "Sender domain has no MX record"))

    # domain age
    age = rdap_age_days(rd)
    info["age_days"] = age
    if age is not None:
        if age < 30:
            findings.append((25, f"Sender domain registered only {age} days ago"))
        elif age < 180:
            findings.append((10, f"Sender domain is young ({age} days)"))

    # reputation
    vt = vt_domain(rd)
    info["virustotal"] = vt
    if vt and vt["stats"]:
        bad = vt["stats"].get("malicious", 0) + vt["stats"].get("suspicious", 0)
        if bad:
            findings.append((min(15 + 5 * bad, 35), f"VirusTotal flags sender domain ({bad} engines)"))

    # impersonation
    ll = lookalike(rd)
    if ll:
        findings.append((25, f"Sender domain {ll}"))
    disp = (name or "").lower()
    if disp and domain in FREE_MAIL and any(b in disp for b in BRANDS):
        findings.append((20, f"Brand in display name '{name}' sent from free mail {domain}"))
    if "@" in disp:
        d2 = disp.split("@")[-1].strip()
        if d2 and d2 != domain:
            findings.append((20, "Display name contains a different email address"))
    rt = p["reply_to"][1].split("@")[-1].lower() if "@" in p["reply_to"][1] else ""
    if rt and reg_domain(rt) != rd:
        findings.append((15, f"Reply-To domain ({rt}) differs from From domain"))
        if rt in FREE_MAIL and domain not in FREE_MAIL:
            findings.append((15, f"Company-style sender but replies go to free mailbox ({rt})"))
    rp = p["return_path"][1].split("@")[-1].lower() if "@" in p["return_path"][1] else ""
    if rp and reg_domain(rp) != rd:
        info["return_path_mismatch"] = rp  # common with ESPs; informational only
    return findings, info


# ------------------------------------------------------------------ URL heuristics
def analyze_link_static(href, text):
    f = []
    u = urlparse(href)
    host = (u.hostname or "").lower()
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        f.append((20, "URL uses a raw IP address"))
    if host in SHORTENERS:
        f.append((8, "URL shortener hides destination"))
    if "xn--" in host:
        f.append((20, "Punycode (possible homograph) domain"))
    if host.count(".") >= 4:
        f.append((8, "Excessive subdomains"))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        f.append((8, f"Suspicious TLD .{host.rsplit('.', 1)[-1]}"))
    if "@" in u.netloc:
        f.append((15, "URL contains @ credential trick"))
    if u.scheme == "http":
        f.append((4, "Plain HTTP link"))
    if re.search(r"[A-Za-z0-9_-]{60,}", (u.path or "") + (u.query or "")):
        f.append((10, "Very long random token in URL (typical of redirect / cloaking links)"))
    ll = lookalike(host)
    if ll:
        f.append((20, f"Link domain {ll}"))
    m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", text.lower())
    if m and reg_domain(m.group(0)) != reg_domain(host) and "." in text:
        f.append((25, f"Link text shows '{m.group(0)}' but goes to {host}"))
    return f


def brand_link_mismatch(p):
    name, addr = p["from"]
    claim_src = f"{name} {addr} {p['subject']}".lower()
    claimed = [b for b in BRANDS if re.search(rf"\b{b}\b", claim_src)]
    if not claimed or not p["links"]:
        return None
    doms = [reg_domain(urlparse(h).hostname or "") for h, _ in p["links"]]
    if any(b in d for d in doms for b in claimed):
        return None
    return f"Email claims to be '{claimed[0]}' but none of its links go to a {claimed[0]} domain ({', '.join(sorted(set(doms)))[:80]})"


def api_error(name, r):
    """Turn an HTTP error from an API into a sentence a person can act on."""
    if r.status_code in (401, 403):
        return f"{name} rejected the API key (wrong, mistyped or inactive key)"
    if r.status_code == 429:
        return f"{name} rate limit reached - free keys allow only a few lookups per minute/day; wait and retry"
    msg = None
    try:
        j = r.json()
        err = j.get("error")
        msg = j.get("message") or j.get("description") or (err.get("message") if isinstance(err, dict) else err)
    except Exception:
        pass
    return f"{name} error {r.status_code}: {msg or r.text[:120]}"


# ------------------------------------------------------------------ external services
_last_vt = 0.0


def vt_url(url):
    global _last_vt
    if not VT_KEY:
        return None
    h = {"x-apikey": VT_KEY}
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    wait = 16 - (time.time() - _last_vt)  # free tier: 4 req/min
    if wait > 0:
        time.sleep(wait)
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=h, timeout=TIMEOUT)
        _last_vt = time.time()
        if r.status_code not in (200, 404):
            return {"error": api_error("VirusTotal", r)}
        if r.status_code == 404:
            r = requests.post("https://www.virustotal.com/api/v3/urls", headers=h,
                              data={"url": url}, timeout=TIMEOUT)
            if not r.ok:
                return {"error": api_error("VirusTotal", r)}
            aid = r.json()["data"]["id"]
            for _ in range(8):
                time.sleep(8)
                a = requests.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=h, timeout=TIMEOUT)
                _last_vt = time.time()
                d = a.json()["data"]["attributes"]
                if d.get("status") == "completed":
                    return {"stats": d["stats"], "link": f"https://www.virustotal.com/gui/url/{uid}"}
            return {"error": "analysis timed out", "link": f"https://www.virustotal.com/gui/url/{uid}"}
        a = r.json()["data"]["attributes"]
        return {"stats": a.get("last_analysis_stats"), "link": f"https://www.virustotal.com/gui/url/{uid}"}
    except Exception as e:
        return {"error": str(e)}


def urlscan(url, wait=180):
    if not URLSCAN_KEY:
        return None
    try:
        r = requests.post("https://urlscan.io/api/v1/scan/",
                          headers={"API-Key": URLSCAN_KEY, "Content-Type": "application/json"},
                          json={"url": url, "visibility": "unlisted"}, timeout=TIMEOUT)
        if not r.ok:
            return {"error": api_error("urlscan.io", r)}
        uuid = r.json()["uuid"]
        end = time.time() + wait
        time.sleep(10)
        while time.time() < end:
            res = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=TIMEOUT)
            if res.status_code == 200:
                j = res.json()
                ov = j.get("verdicts", {}).get("overall", {})
                return {"malicious": ov.get("malicious"), "score": ov.get("score"),
                        "categories": ov.get("categories"),
                        "title": j.get("page", {}).get("title"),
                        "final_url": j.get("page", {}).get("url"),
                        "ip": j.get("page", {}).get("ip"),
                        "country": j.get("page", {}).get("country"),
                        "report": f"https://urlscan.io/result/{uuid}/",
                        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png"}
            time.sleep(5)
        return {"pending": True, "report": f"https://urlscan.io/result/{uuid}/"}
    except Exception as e:
        return {"error": str(e)}


def joe_submit(url, wait=0):
    if not JOE_KEY:
        return None
    try:
        r = requests.post(f"{JOE_URL}/v2/submission/new",
                          data={"apikey": JOE_KEY, "accept-tac": 1, "url": url}, timeout=TIMEOUT)
        if not r.ok:
            return {"error": api_error("Joe Sandbox", r)}
        sid = r.json()["data"]["submission_id"]
        out = {"submission_id": sid, "status": "submitted"}
        end = time.time() + wait
        while time.time() < end:
            time.sleep(20)
            i = requests.post(f"{JOE_URL}/v2/submission/info",
                              data={"apikey": JOE_KEY, "submission_id": sid}, timeout=TIMEOUT).json()["data"]
            out["status"] = i.get("status")
            if i.get("status") == "finished":
                an = (i.get("analyses") or [{}])[0]
                out.update({"detection": an.get("detection"), "score": an.get("score"),
                            "report": f"https://jbxcloud.joesecurity.org/analysis/{an.get('webid')}"})
                break
        return out
    except Exception as e:
        return {"error": str(e)}


_openphish = None


def openphish_hit(url):
    """Free, keyless: checks the public OpenPhish community feed."""
    global _openphish
    if _openphish is None:
        try:
            r = requests.get("https://openphish.com/feed.txt", timeout=TIMEOUT)
            _openphish = set(r.text.split()) if r.ok else set()
        except Exception:
            _openphish = set()
    return url in _openphish or url.rstrip("/") in _openphish


def wannabrowser_fetch(url, max_hops=6, trusted=None):
    """WannaBrowser-style check: custom UA, JS NOT executed, follow redirects manually."""
    chain, cur = [], url
    try:
        for _ in range(max_hops):
            r = requests.get(cur, headers={"User-Agent": UA}, timeout=TIMEOUT,
                             allow_redirects=False, stream=True)
            chain.append(f"{r.status_code} {cur}")
            if r.is_redirect and r.headers.get("Location"):
                cur = urljoin(cur, r.headers["Location"])
                continue
            body = r.raw.read(600_000, decode_content=True).decode("utf-8", "ignore")
            break
        else:
            return {"redirect_chain": chain, "error": "too many redirects", "risk": 10}
    except Exception as e:
        return {"redirect_chain": chain, "error": str(e), "risk": 0}

    soup = BeautifulSoup(body, "html.parser")
    final_host = reg_domain(urlparse(cur).hostname or "")
    notes, risk = [], 0
    status = chain[-1].split()[0]
    first_host = reg_domain(urlparse(url).hostname or "")
    own_site = bool(trusted) and first_host == trusted  # e.g. tracking link on the sender's own domain
    if status.isdigit() and int(status) >= 400 and not own_site:
        notes.append(f"Page did not load (HTTP {status}): dead, cloaked, geo-blocked or taken down - cannot be verified, treat as unsafe")
        risk += 8
    first_host = reg_domain(urlparse(url).hostname or "")
    if len(chain) > 1 and first_host != final_host:
        notes.append(f"Redirects from {first_host} to a different domain: {final_host}")
        risk += 8
    pw = soup.find_all("input", {"type": "password"})
    if pw:
        notes.append("Page has a password field")
        risk += 20
    for fm in soup.find_all("form"):
        act = urljoin(cur, fm.get("action", ""))
        ah = reg_domain(urlparse(act).hostname or "")
        if ah and ah != final_host:
            notes.append(f"Form posts to different domain: {ah}")
            risk += 20
    if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        notes.append("Meta-refresh redirect")
        risk += 8
    if re.search(r"eval\(|atob\(|unescape\(|fromCharCode|document\.write\(", body):
        notes.append("Obfuscated / dynamic JavaScript")
        risk += 12
    for fr in soup.find_all("iframe"):
        if "display:none" in (fr.get("style") or "").replace(" ", "") or fr.get("width") in ("0", "1"):
            notes.append("Hidden iframe")
            risk += 12
            break
    t = (soup.title.string or "").strip() if soup.title else ""
    ll = lookalike(final_host)
    if t and any(b in t.lower() for b in BRANDS) and ll:
        notes.append(f"Page title '{t}' impersonates a brand on {final_host}")
        risk += 20
    return {"final_url": cur, "status": status, "title": t, "redirect_chain": chain, "notes": notes, "risk": risk,
            "manual_check": "https://wannabrowser.net/  (paste the URL, set your own User-Agent)"}


# ------------------------------------------------------------------ orchestration
def scan_message(raw, args):
    p = parse_email(raw)
    score, findings = 0, []

    for pts, why in analyze_content(p):
        findings.append({"points": pts, "why": why})
        score += pts
    sf, sinfo = analyze_sender(p)
    for pts, why in sf:
        findings.append({"points": pts, "why": why})
        score += pts

    bm = brand_link_mismatch(p)
    if bm:
        findings.append({"points": 25, "why": bm})
        score += 25

    link_reports, seen = [], set()
    for href, text in p["links"][: args.max_links]:
        if href in seen:
            continue
        seen.add(href)
        rep = {"url": defang(href), "static": [], "virustotal": None, "urlscan": None,
               "joesandbox": None, "browser": None}
        for pts, why in analyze_link_static(href, text):
            rep["static"].append(why)
            score += pts
        if not args.offline:
            if openphish_hit(href):
                rep["static"].append("Listed in OpenPhish live phishing feed")
                findings.append({"points": 50, "why": f"OpenPhish feed lists {defang(href)}"})
                score += 50
            rep["virustotal"] = vt_url(href)
            vs = (rep["virustotal"] or {}).get("stats") or {}
            if vs.get("malicious", 0) + vs.get("suspicious", 0):
                score += min(25 + 5 * (vs.get("malicious", 0)), 45)
                findings.append({"points": 25, "why": f"VirusTotal flags link {defang(href)}"})
            rep["urlscan"] = urlscan(href)
            if (rep["urlscan"] or {}).get("malicious"):
                score += 40
                findings.append({"points": 40, "why": f"urlscan.io verdict MALICIOUS for {defang(href)}"})
            rep["joesandbox"] = joe_submit(href, wait=args.joe_wait)
            jd = ((rep["joesandbox"] or {}).get("detection") or "").lower()
            if jd in ("malicious", "suspicious"):
                score += 40
                findings.append({"points": 40, "why": f"Joe Sandbox detection: {jd} for {defang(href)}"})
            if args.fetch:
                rep["browser"] = wannabrowser_fetch(href, trusted=sinfo.get("domain"))
                score += (rep["browser"] or {}).get("risk", 0)
        link_reports.append(rep)

    score = min(score, 100)
    verdict = "MALICIOUS / HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LIKELY SAFE"
    return {"subject": p["subject"], "from": p["from"][1], "score": score, "verdict": verdict,
            "from_name": p["from"][0], "reply_to": p["reply_to"][1],
            "findings": findings, "sender": sinfo, "links": link_reports,
            "attachments": p["attachments"]}


def show_service(name, v, skipped):
    if v is None:
        kv(name, skipped)
        return
    if v.get("error"):
        kv(name, "ERROR - " + str(v["error"]))
        if v.get("report") or v.get("link"):
            kv("   link", v.get("report") or v.get("link"))
        return
    if name == "VirusTotal":
        st = v.get("stats") or {}
        bad = st.get("malicious", 0) + st.get("suspicious", 0)
        kv(name, f"{'FLAGGED' if bad else 'clean'}  (malicious={st.get('malicious', 0)}, suspicious={st.get('suspicious', 0)}, "
                 f"harmless={st.get('harmless', 0)}, undetected={st.get('undetected', 0)})")
        if v.get("link"):
            kv("   report", v["link"])
    elif name == "urlscan.io":
        if v.get("pending"):
            kv(name, "scan submitted but still running - open the report link below in a minute")
            kv("   report", v.get("report"))
            return
        kv(name, f"{'MALICIOUS' if v.get('malicious') else 'no threat verdict'}  (score={v.get('score')}, "
                 f"title={v.get('title')!r}, server={v.get('ip')} {v.get('country')})")
        kv("   report", v.get("report"))
        kv("   screenshot", v.get("screenshot"))
    else:
        kv(name, f"status={v.get('status')} detection={v.get('detection')} score={v.get('score')} id={v.get('submission_id')}")
        if v.get("report"):
            kv("   report", v["report"])


def print_report_technical(r):
    bar = c("═" * 74, PURPLE)
    print("\n" + bar)
    heading("EMAIL")
    kv("Subject", r["subject"])
    kv("From", r["from"])
    kv("Attachments", ", ".join(r["attachments"]) or "none")
    heading("VERDICT")
    kv("Result", r["verdict"])
    kv("Risk score", f"{r['score']}/100")

    if r["score"] >= 30 and r["sender"].get("spf") == "pass" and r["sender"].get("dmarc") == "pass":
        kv("Note", "SPF/DMARC passed but content is suspicious: headers may be forged, or the sender account may be compromised")

    heading("WHAT SIFTVEIL FOUND")
    if not r["findings"]:
        print("  " + c("Nothing suspicious detected", WHITE))
    for f in sorted(r["findings"], key=lambda x: -x["points"]):
        print(f"  {c('[+%d]' % f['points'], PINK)} {c(f['why'], WHITE)}")

    s = r["sender"]
    heading("SENDER DOMAIN")
    kv("Domain", s.get("domain"))
    kv("Age (days)", s.get("age_days") if s.get("age_days") is not None else "unknown")
    kv("SPF / DKIM / DMARC", f"{s.get('spf')} / {s.get('dkim')} / {s.get('dmarc')}")
    kv("SPF / DMARC DNS records", f"{s.get('spf_record')} / {s.get('dmarc_record')}")

    for l in r["links"]:
        heading("LINK ANALYSIS")
        kv("URL (defanged)", l["url"])
        for w in l["static"]:
            kv("Red flag", w)
        show_service("VirusTotal", l["virustotal"], "skipped (no key found, or --offline)")
        show_service("urlscan.io", l["urlscan"], "skipped (no key found, or --offline)")
        show_service("Joe Sandbox", l["joesandbox"], "skipped (no key found, or --offline)")
        if l["browser"]:
            b = l["browser"]
            kv("Page fetch", f"title={b.get('title')!r}, hops={len(b.get('redirect_chain', []))}")
            for n in b.get("notes", []) or []:
                kv("Page finding", n)
            if b.get("error"):
                kv("Fetch note", b["error"])
    print("\n" + bar + "\n")


# ------------------------------------------------------------------ plain-English report
import textwrap

RED = "\033[1;38;2;255;80;80m"
YELLOW = "\033[1;38;2;255;200;0m"
GREEN = "\033[1;38;2;90;220;130m"

PLAIN = [
    (r"^Urgency/pressure language", "The email tries to rush or scare you (words like 'urgent', 'blocked', 'verify now'). Scammers do this so you act before you think."),
    (r"^Credential/financial request", "It asks you to log in, confirm a password or update payment details. Real companies don't ask for this by email."),
    (r"^Social-engineering cues", "It uses common scam tricks such as gift cards, crypto, refunds or asking you to keep it secret."),
    (r"^Risky attachment type: (.+)", "The attachment '{0}' is a type of file that can carry a virus."),
    (r"^Double-extension attachment: (.+)", "The attachment '{0}' pretends to be a normal document but is really a program."),
    (r"^Very short body", "The email is almost empty and only pushes you to click a link."),
    (r"^Missing/invalid From", "The sender address is missing or fake."),
    (r"^(SPF|DKIM|DMARC) (fail|softfail|permerror)", "The email failed a check that proves it really came from the sender it claims ({0}). It is probably faked."),
    (r"could not be verified", "One of the sender identity checks could not be completed (minor)."),
    (r"^No (SPF|DKIM|DMARC) result", "One of the sender identity checks is missing (minor)."),
    (r"^Sender domain publishes neither", "The sender's website has no email-protection setup, which real companies almost always have."),
    (r"^Sender domain has no MX", "The sender's domain cannot even receive email, which suggests it is fake."),
    (r"^Sender domain registered only (\d+) days", "The sender's web address was created only {0} days ago. Scam addresses are usually brand new."),
    (r"^Sender domain is young \((\d+) days\)", "The sender's web address is fairly new ({0} days old)."),
    (r"^VirusTotal flags sender domain", "Security scanners (VirusTotal) flag the sender's domain as dangerous."),
    (r"^Sender domain contains brand '(\w+)'", "The sender's address uses the name '{0}' but it is not {0}'s real domain. It is an imitation."),
    (r"^Sender domain looks like '(\w+)'", "The sender's address is a misspelled copy of '{0}'."),
    (r"^Brand in display name '(.+?)' sent from free mail (.+)", "The sender's name says '{0}' but it was sent from a free personal account ({1})."),
    (r"^Display name contains a different email", "The sender's display name shows a different email address than the real one."),
    (r"^Reply-To domain \((.+?)\) differs", "If you press Reply, your answer goes to a different address ({0}) than the one it came from. Scammers do this to catch your reply."),
    (r"^Company-style sender but replies go to free mailbox \((.+?)\)", "A real company would not ask you to reply to a free personal inbox ({0})."),
    (r"^Multiple Authentication-Results", "The email contains what look like forged security stamps."),
    (r"^Email claims to be '(\w+)' but none of its links go to a \w+ domain \((.+)\)", "It pretends to be {0}, but its links go to {1}, not to {0}'s real website."),
    (r"^VirusTotal flags link", "Security scanners (VirusTotal) flag a link in this email as dangerous."),
    (r"^urlscan.io verdict MALICIOUS", "The online scanner urlscan.io says a link in this email is malicious."),
    (r"^Joe Sandbox detection: (\w+)", "A malware-testing lab (Joe Sandbox) rates a link as {0}."),
    (r"^OpenPhish feed lists|^Listed in OpenPhish", "This link is on a public list of known phishing sites."),
    # link flags
    (r"^URL uses a raw IP", "The link goes to a bare number address instead of a normal website name."),
    (r"^URL shortener", "The link is shortened, which hides where it really goes."),
    (r"^Punycode", "The web address uses look-alike foreign letters to imitate a real site."),
    (r"^Excessive subdomains", "The web address is unusually long and tangled."),
    (r"^Suspicious TLD (\.\w+)", "The address ends in '{0}', an ending scammers use a lot."),
    (r"^URL contains @", "The link contains a trick that sends you somewhere other than where it seems to go."),
    (r"^Plain HTTP", "The link is not encrypted (no padlock)."),
    (r"^Very long random token", "The link contains a long random code, often used to track victims or hide the real destination."),
    (r"^Link domain (contains brand|looks like) '(\w+)'", "The link imitates {1}'s website but is not it."),
    (r"^Link text shows '(.+?)' but goes to (.+)", "The link says it goes to {0} but really goes to {1}. A classic trick."),
    # page flags
    (r"^Page has a password field", "The page asks you for a password."),
    (r"^Form posts to different domain: (.+)", "Anything you type on that page would be sent to a different website ({0})."),
    (r"^Meta-refresh", "The page silently sends you somewhere else."),
    (r"^Obfuscated", "The page contains scrambled, hidden code."),
    (r"^Hidden iframe", "The page contains hidden content."),
    (r"^Page title '(.+?)' impersonates a brand on (.+)", "The page pretends to be a known brand but is hosted on {1}."),
    (r"^Page did not load \(HTTP (\d+)\)", "The page did not load (error {0}). It may be dead, taken down, or hiding from scanners, so it can't be checked. Treat it as unsafe."),
    (r"^Redirects from (.+?) to a different domain: (.+)", "The link silently bounces you from {0} to {1}."),
]


def plain(why):
    for pat, tpl in PLAIN:
        m = re.search(pat, why)
        if m:
            try:
                return tpl.format(*[g.capitalize() if g in BRANDS else g for g in m.groups()])
            except Exception:
                return tpl
    return why


def say(text, color=WHITE, indent=2, bullet=None):
    pre = " " * indent + (bullet + " " if bullet else "")
    for ln in textwrap.wrap(text, width=78, initial_indent=pre, subsequent_indent=" " * len(pre)):
        print(c(ln, color))


def print_report_simple(r, technical=False):
    if technical:
        return print_report_technical(r)
    score = r["score"]
    if score >= 60:
        col, icon, label = RED, "🔴", "DANGEROUS - DO NOT CLICK ANYTHING"
        summary = "This email is very likely a scam (phishing). Do not click its links, open its attachments, or reply to it."
    elif score >= 30:
        col, icon, label = YELLOW, "🟡", "SUSPICIOUS - BE CAREFUL"
        summary = "This email has several warning signs. Do not click anything until you have checked it another way."
    else:
        col, icon, label = GREEN, "🟢", "NO STRONG WARNING SIGNS"
        summary = "We did not find strong warning signs, but always be careful with unexpected emails. No tool can promise an email is 100% safe."
    n = score // 10
    bar = "█" * n + "░" * (10 - n)
    line = c("═" * 78, PURPLE)

    print("\n" + line)
    heading("RESULT")
    print(f"  {icon} {c(label, col)}")
    print(f"  {c('Danger level:', PINK)} {c(bar + f'  {score}/100', col)}")
    say(summary, WHITE)

    heading("ABOUT THIS EMAIL")
    kv("Subject", r["subject"])
    kv("Name shown as sender", r.get("from_name") or "(none)")
    kv("Real sending address", r["from"])
    if r.get("reply_to"):
        kv("Replies would go to", r["reply_to"])
    kv("Attachments", ", ".join(r["attachments"]) or "none")

    sd = r["sender"]
    spf, dm = sd.get("spf"), sd.get("dmarc")
    if "fail" in (spf, dm) or "softfail" in (spf, dm):
        ident = "NO - it failed the identity check, so it is probably faked"
    elif spf == "pass" and dm == "pass":
        ident = "Passed the technical identity check"
    else:
        ident = "Could not be confirmed"
    kv("Did it really come from that sender?", ident)
    if sd.get("age_days") is not None:
        kv("Sender web address created", f"{sd['age_days']} days ago")
    if score >= 30 and spf == "pass" and dm == "pass":
        say("Note: the identity check passed, but the content looks like a scam. The sender's account may have been hacked, or the email's security stamps may have been forged.", YELLOW)

    heading("WHY WE THINK SO")
    main = [f for f in sorted(r["findings"], key=lambda x: -x["points"]) if f["points"] >= 5]
    if not main:
        say("Nothing worrying was found.", WHITE)
    for f in main[:8]:
        say(plain(f["why"]), WHITE, bullet="•")
    if len(main) > 8:
        say(f"...and {len(main) - 8} more minor signs.", DIM)

    if r["links"]:
        heading("WHERE THE LINKS REALLY GO")
        for i, l in enumerate(r["links"], 1):
            kv(f"Link {i}", l["url"])
            say("(written safely so you can't click it by accident)", DIM, indent=4)
            flags = l["static"][:]
            b = l.get("browser") or {}
            flags += b.get("notes", []) or []
            bad = False
            for fl in flags:
                if fl:
                    say(plain(fl), WHITE, indent=4, bullet="•")
                    bad = True
            for name, key in (("VirusTotal", "virustotal"), ("urlscan.io", "urlscan"), ("Joe Sandbox", "joesandbox")):
                v = l.get(key) or {}
                st = v.get("stats") or {}
                if v.get("error"):
                    say(f"{name} could not be used: {v['error']}", DIM, indent=4)
                if key == "virustotal" and (st.get("malicious", 0) + st.get("suspicious", 0)):
                    say(f"{name}: flagged by {st.get('malicious', 0) + st.get('suspicious', 0)} security engines.", RED, indent=4, bullet="•")
                if key == "urlscan" and v.get("malicious"):
                    say(f"{name}: rated MALICIOUS.", RED, indent=4, bullet="•")
                if key == "joesandbox" and str(v.get("detection", "")).lower() in ("malicious", "suspicious"):
                    say(f"{name}: rated {v.get('detection')}.", RED, indent=4, bullet="•")
            if not bad:
                say("No obvious problems found with this link by itself.", DIM, indent=4)
        used = any(l.get("virustotal") or l.get("urlscan") or l.get("joesandbox") for l in r["links"])
        if not used:
            say("Extra online scanners (VirusTotal, urlscan.io, Joe Sandbox) were not used. Add free keys for stronger checking.", DIM)

    heading("WHAT YOU SHOULD DO")
    if score >= 60:
        steps = ["Do NOT click any link or open any attachment.",
                 "Do NOT reply or send any personal information.",
                 "Delete it, or use 'Report phishing' / 'Report spam' in your email app.",
                 "If it claims to be your bank or a service you use, contact them using the phone number on your card or their official app. Never use anything from the email.",
                 "Already clicked or typed a password? Change that password right now, turn on two-step verification, and tell your bank or IT team."]
    elif score >= 30:
        steps = ["Do not click links or open attachments yet.",
                 "Check it another way: type the company's website address yourself or call them on a number you already trust.",
                 "If you are still unsure, ask someone you trust or your IT team."]
    else:
        steps = ["If the email is unexpected, still avoid clicking links; go to the website directly instead.",
                 "If something feels wrong, trust your instinct and ask someone."]
    for i, st in enumerate(steps, 1):
        say(st, WHITE, bullet=f"{i}.")
    print("\n" + c("  Want the expert details? Run again without --simple", DIM))
    print(line + "\n")



def print_report(r, simple=False):
    return print_report_simple(r) if simple else print_report_technical(r)


def cmd_keys(args):
    """Live-test every API key so you know it works before scanning."""
    heading("TESTING YOUR API KEYS")

    def src(n):
        return f" (from {KEY_SOURCE.get(n, 'command line')})"
    # VirusTotal
    if VT_KEY:
        try:
            r = requests.get("https://www.virustotal.com/api/v3/domains/google.com", headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
            kv("VirusTotal", ("WORKS ✔" if r.ok else "FAILED - " + api_error("VirusTotal", r)) + src("VT_API_KEY"))
        except Exception as e:
            kv("VirusTotal", f"could not connect: {e}")
    else:
        kv("VirusTotal", "no key found")
    # urlscan.io
    if URLSCAN_KEY:
        try:
            r = requests.get("https://urlscan.io/user/quotas/", headers={"API-Key": URLSCAN_KEY}, timeout=TIMEOUT)
            kv("urlscan.io", ("WORKS ✔" if r.ok else "FAILED - " + api_error("urlscan.io", r)) + src("URLSCAN_API_KEY"))
        except Exception as e:
            kv("urlscan.io", f"could not connect: {e}")
    else:
        kv("urlscan.io", "no key found")
    # Joe Sandbox
    if JOE_KEY:
        try:
            r = requests.post(f"{JOE_URL}/v2/account/info", data={"apikey": JOE_KEY}, timeout=TIMEOUT)
            kv("Joe Sandbox", ("WORKS ✔" if r.ok else "FAILED - " + api_error("Joe Sandbox", r)) + src("JOE_API_KEY"))
        except Exception as e:
            kv("Joe Sandbox", f"could not connect: {e}")
    else:
        kv("Joe Sandbox", "no key found (optional)")
    print()
    if not (VT_KEY or URLSCAN_KEY):
        say("No keys found. Put them in ~/.siftveil.env like this (no spaces around the = sign):", WHITE)
        say("VT_API_KEY=your_virustotal_key", PINK, indent=4)
        say("URLSCAN_API_KEY=your_urlscan_key", PINK, indent=4)
        print()


def cmd_scan(args):
    results = []
    for path in args.files:
        with open(path, "rb") as fh:
            r = scan_message(fh.read(), args)
        r["file"] = path
        print_report(r, args.simple)
        results.append(r)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"JSON report saved to {args.json}")


def cmd_watch(args):
    host, user, pw = os.getenv("IMAP_HOST"), os.getenv("IMAP_USER"), os.getenv("IMAP_PASS")
    if not (host and user and pw):
        sys.exit("Set IMAP_HOST, IMAP_USER and IMAP_PASS environment variables.")
    print(f"[SiftVeil] watching {user}@{host} every {args.interval}s (Ctrl+C to stop)")
    while True:
        try:
            m = imaplib.IMAP4_SSL(host)
            m.login(user, pw)
            m.select("INBOX")
            _, data = m.search(None, "UNSEEN")
            for num in data[0].split():
                _, msgdata = m.fetch(num, "(BODY.PEEK[])")  # PEEK keeps it unread
                r = scan_message(msgdata[0][1], args)
                print_report(r, args.simple)
                if args.quarantine and r["score"] >= 60:
                    m.create(args.quarantine)
                    m.copy(num, args.quarantine)
                    m.store(num, "+FLAGS", "\\Deleted")
                    print(f"  -> moved to '{args.quarantine}'")
            m.expunge()
            m.logout()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[error] {e}")
        time.sleep(args.interval)


def main():
    ap = argparse.ArgumentParser(prog="siftveil", description="Email phishing scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def keyargs(p):
        p.add_argument("--vt-key", help="VirusTotal API key (overrides saved keys)")
        p.add_argument("--urlscan-key", help="urlscan.io API key (overrides saved keys)")
        p.add_argument("--joe-key", help="Joe Sandbox API key (overrides saved keys)")

    def common(p):
        p.add_argument("--simple", action="store_true",
                       help="show a plain-English report instead of the detailed one")
        p.add_argument("--offline", action="store_true", help="skip all external services")
        keyargs(p)
        p.add_argument("--no-fetch", dest="fetch", action="store_false",
                       help="don't touch suspicious sites directly from this machine")
        p.add_argument("--max-links", type=int, default=5)
        p.add_argument("--joe-wait", type=int, default=0,
                       help="seconds to wait for Joe Sandbox result (0 = submit only)")

    s = sub.add_parser("scan", help="scan .eml files")
    s.add_argument("files", nargs="+")
    s.add_argument("--json")
    common(s)
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="auto-scan new IMAP mail")
    w.add_argument("--interval", type=int, default=120)
    w.add_argument("--quarantine", help="IMAP folder to move high-risk mail into")
    common(w)
    w.set_defaults(func=cmd_watch)

    k = sub.add_parser("keys", help="test that your API keys work")
    keyargs(k)
    k.set_defaults(func=cmd_keys)

    global VT_KEY, URLSCAN_KEY, JOE_KEY
    a = ap.parse_args()
    if a.vt_key:
        VT_KEY = a.vt_key.strip()
    if a.urlscan_key:
        URLSCAN_KEY = a.urlscan_key.strip()
    if a.joe_key:
        JOE_KEY = a.joe_key.strip()
    show_banner()
    show_key_status(getattr(a, "offline", False))
    a.func(a)


if __name__ == "__main__":
    main()
