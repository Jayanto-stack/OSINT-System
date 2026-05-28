import httpx
import subprocess
import re
import socket
from dotenv import load_dotenv
import os

try:
    import shodan as shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    print("[OSINT] shodan not installed — run: pip install shodan")

try:
    from googlesearch import search as google_search
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────
# API KEYS
# ─────────────────────────────────────────────────────────────────────
load_dotenv()

SHODAN_API_KEY          = os.getenv("SHODAN_API_KEY", "")
HUNTER_API_KEY          = os.getenv("HUNTER_API_KEY", "")
NUMVERIFY_API_KEY       = os.getenv("NUMVERIFY_API_KEY", "")
LEAKCHECK_API_KEY       = os.getenv("LEAKCHECK_API_KEY", "")


def google_dork_search(name: str, email: str) -> list:
    if not GOOGLE_AVAILABLE:
        return []
    queries = [
        f'"{name}"',
        f'"{email}"',
        f'"{name}" site:linkedin.com OR site:twitter.com OR site:facebook.com',
    ]
    results = []
    for query in queries:
        try:
            hits = list(google_search(query, num_results=3, sleep_interval=3))
            results.extend(hits)
            print(f"[OSINT] Google: {query[:50]}")
        except Exception as e:
            print(f"[OSINT] Google error: {e}")
    return list(set(results))

HOLEHE_FALSE_POSITIVES = {
    "firefox.com", "office365.com", "amazon.com",
    "spotify.com", "wordpress.com", "adobe.com"
}

def check_email_registrations(email: str) -> list:
    try:
        result = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=90
        )
        lines = result.stdout.strip().split("\n")
        filtered = []
        for l in lines:
            if not l.strip():
                continue
            if "[+]" in l or "[-]" in l or "[x]" in l:
                # Extract domain from line
                match = re.search(r'\[.\]\s*(\S+)', l.strip())
                domain = match.group(1).lower() if match else ""
                # Skip known false positives
                if "[+]" in l and domain in HOLEHE_FALSE_POSITIVES:
                    print(f"[OSINT] Holehe: skipping false positive - {domain}")
                    continue
                filtered.append(l.strip())
        found = [l for l in filtered if "[+]" in l]
        print(f"[OSINT] Holehe: {len(found)} real registrations found")
        return filtered
    except FileNotFoundError:
        print("[OSINT] holehe not found")
        return []
    except Exception as e:
        print(f"[OSINT] Holehe error: {e}")
        return []


def check_email_breach(email: str) -> dict:
    if not LEAKCHECK_API_KEY:
        return {"breached": "unknown", "count": 0, "breaches": [],
                "note": "Add LEAKCHECK_API_KEY in scanner.py"}
    try:
        r = httpx.get(
            f"https://leakcheck.io/api/public?check={email}&key={LEAKCHECK_API_KEY}",
            timeout=15
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            sources = [s.get("name", "Unknown") for s in data.get("sources", [])[:5]]
            print(f"[OSINT] LeakCheck: {data['found']} breaches")
            return {"breached": True, "count": data["found"], "breaches": sources}
        return {"breached": False, "count": 0, "breaches": []}
    except Exception as e:
        print(f"[OSINT] LeakCheck error: {e}")
        return {"breached": "unknown", "count": 0, "breaches": []}


def shodan_lookup(email: str) -> dict:
    if not SHODAN_API_KEY or not SHODAN_AVAILABLE:
        return {"available": False, "note": "Add SHODAN_API_KEY in scanner.py"}
    domain = email.split("@")[-1]
    result = {"available": True, "domain": domain, "ip": None,
              "open_ports": [], "vulns": [], "hostnames": [],
              "country": None, "org": None, "note": None}
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        api  = shodan_lib.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        result["open_ports"] = host.get("ports", [])
        result["hostnames"]  = host.get("hostnames", [])
        result["country"]    = host.get("country_name")
        result["org"]        = host.get("org")
        result["vulns"]      = list(host.get("vulns", {}).keys())[:5]
        print(f"[OSINT] Shodan: {len(result['open_ports'])} ports, {len(result['vulns'])} vulns")
    except Exception as e:
        result["note"] = str(e)
        print(f"[OSINT] Shodan error: {e}")
    return result


def hunter_email_lookup(email: str) -> dict:
    if not HUNTER_API_KEY:
        return {"available": False, "note": "Add HUNTER_API_KEY in scanner.py"}
    domain = email.split("@")[-1]
    try:
        r = httpx.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": HUNTER_API_KEY, "limit": 10},
            timeout=15
        )
        data = r.json().get("data", {})
        emails_found = [
            {"email": e.get("value"), "type": e.get("type"),
             "confidence": e.get("confidence"), "position": e.get("position")}
            for e in data.get("emails", [])[:8]
        ]
        print(f"[OSINT] Hunter.io: {len(emails_found)} emails for {domain}")
        return {"available": True, "domain": domain,
                "organization": data.get("organization"),
                "total_emails": data.get("meta", {}).get("total", 0),
                "emails": emails_found, "pattern": data.get("pattern")}
    except Exception as e:
        print(f"[OSINT] Hunter.io error: {e}")
        return {"available": False, "note": str(e)}


def phone_lookup(phone: str) -> dict:
    if not phone:
        return {"available": False, "note": "No phone provided"}
    if not NUMVERIFY_API_KEY:
        digits = re.sub(r'\D', '', phone)
        return {"available": False, "raw": phone,
                "digit_count": len(digits),
                "note": "Add NUMVERIFY_API_KEY for carrier/location lookup"}
    try:
        r = httpx.get(
            "http://apilayer.net/api/validate",
            params={"access_key": NUMVERIFY_API_KEY, "number": phone, "format": 1},
            timeout=15
        )
        data = r.json()
        print(f"[OSINT] Phone: {data.get('carrier')} / {data.get('country_name')}")
        return {"available": True, "valid": data.get("valid"),
                "number": data.get("number"),
                "international": data.get("international_format"),
                "country": data.get("country_name"),
                "location": data.get("location"),
                "carrier": data.get("carrier"),
                "line_type": data.get("line_type")}
    except Exception as e:
        print(f"[OSINT] NumVerify error: {e}")
        return {"available": False, "note": str(e)}


def social_media_search(name: str) -> list:
    parts = name.lower().split()
    usernames = []
    if len(parts) >= 2:
        usernames = [
            parts[0] + parts[1],
            parts[0] + "." + parts[1],
            parts[0][0] + parts[1],
            parts[0],
        ]
    elif parts:
        usernames = [parts[0]]

    found = []
    for username in usernames[:2]:
        print(f"[OSINT] Sherlock: searching '{username}'")
        try:
            result = subprocess.run(
                ["sherlock", username, "--print-found", "--no-color", "--timeout", "10"],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split("\n"):
                if "[+]" in line:
                    match = re.search(r'https?://\S+', line)
                    if match:
                        found.append({"username": username, "url": match.group(0)})
        except FileNotFoundError:
            print("[OSINT] Sherlock not installed — run: pip install sherlock-project")
            break
        except Exception as e:
            print(f"[OSINT] Sherlock error: {e}")

    seen, unique = set(), []
    for p in found:
        if p["url"] not in seen:
            seen.add(p["url"])
            unique.append(p)
    print(f"[OSINT] Sherlock: {len(unique)} profiles found")
    return unique[:15]


def run_osint_scan(name: str, email: str, phone: str = None) -> dict:
    print(f"\n[OSINT] ═══ Starting full scan: {name} / {email} ═══")
    google_results = google_dork_search(name, email)
    email_sites    = check_email_registrations(email)
    breach_data    = check_email_breach(email)
    shodan_data    = shodan_lookup(email)
    hunter_data    = hunter_email_lookup(email)
    phone_data     = phone_lookup(phone)
    social_data    = social_media_search(name)
    print(f"[OSINT] ═══ Scan complete ═══\n")
    return {
        "name": name, "email": email, "phone": phone,
        "google_mentions": google_results,
        "registered_sites": email_sites,
        "breach_data": breach_data,
        "shodan_data": shodan_data,
        "hunter_data": hunter_data,
        "phone_data":  phone_data,
        "social_data": social_data,
    }