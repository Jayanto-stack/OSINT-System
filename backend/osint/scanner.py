import httpx
from googlesearch import search
import subprocess
import json

# ── 1. Google Dork Search ──────────────────────────────────────────
def google_dork_search(name: str, email: str) -> list:
    """Search Google for public mentions of the person."""
    queries = [
        f'"{name}"',
        f'"{email}"',
        f'"{name}" site:linkedin.com OR site:twitter.com OR site:facebook.com',
        f'"{email}" leaked OR breach OR database',
    ]
    results = []
    for query in queries:
        try:
            hits = list(search(query, num_results=3, sleep_interval=2))
            results.extend(hits)
        except Exception as e:
            print(f"Google search error: {e}")
    return list(set(results))  # deduplicate


# ── 2. Email Registration Check (Holehe) ──────────────────────────
def check_email_registrations(email: str) -> list:
    """Check which websites the email is registered on using holehe."""
    try:
        result = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=60
        )
        lines = result.stdout.strip().split("\n")
        # Parse holehe output — lines with [+] mean account found
        found = [l.strip() for l in lines if "[+]" in l]
        return found
    except Exception as e:
        print(f"Holehe error: {e}")
        return []


# ── 3. Have I Been Pwned — breach check ───────────────────────────
def check_email_breach(email: str) -> dict:
    """Check HaveIBeenPwned API for data breaches."""
    try:
        headers = {"User-Agent": "OSINT-RiskTool"}
        r = httpx.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, timeout=10
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "breached": True,
                "count": len(breaches),
                "breaches": [b["Name"] for b in breaches[:5]]  # top 5
            }
        elif r.status_code == 404:
            return {"breached": False, "count": 0, "breaches": []}
        else:
            return {"breached": "unknown", "count": 0, "breaches": []}
    except Exception as e:
        print(f"HIBP error: {e}")
        return {"breached": "unknown", "count": 0, "breaches": []}


# ── 4. Full OSINT Scan ─────────────────────────────────────────────
def run_osint_scan(name: str, email: str, phone: str = None) -> dict:
    print(f"[OSINT] Starting scan for {name} / {email}")

    google_results = google_dork_search(name, email)
    email_sites    = check_email_registrations(email)
    breach_data    = check_email_breach(email)

    return {
        "name": name,
        "email": email,
        "phone": phone,
        "google_mentions": google_results,
        "registered_sites": email_sites,
        "breach_data": breach_data,
    }