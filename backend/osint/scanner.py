import httpx
import subprocess
import re

try:
    from googlesearch import search as google_search
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False
    print("[OSINT] googlesearch-python not installed — Google search disabled")

# ─────────────────────────────────────────────────────────────────────
# API KEYS — fill these in
# HIBP key: sign up free at https://haveibeenpwned.com/API/Key ($3.50/month)
# Without it, breach check is skipped (everything else still works)
# HIBP_API_KEY = ""   # paste your key here e.g. "abc123xyz..."
# ─────────────────────────────────────────────────────────────────────


def google_dork_search(name: str, email: str) -> list:
    """Search Google for public mentions of the person."""
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
            print(f"[OSINT] Google done: {query[:60]}")
        except Exception as e:
            print(f"[OSINT] Google error (rate limit?): {e}")
    return list(set(results))


def check_email_registrations(email: str) -> list:
    """Check which websites the email is registered on using holehe."""
    try:
        result = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=90
        )
        lines = result.stdout.strip().split("\n")
        # Return all meaningful lines — app.js will filter [+] only
        filtered = [
            l.strip() for l in lines
            if ("[+]" in l or "[-]" in l or "[x]" in l)
            and l.strip()
        ]
        print(f"[OSINT] Holehe: {len([l for l in filtered if '[+]' in l])} registrations found")
        return filtered
    except FileNotFoundError:
        print("[OSINT] holehe not found — run: pip install holehe")
        return []
    except Exception as e:
        print(f"[OSINT] Holehe error: {e}")
        return []


def check_email_breach(email: str) -> dict:
    """Check LeakCheck.io for breaches — free tier available."""
    LEAKCHECK_KEY = "ee514546e62bff550cea0f73de2eea53f4e754ec"
    try:
        r = httpx.get(
            f"https://leakcheck.io/api/public?check={email}&key={LEAKCHECK_KEY}",
            timeout=15
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            sources = [s.get("name", "Unknown") for s in data.get("sources", [])[:5]]
            print(f"[OSINT] LeakCheck: {data['found']} breaches found")
            return {"breached": True, "count": data["found"], "breaches": sources}
        else:
            print("[OSINT] LeakCheck: no breaches found")
            return {"breached": False, "count": 0, "breaches": []}
    except Exception as e:
        print(f"[OSINT] LeakCheck error: {e}")
        return {"breached": "unknown", "count": 0, "breaches": []}

def run_osint_scan(name: str, email: str, phone: str = None) -> dict:
    print(f"[OSINT] ── Starting scan: {name} / {email} ──")

    google_results = google_dork_search(name, email)
    email_sites    = check_email_registrations(email)
    breach_data    = check_email_breach(email)

    # Count only [+] registrations for summary
    found_sites = [l for l in email_sites if "[+]" in l]
    print(f"[OSINT] ── Done: {len(google_results)} URLs, "
          f"{len(found_sites)} site registrations, "
          f"breached={breach_data.get('breached')} ──")

    return {
        "name":             name,
        "email":            email,
        "phone":            phone,
        "google_mentions":  google_results,
        "registered_sites": email_sites,
        "breach_data":      breach_data,
    }