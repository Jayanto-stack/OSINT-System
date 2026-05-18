import httpx
import json
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL      = "llama3"


def analyze_with_ai(osint_data: dict) -> dict:
    """Send OSINT findings to local Ollama for structured risk analysis."""

    breach      = osint_data.get("breach_data", {})
    breached    = breach.get("breached", "unknown")
    breach_list = breach.get("breaches", [])
    sites       = osint_data.get("registered_sites", [])
    urls        = osint_data.get("google_mentions", [])

    # Clean holehe output — strips "[+] spotify.com" → "spotify.com"
    clean_sites = []
    for s in sites:
        match = re.search(r'\[.\]\s*(\S+)', s.strip())
        if match:
            clean_sites.append(match.group(1))
        elif s.strip():
            clean_sites.append(s.strip())

    prompt = f"""You are a cybersecurity OSINT analyst. Analyze this data and return a JSON risk report.

DATA:
Name: {osint_data.get("name")}
Email: {osint_data.get("email")}
Phone: {osint_data.get("phone") or "Not provided"}
Public URLs found: {len(urls)}
Sample URLs: {", ".join(urls[:3]) if urls else "None"}
Email registered on: {", ".join(clean_sites) if clean_sites else "None found"}
Data breaches: breached={breached}, count={breach.get("count", 0)}, services={", ".join(breach_list) if breach_list else "None"}

Return ONLY this JSON, nothing else, No explanation. No markdown. Keep all values under 30 words each:
{{
  "risk_score": "Medium",
  "risk_reasons": ["reason one", "reason two"],
  "digital_footprint": "summary here",
  "breach_summary": "breach info here",
  "recommendations": ["action one", "action two"],
  "ai_summary": "overall summary here"
}}"""

    print(f"[AI] Sending to Ollama ({MODEL})...")

    try:
        response = httpx.post(
            OLLAMA_URL,
            json={
                "model":  MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 1200
                }
            },
            timeout=180
        )

        raw = response.json().get("response", "").strip()
        print(f"[AI] Raw response ({len(raw)} chars):")
        print(raw[:500])

        result = extract_json(raw)

        # Ensure digital_footprint always has a value even if Ollama skips it
        if result:
            print("[AI] JSON extracted successfully")
            # Guarantee digital_footprint is never empty
            if not result.get("digital_footprint"):
                result["digital_footprint"] = build_manual_report(
                    osint_data, clean_sites, breached, breach_list
                    )["digital_footprint"]
            
            if not result.get("breach_summary"):
                result["breach_summary"] = build_manual_report(
                    osint_data, clean_sites, breached, breach_list
                    )["breach_summary"]
                return result
        else:
            print("[AI] Could not extract JSON - building mnaual report")
            return build_manual_report(osint_data, clean_sites, breached, breach_list)

    except httpx.ConnectError:
        print("[AI] Cannot connect to Ollama")
        return _fallback("Cannot connect to Ollama. Make sure Ollama is running.")
    except Exception as e:
        print(f"[AI] Unexpected error: {e}")
        return build_manual_report(osint_data, clean_sites, breached, breach_list)


def extract_json(raw: str) -> dict | None:
    """Try multiple strategies to extract valid JSON from Ollama output."""

    # Strategy 1: direct parse
    try:
        return json.loads(raw)
    except Exception:
        pass

    # Strategy 2: strip markdown code fences
    cleaned = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Strategy 3: find first { to last }
    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start != -1 and end > start:
        candidate = raw[start:end]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Strategy 4: fix trailing commas and single quotes
    try:
        candidate = raw[raw.find("{"):raw.rfind("}")+1]
        candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
        candidate = candidate.replace("'", '"')
        return json.loads(candidate)
    except Exception:
        pass

    return None


def build_manual_report(osint_data: dict, clean_sites: list,
                         breached, breach_list: list) -> dict:
    """
    Build a meaningful report directly from OSINT data
    when AI JSON parsing fails — user always gets useful output.
    """
    name  = osint_data.get("name", "Unknown")
    email = osint_data.get("email", "Unknown")
    urls  = osint_data.get("google_mentions", [])

    risk_points  = 0
    risk_reasons = []

    if len(urls) > 5:
        risk_points += 2
        risk_reasons.append(f"Found {len(urls)} public mentions online")
    elif len(urls) > 0:
        risk_points += 1
        risk_reasons.append(f"Found {len(urls)} public URLs mentioning this identity")

    if clean_sites:
        risk_points += 1
        risk_reasons.append(
            f"Email registered on {len(clean_sites)} platforms: {', '.join(clean_sites[:4])}"
        )

    if breached is True:
        risk_points += 3
        risk_reasons.append(
            f"Email found in {osint_data['breach_data'].get('count', '?')} known data breaches"
        )
    elif breached == "unknown":
        risk_reasons.append("Breach status could not be checked (HIBP API key needed)")

    if not risk_reasons:
        risk_reasons.append("Limited public data found — low online exposure")

    if risk_points >= 5:   score = "Critical"
    elif risk_points >= 3: score = "High"
    elif risk_points >= 1: score = "Medium"
    else:                  score = "Low"

    footprint = (
        f"{name} has a {'significant' if len(urls) > 3 else 'moderate' if urls else 'minimal'} "
        f"online presence. "
        f"{'Found on ' + str(len(clean_sites)) + ' platforms including ' + ', '.join(clean_sites[:3]) + '.' if clean_sites else 'No platform registrations detected.'} "
        f"{str(len(urls)) + ' public URLs were found via Google.' if urls else 'No Google results found.'}"
    )

    if breached is True:
        breach_summary = (
            f"This email appeared in {osint_data['breach_data'].get('count', '?')} known data breaches"
            + (f", including: {', '.join(breach_list)}." if breach_list else ".")
            + " Change all associated passwords immediately."
        )
    elif breached is False:
        breach_summary = "No known data breaches found for this email address."
    else:
        breach_summary = "Breach status unknown — a HaveIBeenPwned API key is needed for this check."

    recommendations = [
        "Review and audit your public social media profiles",
        "Enable two-factor authentication on all registered platforms",
        "Use a password manager with unique passwords per site",
    ]
    if breached is True:
        recommendations.insert(0, "Change passwords immediately for all breached services")

    return {
        "risk_score":        score,
        "risk_reasons":      risk_reasons,
        "digital_footprint": footprint,
        "breach_summary":    breach_summary,
        "recommendations":   recommendations,
        "ai_summary": (
            f"{name} ({email}) has a {score.lower()} digital risk profile. "
            f"{footprint} {breach_summary}"
        )
    }


def _fallback(reason: str) -> dict:
    return {
        "risk_score":        "Unknown",
        "risk_reasons":      [reason],
        "digital_footprint": "Analysis not completed.",
        "breach_summary":    "Analysis not completed.",
        "recommendations":   ["Ensure Ollama is running", "Restart uvicorn and try again"],
        "ai_summary":        f"Analysis failed: {reason}"
    }