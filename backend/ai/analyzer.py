import httpx
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"

def analyze_with_ai(osint_data: dict) -> dict:
    """Send OSINT findings to local Ollama model for risk analysis."""

    breach = osint_data.get("breach_data", {})
    breached    = breach.get("breached", "unknown")
    breach_list = breach.get("breaches", [])
    sites       = osint_data.get("registered_sites", [])
    urls        = osint_data.get("google_mentions", [])
 
    prompt = f"""You are a cybersecurity OSINT analyst. Analyze the data below and return a JSON risk report.
 
OSINT FINDINGS:
- Name: {osint_data.get("name")}
- Email: {osint_data.get("email")}
- Phone: {osint_data.get("phone") or "Not provided"}
- Public URLs found on Google: {len(urls)}
- Sample URLs: {", ".join(urls[:5]) if urls else "None"}
- Email registered on sites (via holehe): {", ".join(sites) if sites else "None found"}
- Known data breaches (HaveIBeenPwned): breached={breached}, count={breach.get("count", 0)}, services={", ".join(breach_list) if breach_list else "None"}
 
Respond ONLY with a valid JSON object — no explanation, no markdown, no code fences. Use exactly these keys:
{{
  "risk_score": "Low or Medium or High or Critical",
  "risk_reasons": ["reason 1", "reason 2", "reason 3"],
  "digital_footprint": "2-3 sentence summary of their online presence based on the data",
  "breach_summary": "Summary of their breach exposure and what it means",
  "recommendations": ["action 1", "action 2", "action 3"],
  "ai_summary": "One paragraph overall risk assessment written for a non-technical audience"
}}"""
 
    print(f"[AI] Sending prompt to Ollama ({MODEL})...")
 
    try:
        response = httpx.post(
            OLLAMA_URL,
            json={
                "model":  MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,   # lower = more consistent JSON output
                    "num_predict": 800
                }
            },
            timeout=180  # Ollama can be slow on first inference
        )
 
        raw = response.json().get("response", "").strip()
        print(f"[AI] Raw response received ({len(raw)} chars)")
 
        # Strip markdown code fences if model wraps output in ```json ... ```
        if "```" in raw:
            parts = raw.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    raw = part
                    break
 
        # Find the first { and last } to extract clean JSON
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start != -1 and end > start:
            raw = raw[start:end]
 
        result = json.loads(raw)
        print("[AI] JSON parsed successfully")
        return result
 
    except json.JSONDecodeError as e:
        print(f"[AI] JSON parse error: {e}")
        print(f"[AI] Raw was: {raw[:300]}")
        return _fallback("AI returned invalid JSON — try again")
 
    except httpx.ConnectError:
        print("[AI] Cannot connect to Ollama — is it running?")
        return _fallback("Cannot connect to Ollama. Make sure Ollama is running (check system tray).")
 
    except Exception as e:
        print(f"[AI] Unexpected error: {e}")
        return _fallback(str(e))
 
 
def _fallback(reason: str) -> dict:
    return {
        "risk_score":        "Unknown",
        "risk_reasons":      [f"AI analysis failed: {reason}"],
        "digital_footprint": "AI analysis was not completed.",
        "breach_summary":    "AI analysis was not completed.",
        "recommendations":   ["Ensure Ollama is running", "Restart uvicorn and try again"],
        "ai_summary":        f"AI analysis failed. Reason: {reason}"
    }