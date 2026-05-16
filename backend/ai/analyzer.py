import httpx
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"

def analyze_with_ai(osint_data: dict) -> dict:
    """Send OSINT findings to local Ollama model for risk analysis."""

    prompt = f"""
You are a cybersecurity OSINT analyst. Analyze the following data about a person 
and produce a structured risk report.

OSINT DATA:
- Name: {osint_data['name']}
- Email: {osint_data['email']}
- Phone: {osint_data.get('phone', 'Not provided')}
- Google public mentions found: {len(osint_data['google_mentions'])} URLs
- URLs: {', '.join(osint_data['google_mentions'][:5])}
- Email registered on sites: {', '.join(osint_data['registered_sites']) or 'None found'}
- Data breach info: {json.dumps(osint_data['breach_data'])}

Respond ONLY in this exact JSON format, no extra text:
{{
  "risk_score": "Low | Medium | High | Critical",
  "risk_reasons": ["reason 1", "reason 2", "reason 3"],
  "digital_footprint": "Brief summary of their online presence",
  "breach_summary": "Summary of breach exposure",
  "recommendations": ["recommendation 1", "recommendation 2"],
  "ai_summary": "One paragraph overall risk assessment"
}}
"""

    try:
        response = httpx.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=120  # Ollama can be slow on first run
        )
        raw = response.json()["response"].strip()

        # Strip markdown code fences if model adds them
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        return json.loads(raw)

    except Exception as e:
        print(f"AI analysis error: {e}")
        return {
            "risk_score": "Unknown",
            "risk_reasons": ["AI analysis failed"],
            "digital_footprint": "Unable to analyze",
            "breach_summary": "Unable to analyze",
            "recommendations": ["Try again later"],
            "ai_summary": f"AI analysis failed: {str(e)}"
        }