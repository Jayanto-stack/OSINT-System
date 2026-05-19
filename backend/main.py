from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from database.db import insert_user, insert_scan_report, get_all_scans, get_scan_by_id, get_risk_trend
from osint.scanner import run_osint_scan
from ai.analyzer import analyze_with_ai
import os
import traceback

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_csp_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline';"
    )
    return response

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")

class UserData(BaseModel):
    name: str
    email: str
    phone: str | None = None


# ── Serve frontend ───────────────────────────────────────────────────
@app.get("/")
def serve_frontend():
    return FileResponse(os.path.join(frontend_path, "index.html"))

@app.get("/history")
def serve_history():
    return FileResponse(os.path.join(frontend_path, "history.html"))


# ── Main scan endpoint ───────────────────────────────────────────────
@app.post("/scan-risk")
async def scan_risk(user: UserData):
    print(f"\n[API] Scan request: {user.name} / {user.email}")

    # Save user
    try:
        user_id = insert_user(user.name, user.email, user.phone)
    except Exception as e:
        print("[DB] User insert error:", e)
        user_id = None

    # Run OSINT + AI
    try:
        osint_data = run_osint_scan(user.name, user.email, user.phone)
        ai_report  = analyze_with_ai(osint_data)
    except Exception as e:
        traceback.print_exc()
        ai_report  = {
            "risk_score": "Unknown", "ai_summary": f"Analysis error: {e}",
            "digital_footprint": "Error", "breach_summary": "Error",
            "risk_reasons": [str(e)], "recommendations": ["Check terminal"]
        }
        osint_data = {
            "google_mentions": [], "registered_sites": [], "breach_data": {},
            "shodan_data": {}, "hunter_data": {}, "phone_data": {}, "social_data": []
        }

    # Build full report
    report = {
        "name":              user.name,
        "email":             user.email,
        "phone":             user.phone,
        "risk_score":        ai_report.get("risk_score", "Unknown"),
        "ai_summary":        ai_report.get("ai_summary") or "No summary",
        "digital_footprint": ai_report.get("digital_footprint") or "Not available",
        "breach_summary":    ai_report.get("breach_summary") or "Not available",
        "risk_reasons":      ai_report.get("risk_reasons") or [],
        "recommendations":   ai_report.get("recommendations") or [],
        "google_mentions":   osint_data.get("google_mentions", []),
        "registered_sites":  osint_data.get("registered_sites", []),
        "breach_data":       osint_data.get("breach_data", {}),
        "shodan_data":       osint_data.get("shodan_data", {}),
        "hunter_data":       osint_data.get("hunter_data", {}),
        "phone_data":        osint_data.get("phone_data", {}),
        "social_data":       osint_data.get("social_data", []),
    }

    # Save full report to DB
    try:
        if user_id:
            insert_scan_report(user_id, report)
    except Exception as e:
        print("[DB] Report save error:", e)

    return report


# ── Scan history ─────────────────────────────────────────────────────
@app.get("/api/scans")
def list_scans():
    return get_all_scans()

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return {"error": "Scan not found"}
    return scan

@app.get("/api/trend")
def risk_trend(email: str):
    return get_risk_trend(email)


# ── Static files (MUST be last) ──────────────────────────────────────
app.mount("/", StaticFiles(directory=frontend_path), name="static")