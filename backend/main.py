from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request
from database.db import insert_user
from osint.scanner import run_osint_scan
from ai.analyzer import analyze_with_ai
import os

app = FastAPI()

# ------------CORS---------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------CSP header (fixes inline style blocked error)
@app.middleware("http")
async def add_csp_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline';"
        "style-src 'self' 'unsafe-inline';"
    )
    return response

# Serve frontend folder as static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")

# Define model BEFORE it is used
class UserData(BaseModel):
    name: str
    email: str
    phone: str | None = None

# Define all routes BEFORE app.mount
@app.get("/")
def serve_frontend():
    return FileResponse(os.path.join(frontend_path, "index.html"))


@app.post("/scan-risk")
async def scan_risk(user: UserData):
    print(f"[API] Scan request for {user.name} / {user.email}")

    # 1. Save to database
    try:
        insert_user(user.name, user.email, user.phone)
        print("INSERT SUCCESS")
    except Exception as e:
        print("MAIN ERROR:", e)
    
    # 2. Run OSINT scan
    print("[OSINT] Starting scan...")
    osint_data = run_osint_scan(user.name, user.email, user.phone)
    print("[OSINT] Scan complete")

    # 3. AI analysis
    print("[AI] Starting analysis...")
    ai_report = analyze_with_ai(osint_data)
    print("[AI] Analysis complete")

    # 4. Return combined report to frontend
    return {
        "message": "Scan complete",
        "name": user.name,
        "email": user.email,
        "risk_score": ai_report.get("risk_score", "Unknown"),
        "ai_summary": ai_report.get("ai_summary", "No summary avaialble"),
        "digital_foorprint": ai_report.get("digital_footprint") or "No footprint data available",
        "breach_summary": ai_report.get("breach_summary") or "No breach data available",
        "risk_reasons": ai_report.get("risk_reasons", []),
        "recommendations": ai_report.get("recommendations", []),
        "google_mentions": osint_data.get("google_mentions", []),
        "registered_sites": osint_data.get("registered_sites", []),
        "breach_data": osint_data.get("breach_data, {}"), 
    }

# Mount After defining routes, with "/" so css/js paths match index.html
app.mount("/", StaticFiles(directory=frontend_path), name="static")
