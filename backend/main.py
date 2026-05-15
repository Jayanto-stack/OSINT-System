from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from database.db import insert_user
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    print("API HIT")
    try:
        insert_user(user.name, user.email, user.phone)
        print("INSERT SUCCESS")
    except Exception as e:
        print("MAIN ERROR:", e)

    return {
        "message": "Data received successfully",
        "name": user.name,
        "email": user.email,
        "risk_score": "Medium",
        "ai_summary": "Public email exposure detected."
    }

# Mount After defining routes, with "/" so css/js paths match index.html
app.mount("/", StaticFiles(directory=frontend_path), name="static")
