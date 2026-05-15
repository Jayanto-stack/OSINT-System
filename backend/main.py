from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from database.db import insert_user

# Create FastAPI app
app = FastAPI()

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# User data model
class UserData(BaseModel):
    name: str
    email: str
    phone: str | None = None


# API endpoint
@app.post("/scan-risk")
async def scan_risk(user: UserData):
    print("API HIT")

    # Save into database
    try:
        insert_user(user.name, user.email, user.phone)
        print("INSERT SUCCESS")
    
    except Exception as e:
        print("MAIN ERROR:", e)

    # Temporary fake response
    return {
        "message": "Data received successfully",
        "name": user.name,
        "email": user.email,
        "risk_score": "Medium",
        "ai_summary": "Public email exposure detected."
    }