import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Pdf, Checkup, Session

app = FastAPI(title="MediLearn Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers

def oid(oid_str: str) -> ObjectId:
    try:
        return ObjectId(oid_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


# Auth dependencies
class TokenData(BaseModel):
    user_id: str
    role: str


def get_current_user(authorization: Optional[str] = Header(default=None)) -> TokenData:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session.get("expires_at") and session["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")
    user = db["user"].find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenData(user_id=str(user["_id"]), role=user.get("role", "user"))


def require_admin(user: TokenData = Depends(get_current_user)) -> TokenData:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# Models for requests
class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    role: Optional[str] = "user"


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user: Dict[str, Any]


class PdfCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    url: str
    tags: Optional[List[str]] = None


class CheckupCreateRequest(BaseModel):
    patient_name: Optional[str] = None
    department: Optional[str] = None
    notes: Optional[str] = None
    date: Optional[datetime] = None


# Root & health
@app.get("/")
def read_root():
    return {"message": "MediLearn Backend Running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": os.getenv("DATABASE_NAME") or "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        collections = db.list_collection_names() if db is not None else []
        response["database"] = "✅ Connected & Working" if collections is not None else "❌ Not Available"
        response["connection_status"] = "Connected" if collections is not None else "Not Connected"
        response["collections"] = collections[:10]
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"
    return response


# Bootstrap admin: only allowed if no admin exists yet
class SetupAdminRequest(BaseModel):
    name: str = Field("Admin")
    email: str = Field(...)
    password: str = Field(...)


@app.post("/setup/admin")
def setup_admin(body: SetupAdminRequest):
    existing_admin = db["user"].find_one({"role": "admin"})
    if existing_admin:
        raise HTTPException(status_code=400, detail="Admin already exists")
    user_doc = User(name=body.name, email=body.email, password_hash=hash_password(body.password), role="admin", is_active=True)
    uid = create_document("user", user_doc)
    return {"message": "Admin created", "user_id": uid}


# Auth endpoints
@app.post("/auth/register")
def register(body: RegisterRequest):
    if db["user"].find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    role = body.role if body.role in ("admin", "user") else "user"
    user_doc = User(name=body.name, email=body.email, password_hash=hash_password(body.password), role=role, is_active=True)
    uid = create_document("user", user_doc)
    return {"message": "Registered", "user_id": uid}


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest):
    user = db["user"].find_one({"email": body.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("password_hash") != hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = new_token()
    session = Session(user_id=str(user["_id"]), token=token, expires_at=datetime.now(timezone.utc) + timedelta(days=7))
    create_document("session", session)
    user_sanitized = {"_id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"), "role": user.get("role", "user")}
    return {"token": token, "user": user_sanitized}


# PDF Library
@app.get("/pdfs")
def list_pdfs():
    items = get_documents("pdf", {})
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.post("/pdfs")
def create_pdf(body: PdfCreateRequest, _: TokenData = Depends(require_admin)):
    pdf = Pdf(title=body.title, description=body.description, url=body.url, tags=body.tags)
    pid = create_document("pdf", pdf)
    return {"message": "PDF added", "id": pid}


@app.delete("/pdfs/{pdf_id}")
def delete_pdf(pdf_id: str, _: TokenData = Depends(require_admin)):
    result = db["pdf"].delete_one({"_id": oid(pdf_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="PDF not found")
    return {"message": "Deleted"}


# Patient Checkups & Analytics
@app.post("/checkups")
def create_checkup(body: CheckupCreateRequest, _: TokenData = Depends(require_admin)):
    data = {
        "patient_name": body.patient_name,
        "department": body.department,
        "notes": body.notes,
        "date": body.date or datetime.now(timezone.utc),
    }
    cid = create_document("checkup", data)
    return {"message": "Recorded", "id": cid}


@app.get("/checkups")
def list_checkups(limit: int = 50):
    cur = db["checkup"].find({}).sort("date", -1).limit(limit)
    items = []
    for d in cur:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("date"), datetime):
            d["date"] = d["date"].isoformat()
        items.append(d)
    return items


@app.get("/analytics/weekly")
def analytics_weekly():
    # Aggregate last 7 days grouped by weekday
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    pipeline = [
        {"$match": {"date": {"$gte": seven_days_ago}}},
        {"$project": {"dow": {"$dayOfWeek": "$date"}}},  # 1=Sunday..7=Saturday
        {"$group": {"_id": "$dow", "count": {"$sum": 1}}},
    ]
    agg = list(db["checkup"].aggregate(pipeline))
    # Map to Mon..Sun order
    order = [2, 3, 4, 5, 6, 7, 1]
    labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    counts_map = {a["_id"]: a["count"] for a in agg}
    data = [{"label": labels[i], "value": int(counts_map.get(order[i], 0))} for i in range(7)]
    return {"range": "last_7_days", "data": data}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
