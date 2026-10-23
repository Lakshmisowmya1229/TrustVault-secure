import os
import sqlite3
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("TRUSTVAULT_DB", APP_DIR / "trustvault.db"))
STORAGE_DIR = Path(os.getenv("TRUSTVAULT_STORAGE", APP_DIR / "private_files"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Set TRUSTVAULT_SECRET to a long random value before deployment.
SECRET_KEY = os.getenv("TRUSTVAULT_SECRET", "DEV-ONLY-change-this-secret-before-deployment")
ALGORITHM = "HS256"
TOKEN_MINUTES = 30
MAX_FILE_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".docx"}
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
app = FastAPI(title="TrustVault API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5174",
        "https://your-actual-vercel-domain.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            storage_name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL DEFAULT 'General',
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS grants (
            document_id TEXT NOT NULL REFERENCES documents(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
            created_at TEXT NOT NULL,
            PRIMARY KEY(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_id INTEGER,
            document_id TEXT,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        """)
        # Development seed accounts. Change these passwords before any shared deployment.
        seeds = [
            ("admin", "Admin-ChangeMe-123!", "admin"),
            ("owner", "Owner-ChangeMe-123!", "owner"),
            ("viewer", "Viewer-ChangeMe-123!", "viewer"),
        ]
        for username, password, role in seeds:
            exists = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not exists:
                db.execute(
                    "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                    (username, password_hash.hash(password), role),
                )


@app.on_event("startup")
def startup():
    init_db()


def append_audit(actor_id: Optional[int], document_id: Optional[str], action: str,
                 outcome: str, details: dict):
    """Append a hash-chained event. This detects casual edits, not a DB owner rewriting the whole chain."""
    with connect() as db:
        last = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = last["event_hash"] if last else "GENESIS"
        timestamp = now_iso()
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
        material = "|".join([
            timestamp, str(actor_id), str(document_id), action, outcome,
            details_json, previous_hash
        ])
        event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
        db.execute("""
            INSERT INTO audit_events(timestamp,actor_id,document_id,action,outcome,details,previous_hash,event_hash)
            VALUES(?,?,?,?,?,?,?,?)
        """, (timestamp, actor_id, document_id, action, outcome, details_json, previous_hash, event_hash))


def fail(actor_id, document_id, action, status=403):
    append_audit(actor_id, document_id, action, "denied", {"reason": "not_found_or_not_authorized"})
    # Avoid revealing whether another user's document exists.
    raise HTTPException(status_code=status, detail="Document not found or access denied")


def get_user_by_name(username):
    with connect() as db:
        return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user or not user["active"]:
        raise HTTPException(status_code=401, detail="Inactive account")
    return user


def can_read(db, user, document_id):
    doc = db.execute("SELECT * FROM documents WHERE id=? AND deleted=0", (document_id,)).fetchone()
    if not doc:
        return None, False
    if doc["owner_id"] == user["id"]:
        return doc, True
    grant = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                       (document_id, user["id"])).fetchone()
    # Admins do not automatically bypass document permissions.
    return doc, bool(grant and grant["permission"] in ("read", "edit"))


def can_edit(db, user, document_id):
    doc = db.execute("SELECT * FROM documents WHERE id=? AND deleted=0", (document_id,)).fetchone()
    if not doc:
        return None, False
    if doc["owner_id"] == user["id"]:
        return doc, True
    grant = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                       (document_id, user["id"])).fetchone()
    return doc, bool(grant and grant["permission"] == "edit")


class GrantRequest(BaseModel):
    username: str
    permission: str = Field(pattern="^(read|edit)$")


class CategoryUpdate(BaseModel):
    category: str = Field(min_length=1, max_length=80)


@app.get("/")
def root():
    return {"app": "TrustVault", "docs": "/docs", "note": "Development prototype; read README before use."}


@app.post("/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_name(form.username)
    if not user or not password_hash.verify(form.password, user["password_hash"]) or not user["active"]:
        append_audit(user["id"] if user else None, None, "login", "denied", {"username": form.username})
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    expires = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)
    token = jwt.encode({"sub": str(user["id"]), "exp": expires}, SECRET_KEY, algorithm=ALGORITHM)
    append_audit(user["id"], None, "login", "allowed", {})
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_MINUTES * 60}


@app.get("/me")
def me(user=Depends(current_user)):
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


@app.post("/documents")
async def upload_document(
    file: UploadFile = File(...),
    category: str = Form("General"),
    user=Depends(current_user),
):
    original_name = Path(file.filename or "upload.bin").name
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        append_audit(user["id"], None, "upload", "denied", {"filename": original_name, "reason": "extension"})
        raise HTTPException(400, "File type not allowed")
    if not category.strip() or len(category) > 80:
        raise HTTPException(400, "Category must be 1-80 characters")
    content = await file.read(MAX_FILE_BYTES + 1)
    if not content or len(content) > MAX_FILE_BYTES:
        append_audit(user["id"], None, "upload", "denied", {"filename": original_name, "reason": "size_or_empty"})
        raise HTTPException(400, "File must be non-empty and at most 10 MB")
    # Extension allowlisting is only a basic validation. Production should inspect MIME/magic bytes
    # and malware-scan uploads before making them available.
    doc_id = secrets.token_urlsafe(16)
    storage_name = secrets.token_hex(24) + suffix
    digest = hashlib.sha256(content).hexdigest()
    target = STORAGE_DIR / storage_name
    target.write_bytes(content)
    try:
        with connect() as db:
            db.execute("""INSERT INTO documents(id,owner_id,original_name,storage_name,category,sha256,size,created_at)
                          VALUES(?,?,?,?,?,?,?,?)""",
                       (doc_id, user["id"], original_name, storage_name, category.strip(),
                        digest, len(content), now_iso()))
    except Exception:
        target.unlink(missing_ok=True)
        raise
    append_audit(user["id"], doc_id, "upload", "allowed",
                 {"filename": original_name, "size": len(content), "sha256": digest})
    return {"id": doc_id, "name": original_name, "category": category.strip(), "size": len(content)}


@app.get("/documents")
def list_documents(
    q: str = "",
    owner: str = "",
    category: str = "",
    user=Depends(current_user),
):
    # Query is limited to documents the caller owns or has a current grant for.
    with connect() as db:
        rows = db.execute("""
            SELECT DISTINCT d.*, u.username AS owner_name
            FROM documents d JOIN users u ON u.id=d.owner_id
            LEFT JOIN grants g ON g.document_id=d.id AND g.user_id=?
            WHERE d.deleted=0 AND (d.owner_id=? OR g.user_id IS NOT NULL)
              AND lower(d.original_name) LIKE lower(?)
              AND lower(u.username) LIKE lower(?)
              AND lower(d.category) LIKE lower(?)
            ORDER BY d.created_at DESC
        """, (user["id"], user["id"], f"%{q}%", f"%{owner}%", f"%{category}%")).fetchall()
    return [{
        "id": r["id"], "name": r["original_name"], "owner": r["owner_name"],
        "category": r["category"], "size": r["size"], "created_at": r["created_at"]
    } for r in rows]


@app.get("/documents/{document_id}")
def get_document(document_id: str, user=Depends(current_user)):
    with connect() as db:
        doc, allowed = can_read(db, user, document_id)
    if not allowed:
        fail(user["id"], document_id, "read_metadata", 404)
    append_audit(user["id"], document_id, "read_metadata", "allowed", {})
    return {"id": doc["id"], "name": doc["original_name"], "owner_id": doc["owner_id"],
            "category": doc["category"], "size": doc["size"], "sha256": doc["sha256"],
            "created_at": doc["created_at"]}


@app.get("/documents/{document_id}/download")
def download_document(document_id: str, user=Depends(current_user)):
    with connect() as db:
        doc, allowed = can_read(db, user, document_id)
    if not allowed:
        fail(user["id"], document_id, "download", 404)
    path = STORAGE_DIR / doc["storage_name"]
    if not path.is_file():
        append_audit(user["id"], document_id, "download", "error", {"reason": "storage_missing"})
        raise HTTPException(410, "Stored file is unavailable")
    append_audit(user["id"], document_id, "download", "allowed", {"sha256": doc["sha256"]})
    return FileResponse(path, filename=doc["original_name"], media_type="application/octet-stream")


@app.patch("/documents/{document_id}")
def update_document(document_id: str, payload: CategoryUpdate, user=Depends(current_user)):
    with connect() as db:
        doc, allowed = can_edit(db, user, document_id)
        if allowed:
            db.execute("UPDATE documents SET category=? WHERE id=?", (payload.category.strip(), document_id))
    if not allowed:
        fail(user["id"], document_id, "edit_metadata", 404)
    append_audit(user["id"], document_id, "edit_metadata", "allowed", {"category": payload.category.strip()})
    return {"status": "updated", "category": payload.category.strip()}


@app.post("/documents/{document_id}/grants")
def grant_access(document_id: str, payload: GrantRequest, user=Depends(current_user)):
    with connect() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND deleted=0", (document_id,)).fetchone()
        if not doc or doc["owner_id"] != user["id"]:
            allowed = False
            target = None
        else:
            allowed = True
            target = db.execute("SELECT * FROM users WHERE username=? AND active=1",
                                (payload.username,)).fetchone()
            if not target:
                allowed = False
    if not allowed:
        fail(user["id"], document_id, "grant_access", 404)
    with connect() as db:
        db.execute("""INSERT INTO grants(document_id,user_id,permission,created_at) VALUES(?,?,?,?)
                      ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission, created_at=excluded.created_at""",
                   (document_id, target["id"], payload.permission, now_iso()))
    append_audit(user["id"], document_id, "grant_access", "allowed",
                 {"target_username": payload.username, "permission": payload.permission})
    return {"status": "granted", "username": payload.username, "permission": payload.permission}


@app.delete("/documents/{document_id}/grants/{username}")
def revoke_access(document_id: str, username: str, user=Depends(current_user)):
    with connect() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND deleted=0", (document_id,)).fetchone()
        target = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not doc or doc["owner_id"] != user["id"] or not target:
            allowed = False
        else:
            allowed = True
            db.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (document_id, target["id"]))
    if not allowed:
        fail(user["id"], document_id, "revoke_access", 404)
    append_audit(user["id"], document_id, "revoke_access", "allowed", {"target_username": username})
    return {"status": "revoked", "username": username}


@app.delete("/documents/{document_id}")
def delete_document(document_id: str, user=Depends(current_user)):
    with connect() as db:
        doc, allowed = can_edit(db, user, document_id)
        if allowed and doc["owner_id"] != user["id"]:
            # Editing permission does not include deletion.
            allowed = False
        if allowed:
            db.execute("UPDATE documents SET deleted=1 WHERE id=?", (document_id,))
            db.execute("DELETE FROM grants WHERE document_id=?", (document_id,))
    if not allowed:
        fail(user["id"], document_id, "delete", 404)
    # Soft delete keeps the storage file for recovery; production needs a retention policy.
    append_audit(user["id"], document_id, "delete", "allowed", {"mode": "soft_delete"})
    return {"status": "deleted"}


@app.get("/admin/audit")
def admin_audit(limit: int = 100, user=Depends(current_user)):
    if user["role"] not in ("admin", "owner"):
        append_audit(user["id"], None, "view_audit", "denied", {})
        raise HTTPException(403, "Administrator role required")
    limit = max(1, min(limit, 500))
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/audit/verify")
def verify_audit(user=Depends(current_user)):
    if user["role"] not in ("admin", "owner"):
        append_audit(user["id"], None, "verify_audit", "denied", {})
        raise HTTPException(403, "Administrator role required")
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    previous = "GENESIS"
    for row in rows:
        material = "|".join([
            row["timestamp"], str(row["actor_id"]), str(row["document_id"]),
            row["action"], row["outcome"], row["details"], previous
        ])
        expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
        if row["previous_hash"] != previous or row["event_hash"] != expected:
            return {"valid": False, "first_invalid_event_id": row["id"]}
        previous = row["event_hash"]
    return {"valid": True, "events_checked": len(rows)}
