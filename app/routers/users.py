"""API người dùng (TV1). Chỉ admin. Khớp mục 5 của docs/API.md."""
from typing import Any, Dict, Literal

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app import db
from app.deps import require_roles
from app.errors import AppError
from app.services.audit import append_audit
from app.timeutil import is_past, now_iso

router = APIRouter(prefix="/api/users", tags=["users"])
_ph = PasswordHasher()


class CreateUserIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,50}$")
    password: str = Field(min_length=10, max_length=200)
    role: Literal["accountant", "manager", "director", "admin"]


@router.post("", status_code=201)
def create_user(body: CreateUserIn, admin: Dict[str, Any] = Depends(require_roles("admin"))):
    if db.query_one("SELECT 1 AS x FROM users WHERE username = ?", (body.username,)):
        raise AppError("USERNAME_TAKEN")
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (body.username, _ph.hash(body.password), body.role, now_iso()),
    )
    append_audit("USER_CREATED", admin["id"], {"user_id": cur.lastrowid, "username": body.username, "role": body.role})
    return {"id": cur.lastrowid, "username": body.username, "role": body.role}


@router.get("")
def list_users(admin: Dict[str, Any] = Depends(require_roles("admin"))):
    rows = db.query_all("SELECT id, username, role, locked_until FROM users ORDER BY id")
    return {
        "users": [
            {
                "id": r["id"],
                "username": r["username"],
                "role": r["role"],
                "locked": r["role"] != "admin" and bool(r["locked_until"]) and not is_past(r["locked_until"]),
            }
            for r in rows
        ]
    }
