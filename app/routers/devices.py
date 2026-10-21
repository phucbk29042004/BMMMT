"""API thiết bị (TV1). Khớp mục 6 của docs/API.md.

Đăng ký thiết bị phải chứng minh sở hữu khóa riêng (proof of possession): ký challenge do server phát hành.
"""
from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app import db
from app.config import settings
from app.deps import current_user
from app.errors import AppError
from app.services.audit import append_audit
from app.services.crypto import is_valid_p256_public_key, random_hex, verify_signature
from app.timeutil import in_minutes, is_past, now_iso

router = APIRouter(prefix="/api/devices", tags=["devices"])

B64 = r"^[A-Za-z0-9+/=]+$"


class RegisterIn(BaseModel):
    label: str = Field(min_length=1, max_length=50)
    public_key: str = Field(pattern=B64, max_length=300)
    challenge: str = Field(pattern=r"^[0-9a-f]{32}$")
    signature: str = Field(pattern=B64, max_length=200)


@router.post("/challenge")
def device_challenge(user: Dict[str, Any] = Depends(current_user)):
    challenge = random_hex(16)
    expires_at = in_minutes(settings.nonce_ttl_minutes)
    db.execute(
        "INSERT INTO nonces (nonce, purpose, user_id, created_at, expires_at) VALUES (?, 'DEVICE_REG', ?, ?, ?)",
        (challenge, user["id"], now_iso(), expires_at),
    )
    return {"challenge": challenge, "expires_at": expires_at}


@router.post("/register", status_code=201)
def register_device(body: RegisterIn, user: Dict[str, Any] = Depends(current_user)):
    if not is_valid_p256_public_key(body.public_key):
        raise AppError("VALIDATION_ERROR", "Khóa công khai không hợp lệ (cần ECDSA P-256, SPKI base64).")

    with db.transaction():
        # Challenge phải do hệ thống phát hành, đúng người, chưa dùng, chưa hết hạn
        row = db.query_one("SELECT * FROM nonces WHERE nonce = ?", (body.challenge,))
        if not row or row["purpose"] != "DEVICE_REG" or row["user_id"] != user["id"]:
            raise AppError("NONCE_UNKNOWN")
        if row["used_at"]:
            raise AppError("NONCE_USED")
        if is_past(row["expires_at"]):
            raise AppError("NONCE_EXPIRED")

        # Proof of possession: phải ký được challenge bằng khóa riêng tương ứng
        if not verify_signature(body.public_key, body.challenge, body.signature):
            raise AppError("SIGNATURE_INVALID")

        active = db.query_one(
            "SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND status = 'active'", (user["id"],)
        )["n"]
        if active >= settings.max_devices_per_user:
            raise AppError("DEVICE_LIMIT")
        if db.query_one("SELECT 1 AS x FROM devices WHERE public_key = ?", (body.public_key,)):
            raise AppError("VALIDATION_ERROR", "Khóa công khai này đã được đăng ký.")

        now = now_iso()
        used = db.execute("UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL", (now, body.challenge))
        if used.rowcount != 1:
            raise AppError("NONCE_USED")
        cur = db.execute(
            "INSERT INTO devices (user_id, public_key, label, status, created_at) VALUES (?,?,?,?,?)",
            (user["id"], body.public_key, body.label, "active", now),
        )
        append_audit("DEVICE_REGISTERED", user["id"], {"device_id": cur.lastrowid, "label": body.label})
        return {"id": cur.lastrowid, "label": body.label, "status": "active", "created_at": now}


@router.get("")
def list_devices(user: Dict[str, Any] = Depends(current_user)):
    rows = db.query_all(
        "SELECT id, label, status, created_at FROM devices WHERE user_id = ? ORDER BY id", (user["id"],)
    )
    return {"devices": rows}


@router.post("/{device_id}/revoke")
def revoke_device(device_id: int, user: Dict[str, Any] = Depends(current_user)):
    with db.transaction():
        device = db.query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
        if not device:
            raise AppError("DEVICE_NOT_FOUND")
        if device["user_id"] != user["id"] and user["role"] != "admin":
            raise AppError("FORBIDDEN_ROLE")
        if device["status"] != "revoked":
            db.execute("UPDATE devices SET status = 'revoked', revoked_at = ? WHERE id = ?", (now_iso(), device_id))
            append_audit("DEVICE_REVOKED", user["id"], {"device_id": device_id, "owner_id": device["user_id"]})
    return {"id": device_id, "status": "revoked"}
