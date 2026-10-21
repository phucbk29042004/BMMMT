"""API xác thực (TV1). Khớp mục 4 của docs/API.md."""
import base64
import hmac
import io
import time
from typing import Any, Dict, Optional

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field

from app import db, session as session_mod
from app.config import settings
from app.deps import current_user, get_session
from app.errors import AppError
from app.ratelimit import rate_limit
from app.services.audit import append_audit
from app.timeutil import in_minutes, is_past

router = APIRouter(prefix="/api/auth", tags=["auth"])

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("dummy-password-for-timing")  # để thời gian phản hồi giống nhau dù user có tồn tại hay không
TOTP_STEP = 30


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=200)


class CodeIn(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


# ---------------------------------------------------------------- tiện ích
def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def _is_locked(user: Dict[str, Any]) -> bool:
    if user["role"] == "admin":
        return False
    return bool(user["locked_until"]) and not is_past(user["locked_until"])


def _register_failure(user: Dict[str, Any], event: str) -> None:
    """Ghi nhận thất bại; tài khoản admin không bị khóa theo số lần sai."""
    if user["role"] == "admin":
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        append_audit(event, user["id"], {"attempts": 0})
        return

    attempts = user["failed_attempts"] + 1
    if attempts >= settings.max_login_attempts:
        until = in_minutes(settings.lock_minutes)
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?", (until, user["id"]))
        append_audit("ACCOUNT_LOCKED", user["id"], {"locked_until": until, "trigger": event})
    else:
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
    append_audit(event, user["id"], {"attempts": attempts})


def match_totp_step(code: str, secret: str) -> Optional[int]:
    """Trả về số bước thời gian (30 giây) khớp với mã, cho phép lệch ±1; không khớp trả None."""
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // TOTP_STEP
    for delta in (0, -1, 1):
        step = current + delta
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def _complete_login(sess: session_mod.Session, response: Response, user: Dict[str, Any]) -> Dict[str, Any]:
    info = {"id": user["id"], "username": user["username"], "role": user["role"]}
    sess.start(response, {"user": info})  # phiên mới, chống session fixation
    return info


# ---------------------------------------------------------------- endpoints
@router.post("/login", dependencies=[Depends(rate_limit("login", "Đăng nhập quá nhiều lần, vui lòng chờ 1 phút."))])
def login(body: LoginIn, response: Response, sess: session_mod.Session = Depends(get_session)):
    user = db.query_one("SELECT * FROM users WHERE username = ?", (body.username,))
    if not user:
        verify_password(_DUMMY_HASH, body.password)
        append_audit("LOGIN_FAILED", 0, {"username": body.username, "reason": "unknown_user"})
        raise AppError("AUTH_INVALID_CREDENTIALS")
    if _is_locked(user):
        append_audit("LOGIN_FAILED", user["id"], {"reason": "locked"})
        raise AppError("ACCOUNT_LOCKED", details={"locked_until": user["locked_until"]})
    if not verify_password(user["password_hash"], body.password):
        _register_failure(user, "LOGIN_FAILED")
        raise AppError("AUTH_INVALID_CREDENTIALS")

    # Mật khẩu đúng nhưng CHƯA đăng nhập: chỉ vào trạng thái "chờ MFA"
    stage = "MFA" if user["totp_secret"] else "TOTP_SETUP"
    sess.start(response, {"pending": {"userId": user["id"], "stage": stage}})
    append_audit("LOGIN_SUCCESS", user["id"], {"stage": stage})
    return {"status": "MFA_REQUIRED" if stage == "MFA" else "TOTP_SETUP_REQUIRED"}


@router.post("/mfa", dependencies=[Depends(rate_limit("mfa", "Nhập mã TOTP quá nhiều lần, vui lòng chờ 1 phút."))])
def mfa(body: CodeIn, response: Response, sess: session_mod.Session = Depends(get_session)):
    pending = sess.data.get("pending")
    if not pending or pending.get("stage") != "MFA":
        raise AppError("NOT_AUTHENTICATED")

    user = db.query_one("SELECT * FROM users WHERE id = ?", (pending["userId"],))
    if not user:
        raise AppError("NOT_AUTHENTICATED")
    if _is_locked(user):
        sess.destroy(response)
        raise AppError("ACCOUNT_LOCKED", details={"locked_until": user["locked_until"]})

    step = match_totp_step(body.code, user["totp_secret"])
    # Mỗi bước thời gian chỉ dùng MỘT lần: cập nhật nguyên tử, không đủ điều kiện thì bị từ chối
    accepted = False
    if step is not None:
        cur = db.execute(
            "UPDATE users SET last_totp_step = ? WHERE id = ? AND last_totp_step < ?", (step, user["id"], step)
        )
        accepted = cur.rowcount == 1
    if not accepted:
        _register_failure(user, "MFA_FAILED")
        raise AppError("MFA_INVALID")

    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    info = _complete_login(sess, response, user)
    append_audit("MFA_SUCCESS", user["id"], {})
    return {"user": info}


@router.post("/totp/setup")
def totp_setup(sess: session_mod.Session = Depends(get_session)):
    pending = sess.data.get("pending")
    if not pending or pending.get("stage") != "TOTP_SETUP":
        raise AppError("NOT_AUTHENTICATED")
    user = db.query_one("SELECT username FROM users WHERE id = ?", (pending["userId"],))

    secret = pyotp.random_base32()
    sess.data["pendingTotpSecret"] = secret  # chưa ghi vào users cho tới khi xác nhận đúng mã
    sess.save()
    otpauth_url = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="TrustSign")

    buf = io.BytesIO()
    qrcode.make(otpauth_url).save(buf, format="PNG")
    qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    return {"otpauth_url": otpauth_url, "qr_data_url": qr}


@router.post(
    "/totp/confirm",
    dependencies=[Depends(rate_limit("mfa", "Nhập mã TOTP quá nhiều lần, vui lòng chờ 1 phút."))],
)
def totp_confirm(body: CodeIn, response: Response, sess: session_mod.Session = Depends(get_session)):
    pending = sess.data.get("pending")
    secret = sess.data.get("pendingTotpSecret")
    if not pending or pending.get("stage") != "TOTP_SETUP" or not secret:
        raise AppError("NOT_AUTHENTICATED")

    user = db.query_one("SELECT * FROM users WHERE id = ?", (pending["userId"],))
    step = match_totp_step(body.code, secret)
    if step is None:
        _register_failure(user, "MFA_FAILED")
        raise AppError("MFA_INVALID")

    db.execute("UPDATE users SET totp_secret = ?, last_totp_step = ? WHERE id = ?", (secret, step, user["id"]))
    info = _complete_login(sess, response, user)
    append_audit("MFA_SUCCESS", user["id"], {"setup": True})
    return {"user": info}


@router.post("/logout", status_code=204)
def logout(sess: session_mod.Session = Depends(get_session)):
    response = Response(status_code=204)
    sess.destroy(response)
    return response


@router.get("/me")
def me(user: Dict[str, Any] = Depends(current_user)):
    return user
