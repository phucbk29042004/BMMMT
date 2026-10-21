"""API xác thực (TV1). Khớp mục 4 của docs/API.md."""
import hmac
import hashlib
import secrets
from typing import Any, Dict

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
from app.services.email import EmailDeliveryError, send_login_code
from app.timeutil import in_minutes, is_past

router = APIRouter(prefix="/api/auth", tags=["auth"])

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("dummy-password-for-timing")  # để thời gian phản hồi giống nhau dù user có tồn tại hay không


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


def _otp_digest(sid: str, code: str) -> str:
    message = f"{sid}:{code}".encode("utf-8")
    return hmac.new(settings.otp_pepper.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _email_hint(email: str) -> str:
    local, domain = email.split("@", 1)
    visible = local[:1] if local else ""
    return f"{visible}{'*' * max(3, len(local) - 1)}@{domain}"


def _issue_email_code(sess: session_mod.Session, user: Dict[str, Any]) -> None:
    if not user.get("email"):
        raise AppError("MFA_DELIVERY_FAILED")
    code = f"{secrets.randbelow(1_000_000):06d}"
    sess.data["pending"]["otp_hash"] = _otp_digest(sess.sid, code)
    sess.data["pending"]["otp_expires_at"] = in_minutes(settings.otp_ttl_minutes)
    sess.save()
    try:
        send_login_code(user["email"], user["username"], code)
    except EmailDeliveryError as exc:
        raise AppError("MFA_DELIVERY_FAILED") from exc


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
    if not user["email"]:
        raise AppError("MFA_DELIVERY_FAILED")
    sess.start(response, {"pending": {"userId": user["id"], "stage": "EMAIL_MFA"}})
    _issue_email_code(sess, user)
    append_audit("LOGIN_SUCCESS", user["id"], {"stage": "EMAIL_MFA"})
    return {"status": "MFA_REQUIRED", "email_hint": _email_hint(user["email"])}


@router.post("/mfa", dependencies=[Depends(rate_limit("mfa", "Nhập mã xác thực quá nhiều lần, vui lòng chờ 1 phút."))])
def mfa(body: CodeIn, response: Response, sess: session_mod.Session = Depends(get_session)):
    pending = sess.data.get("pending")
    if not pending or pending.get("stage") != "EMAIL_MFA":
        raise AppError("NOT_AUTHENTICATED")

    user = db.query_one("SELECT * FROM users WHERE id = ?", (pending["userId"],))
    if not user:
        raise AppError("NOT_AUTHENTICATED")
    if _is_locked(user):
        sess.destroy(response)
        raise AppError("ACCOUNT_LOCKED", details={"locked_until": user["locked_until"]})

    expires_at = pending.get("otp_expires_at")
    expected = pending.get("otp_hash")
    accepted = (
        bool(expected)
        and bool(expires_at)
        and not is_past(expires_at)
        and hmac.compare_digest(expected, _otp_digest(sess.sid, body.code))
    )
    if not accepted:
        _register_failure(user, "MFA_FAILED")
        raise AppError("MFA_INVALID")

    pending["otp_hash"] = None
    sess.save()
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    info = _complete_login(sess, response, user)
    append_audit("MFA_SUCCESS", user["id"], {})
    return {"user": info}


@router.post(
    "/mfa/resend",
    dependencies=[Depends(rate_limit("mfa", "Gửi mã xác thực quá nhiều lần, vui lòng chờ 1 phút."))],
)
def resend_mfa(sess: session_mod.Session = Depends(get_session)):
    pending = sess.data.get("pending")
    if not pending or pending.get("stage") != "EMAIL_MFA":
        raise AppError("NOT_AUTHENTICATED")
    user = db.query_one("SELECT * FROM users WHERE id = ?", (pending["userId"],))
    if not user or _is_locked(user):
        raise AppError("NOT_AUTHENTICATED")
    _issue_email_code(sess, user)
    return {"status": "MFA_REQUIRED", "email_hint": _email_hint(user["email"])}


@router.post("/logout", status_code=204)
def logout(sess: session_mod.Session = Depends(get_session)):
    response = Response(status_code=204)
    sess.destroy(response)
    return response


@router.get("/me")
def me(user: Dict[str, Any] = Depends(current_user)):
    return user
