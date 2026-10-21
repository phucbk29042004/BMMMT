"""Phiên đăng nhập lưu PHÍA SERVER (TV1 sở hữu).

Cookie chỉ chứa một token ngẫu nhiên 256-bit; DB chỉ lưu SHA-256 của token (lộ DB cũng không dùng được token).
Đăng xuất = xóa dòng trong DB, nên cookie bị đánh cắp cũng mất hiệu lực (khác với cookie ký chứa sẵn dữ liệu).
"""
import hashlib
import json
import secrets
from typing import Any, Dict, Optional

from fastapi import Request, Response

from app import db
from app.config import settings
from app.timeutil import in_minutes, is_past, now_iso

COOKIE_NAME = "connect.sid"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Session:
    """data có thể chứa:
       pending : {"userId": int, "stage": "MFA" | "TOTP_SETUP"}   (đã qua mật khẩu, chưa qua TOTP)
       pendingTotpSecret : str                                    (đang cài TOTP)
       user    : {"id", "username", "role"}                       (đã đăng nhập đầy đủ)
    """

    def __init__(self, sid: Optional[str] = None, data: Optional[Dict[str, Any]] = None):
        self.sid = sid  # SHA-256 của token, None nếu chưa có phiên
        self.data: Dict[str, Any] = data or {}

    def start(self, response: Response, data: Dict[str, Any]) -> None:
        """Tạo phiên MỚI (hủy phiên cũ nếu có) - chống session fixation."""
        if self.sid:
            db.execute("DELETE FROM sessions WHERE id = ?", (self.sid,))
        token = secrets.token_urlsafe(32)
        self.sid = _hash(token)
        self.data = data
        db.execute(
            "INSERT INTO sessions (id, data_json, created_at, expires_at) VALUES (?,?,?,?)",
            (self.sid, json.dumps(data), now_iso(), in_minutes(settings.session_ttl_minutes)),
        )
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=settings.session_ttl_minutes * 60,
            httponly=True,
            samesite="strict",
            secure=False,  # demo chạy http://localhost; triển khai thật phải đặt True + HTTPS
            path="/",
        )

    def save(self) -> None:
        if self.sid:
            db.execute("UPDATE sessions SET data_json = ? WHERE id = ?", (json.dumps(self.data), self.sid))

    def destroy(self, response: Response) -> None:
        if self.sid:
            db.execute("DELETE FROM sessions WHERE id = ?", (self.sid,))
        self.sid, self.data = None, {}
        response.delete_cookie(COOKIE_NAME, path="/")


def load(request: Request) -> Session:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return Session()
    sid = _hash(token)
    row = db.query_one("SELECT * FROM sessions WHERE id = ?", (sid,))
    if not row:
        return Session()
    if is_past(row["expires_at"]):
        db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        return Session()
    # Hết hạn theo thời gian KHÔNG hoạt động (trượt)
    db.execute("UPDATE sessions SET expires_at = ? WHERE id = ?", (in_minutes(settings.session_ttl_minutes), sid))
    return Session(sid, json.loads(row["data_json"]))
