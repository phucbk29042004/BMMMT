"""Dependency dùng chung cho mọi router (TV1 sở hữu).

    user = Depends(current_user)                       # đã đăng nhập đầy đủ (qua cả TOTP)
    user = Depends(require_roles("manager","director"))

`user` luôn được NẠP LẠI TỪ DB mỗi request: {"id", "username", "role"}.
Nhờ vậy đổi vai trò / xóa user có hiệu lực ngay, không phụ thuộc dữ liệu cũ trong phiên.
"""
from typing import Any, Callable, Dict

from fastapi import Depends, Request

from app import db, session as session_mod
from app.errors import AppError


def get_session(request: Request) -> session_mod.Session:
    return session_mod.load(request)


def current_user(sess: session_mod.Session = Depends(get_session)) -> Dict[str, Any]:
    # Phiên "chờ MFA" (sess.data["pending"]) KHÔNG được tính là đã đăng nhập
    info = sess.data.get("user")
    if not info:
        raise AppError("NOT_AUTHENTICATED")
    user = db.query_one("SELECT id, username, role FROM users WHERE id = ?", (info["id"],))
    if not user:
        raise AppError("NOT_AUTHENTICATED")
    return user


def require_roles(*roles: str) -> Callable:
    def dependency(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
        if user["role"] not in roles:
            raise AppError("FORBIDDEN_ROLE")
        return user

    return dependency
