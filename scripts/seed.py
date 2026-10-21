"""Tạo dữ liệu mẫu cho dev/demo: python -m scripts.seed"""

from argon2 import PasswordHasher

from app import db
from app.config import settings
from app.services.audit import append_audit
from app.timeutil import now_iso

DEV_PASSWORD = "MatKhau@12345"
USERS = [
    ("admin01", "admin"),
    ("ketoan01", "accountant"),
    ("quanly01", "manager"),
    ("giamdoc01", "director"),
    ("quanly02", "manager"),
]


def seed(password_hash: str = None) -> None:
    db.init(settings.db_path)
    password_hash = password_hash or PasswordHasher().hash(DEV_PASSWORD)
    for username, role in USERS:
        email = settings.admin_email if username == "admin01" else f"{username}@example.test"
        email = email or f"{username}@example.test"
        cur = db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, email, created_at) VALUES (?,?,?,?,?)",
            (
                username,
                password_hash,
                role,
                email,
                now_iso(),
            ),
        )
        if username == "admin01" and settings.admin_email:
            db.execute("UPDATE users SET email = ? WHERE username = ?", (email, username))
        else:
            db.execute("UPDATE users SET email = COALESCE(NULLIF(email, ''), ?) WHERE username = ?", (email, username))
        if cur.rowcount == 1:
            append_audit("USER_CREATED", 0, {"username": username, "role": role, "seeded": True})


if __name__ == "__main__":
    seed()
    print("Đã tạo người dùng mẫu:")
    for u, r in USERS:
        print(f"  {u:<10} ({r})")
    print(f"Mật khẩu dev: {DEV_PASSWORD}")
    if settings.admin_email:
        print(f"Email admin01: {settings.admin_email}")
    else:
        print("Hãy cấu hình ADMIN_EMAIL trong .env trước khi đăng nhập.")
