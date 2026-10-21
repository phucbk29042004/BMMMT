"""Tạo dữ liệu mẫu cho dev/demo (mục 13 của docs/API.md).

    python -m scripts.seed              -> người dùng chưa cài TOTP (đăng nhập lần đầu sẽ quét QR)
    python -m scripts.seed --dev-totp   -> gán sẵn TOTP cố định để TV3/TV4 viết script nhanh (CHỈ DÙNG KHI DEV)
"""
import sys

from argon2 import PasswordHasher

from app import db
from app.config import settings
from app.services.audit import append_audit
from app.timeutil import now_iso

DEV_PASSWORD = "MatKhau@12345"
DEV_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
USERS = [
    ("admin01", "admin"),
    ("ketoan01", "accountant"),
    ("quanly01", "manager"),
    ("giamdoc01", "director"),
    ("quanly02", "manager"),
]


def seed(dev_totp: bool = False, password_hash: str = None) -> None:
    db.init(settings.db_path)
    password_hash = password_hash or PasswordHasher().hash(DEV_PASSWORD)
    for username, role in USERS:
        cur = db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, totp_secret, created_at) VALUES (?,?,?,?,?)",
            (username, password_hash, role, DEV_TOTP_SECRET if dev_totp else None, now_iso()),
        )
        if cur.rowcount == 1:
            append_audit("USER_CREATED", 0, {"username": username, "role": role, "seeded": True})


if __name__ == "__main__":
    flag = "--dev-totp" in sys.argv
    seed(dev_totp=flag)
    print("Đã tạo người dùng mẫu:")
    for u, r in USERS:
        print(f"  {u:<10} ({r})")
    print(f"Mật khẩu dev: {DEV_PASSWORD}")
    if flag:
        print(f"TOTP dev (base32): {DEV_TOTP_SECRET}  ->  python -m scripts.totp")
