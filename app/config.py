"""Cấu hình dùng chung (mục 13 của docs/API.md). Đọc từ biến môi trường / file .env."""
import os
import secrets
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()  # không ghi đè biến môi trường đã có (test đặt biến trước khi import)


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return default if value in (None, "") else int(value)


@dataclass
class Settings:
    port: int = _int("PORT", 3000)
    db_path: str = os.environ.get("DB_PATH") or "./data/trustsign.db"
    approval_threshold_vnd: int = _int("APPROVAL_THRESHOLD_VND", 50_000_000)
    tx_ttl_hours: int = _int("TX_TTL_HOURS", 24)
    nonce_ttl_minutes: int = _int("NONCE_TTL_MINUTES", 5)
    max_login_attempts: int = _int("MAX_LOGIN_ATTEMPTS", 5)
    lock_minutes: int = _int("LOCK_MINUTES", 15)
    max_devices_per_user: int = _int("MAX_DEVICES_PER_USER", 3)
    session_ttl_minutes: int = _int("SESSION_TTL_MINUTES", 30)
    rate_limit_max: int = _int("RATE_LIMIT_MAX", 5)
    admin_email: str = os.environ.get("ADMIN_EMAIL", "").strip()
    smtp_host: str = os.environ.get("SMTP_HOST", "").strip()
    smtp_port: int = _int("SMTP_PORT", 587)
    smtp_username: str = os.environ.get("SMTP_USERNAME", "")
    smtp_password: str = os.environ.get("SMTP_PASSWORD", "")
    smtp_from: str = os.environ.get("SMTP_FROM", "").strip()
    smtp_use_ssl: bool = os.environ.get("SMTP_USE_SSL", "").lower() == "true"
    smtp_starttls: bool = os.environ.get("SMTP_STARTTLS", "true").lower() == "true"
    smtp_timeout_seconds: int = _int("SMTP_TIMEOUT_SECONDS", 15)
    otp_ttl_minutes: int = _int("EMAIL_OTP_TTL_MINUTES", 10)
    otp_pepper: str = os.environ.get("EMAIL_OTP_PEPPER") or secrets.token_hex(32)


settings = Settings()  # đối tượng có thể sửa lúc chạy (test dùng monkeypatch)
