"""Thời gian theo ISO 8601 UTC có mili giây, ví dụ 2026-10-02T08:30:00.000Z.
Định dạng cố định độ dài nên so sánh chuỗi cũng đúng thứ tự thời gian."""
from datetime import datetime, timedelta, timezone


def iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return iso(now())


def in_minutes(minutes: float) -> str:
    return iso(now() + timedelta(minutes=minutes))


def in_hours(hours: float) -> str:
    return iso(now() + timedelta(hours=hours))


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_past(value: str) -> bool:
    return parse(value) < now()
