"""Giới hạn tốc độ theo IP, cửa sổ trượt trong bộ nhớ (TV1 sở hữu).
Dùng:  @router.post("/login", dependencies=[Depends(rate_limit("login"))])"""
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple

from fastapi import Request

from app.config import settings
from app.errors import AppError

WINDOW_SECONDS = 60
_hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def reset() -> None:
    with _lock:
        _hits.clear()


def rate_limit(bucket: str, message: str = "Thử quá nhiều lần, vui lòng chờ 1 phút.") -> Callable:
    def dependency(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with _lock:
            q = _hits[(bucket, ip)]
            while q and now - q[0] > WINDOW_SECONDS:
                q.popleft()
            if len(q) >= settings.rate_limit_max:
                raise AppError("RATE_LIMITED", message)
            q.append(now)

    return dependency
