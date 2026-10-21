"""Chạy server:  python run.py            (hoặc python run.py --reload khi đang code)
Cổng lấy từ PORT trong .env (mặc định 3000, khớp base URL trong docs/API.md)."""
import sys

import uvicorn

from app.config import settings

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=settings.port, reload="--reload" in sys.argv)
