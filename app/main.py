"""Điểm vào của ứng dụng. Chạy:  uvicorn app.main:app --reload"""
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import db
from app.config import settings
from app.errors import AppError

PUBLIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "public")
DOC_PATHS = ("/docs", "/redoc", "/openapi.json")  # Swagger UI cần tải script từ CDN nên không áp CSP chặt


def _error_response(err: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=err.status,
        content={"error": {"code": err.code, "message": err.message, "details": err.details}},
    )


def create_app() -> FastAPI:
    db.init(settings.db_path)
    app = FastAPI(title="TrustSign", version="1.0", description="Xem hợp đồng API đầy đủ tại docs/API.md")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith(DOC_PATHS):
            response.headers["X-Frame-Options"] = "DENY"
            # Không cho JS inline: TV3 đặt JS ở file riêng trong public/
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            )
        return response

    @app.exception_handler(AppError)
    async def on_app_error(request: Request, exc: AppError):
        return _error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError):
        issues = [{"path": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
        return _error_response(AppError("VALIDATION_ERROR", details={"issues": issues}))

    @app.exception_handler(StarletteHTTPException)
    async def on_http_error(request: Request, exc: StarletteHTTPException):
        message = "Không tìm thấy đường dẫn." if exc.status_code == 404 else "Yêu cầu không hợp lệ."
        return _error_response(AppError("VALIDATION_ERROR", f"{message} ({request.method} {request.url.path})"))

    @app.exception_handler(Exception)
    async def on_unexpected(request: Request, exc: Exception):
        import traceback

        traceback.print_exception(type(exc), exc, exc.__traceback__)
        return _error_response(AppError("INTERNAL_ERROR"))

    from app.routers import audit, auth, devices, transactions, users

    for module in (auth, users, devices, transactions, audit):
        app.include_router(module.router)

    os.makedirs(PUBLIC_DIR, exist_ok=True)
    app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="static")  # phải mount SAU các router
    return app


app = create_app()
