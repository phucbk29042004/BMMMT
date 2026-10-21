"""API nhật ký (TV2). Chỉ admin và director. Khớp mục 8 của docs/API.md."""
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query

from app import db
from app.deps import require_roles
from app.errors import AppError
from app.services.audit import verify_chain

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event: Optional[str] = Query(None, max_length=60),
    order: str = Query("desc", description="desc = mới nhất trước (mặc định), asc = theo thứ tự chuỗi"),
    user: Dict[str, Any] = Depends(require_roles("admin", "director")),
):
    if order not in ("asc", "desc"):
        raise AppError("VALIDATION_ERROR", "order phải là asc hoặc desc.")
    where, params = "", []
    if event:
        where, params = "WHERE event = ?", [event]
    total = db.query_one(f"SELECT COUNT(*) AS n FROM audit_log {where}", params)["n"]
    rows = db.query_all(
        f"SELECT * FROM audit_log {where} ORDER BY id {order.upper()} LIMIT ? OFFSET ?", params + [limit, offset]
    )
    entries = [
        {
            "id": r["id"],
            "event": r["event"],
            "actor_id": r["actor_id"],
            "data": json.loads(r["data_json"]),
            "prev_hash": r["prev_hash"],
            "hash": r["hash"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    return {"entries": entries, "total": total}


@router.get("/verify")
def verify(user: Dict[str, Any] = Depends(require_roles("admin", "director"))):
    return verify_chain()
