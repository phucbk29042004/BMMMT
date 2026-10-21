"""Quy tắc nghiệp vụ duyệt giao dịch (TV2 sở hữu). Khớp mục 2 và mục 10 của docs/API.md."""
from typing import Any, Dict

from app import db
from app.config import settings
from app.errors import AppError
from app.services.audit import append_audit

PENDING = ("PENDING_L1", "PENDING_L2")
ALL_STATUSES = ("PENDING_L1", "PENDING_L2", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED")
APPROVER_ROLE_BY_LEVEL = {1: "manager", 2: "director"}


def required_levels_for(amount: int) -> int:
    """Dưới ngưỡng: 1 cấp (manager). Từ ngưỡng trở lên: 2 cấp (manager rồi director)."""
    return 2 if amount >= settings.approval_threshold_vnd else 1


def expire_overdue() -> None:
    """Chuyển các giao dịch quá hạn sang EXPIRED và ghi audit. Gọi đầu mỗi request liên quan giao dịch."""
    from app.timeutil import now_iso

    with db.transaction():
        rows = db.query_all(
            "SELECT id FROM transactions WHERE status IN ('PENDING_L1','PENDING_L2') AND expires_at < ?",
            (now_iso(),),
        )
        for r in rows:
            db.execute("UPDATE transactions SET status = 'EXPIRED' WHERE id = ?", (r["id"],))
            append_audit("TX_EXPIRED", 0, {"tx_id": r["id"]})


def get_tx_or_404(tx_id: int) -> Dict[str, Any]:
    tx = db.query_one("SELECT * FROM transactions WHERE id = ?", (tx_id,))
    if not tx:
        raise AppError("TX_NOT_FOUND")
    return tx


def check_state_and_level(tx: Dict[str, Any], user: Dict[str, Any]) -> int:
    """Bước 3, 4 và vai trò theo cấp. Trả về cấp duyệt hiện tại (1 hoặc 2); cấp do SERVER quyết định."""
    if tx["status"] == "EXPIRED":
        raise AppError("TX_EXPIRED")
    if tx["status"] not in PENDING:
        raise AppError("TX_WRONG_STATE")
    level = 1 if tx["status"] == "PENDING_L1" else 2
    if user["role"] != APPROVER_ROLE_BY_LEVEL[level]:
        raise AppError("FORBIDDEN_ROLE")
    return level


def check_separation_of_duties(tx: Dict[str, Any], user: Dict[str, Any]) -> None:
    """Bước 5 và 6: tách nhiệm vụ."""
    if tx["creator_id"] == user["id"]:
        raise AppError("SELF_APPROVAL")
    already = db.query_one(
        "SELECT 1 AS x FROM approvals WHERE transaction_id = ? AND approver_id = ?", (tx["id"], user["id"])
    )
    if already:
        raise AppError("DUPLICATE_APPROVER")


def check_device(user: Dict[str, Any], device_id: int) -> Dict[str, Any]:
    """Bước 7: thiết bị tồn tại, thuộc đúng người duyệt, còn hiệu lực."""
    device = db.query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not device or device["user_id"] != user["id"]:
        raise AppError("DEVICE_NOT_REGISTERED")
    if device["status"] != "active":
        raise AppError("DEVICE_REVOKED")
    return device
