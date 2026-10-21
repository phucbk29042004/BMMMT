"""API giao dịch (TV2). Khớp mục 7 của docs/API.md."""
import re
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, StrictInt

from app import db
from app.config import settings
from app.deps import current_user, require_roles
from app.errors import AppError
from app.services import approval as rules
from app.services.audit import append_audit
from app.services.crypto import build_signing_string, random_hex, verify_signature
from app.timeutil import in_hours, in_minutes, is_past, now_iso

router = APIRouter(prefix="/api/transactions", tags=["transactions"])

NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------- mô hình dữ liệu vào
class CreateTxIn(BaseModel):
    amount: StrictInt = Field(gt=0, le=10_000_000_000)  # số nguyên (đồng); chuỗi hoặc số thực bị từ chối
    recipient_account: str = Field(pattern=r"^\d{6,20}$")
    recipient_name: str = Field(min_length=2, max_length=100)
    note: Optional[str] = Field(default=None, max_length=200)  # KHÔNG nằm trong chuỗi ký


class ChallengeIn(BaseModel):
    device_id: StrictInt = Field(gt=0)


class ApproveIn(BaseModel):
    # Cố ý để Any/Optional: dữ liệu sai hoặc THIẾU chữ ký phải đi vào logic duyệt
    # để bị từ chối VÀ ghi audit (APPROVAL_REJECTED_BY_SYSTEM), thay vì bị chặn im lặng ở lớp validate.
    device_id: Any = None
    nonce: Any = None
    signature: Any = None


class RejectIn(BaseModel):
    reason: str = Field(min_length=1, max_length=200)


# ---------------------------------------------------------------- tiện ích
def _user_brief(user_id: int) -> Dict[str, Any]:
    return db.query_one("SELECT id, username FROM users WHERE id = ?", (user_id,))


def _can_view(tx: Dict[str, Any], user: Dict[str, Any]) -> bool:
    role = user["role"]
    if role == "director":
        return True
    if role == "accountant":
        return tx["creator_id"] == user["id"]
    if role == "manager":
        acted = db.query_one(
            "SELECT 1 AS x FROM approvals WHERE transaction_id = ? AND approver_id = ?", (tx["id"], user["id"])
        )
        return tx["status"] == "PENDING_L1" or bool(acted) or tx["rejected_by"] == user["id"]
    return False  # admin không xem giao dịch (đặc quyền tối thiểu)


def _summary(tx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": tx["id"],
        "status": tx["status"],
        "amount": tx["amount"],
        "currency": tx["currency"],
        "recipient_account": tx["recipient_account"],
        "recipient_name": tx["recipient_name"],
        "required_levels": tx["required_levels"],
        "created_by": tx["creator_id"],
        "created_at": tx["created_at"],
        "expires_at": tx["expires_at"],
    }


# ---------------------------------------------------------------- tạo / xem
@router.post("", status_code=201)
def create_transaction(body: CreateTxIn, user: Dict[str, Any] = Depends(require_roles("accountant"))):
    levels = rules.required_levels_for(body.amount)
    now = now_iso()
    with db.transaction():
        cur = db.execute(
            """INSERT INTO transactions
               (creator_id, amount, currency, recipient_account, recipient_name, note,
                status, required_levels, created_at, expires_at)
               VALUES (?, ?, 'VND', ?, ?, ?, 'PENDING_L1', ?, ?, ?)""",
            (user["id"], body.amount, body.recipient_account, body.recipient_name, body.note,
             levels, now, in_hours(settings.tx_ttl_hours)),
        )
        tx = rules.get_tx_or_404(cur.lastrowid)
        append_audit("TX_CREATED", user["id"],
                     {"tx_id": tx["id"], "amount": tx["amount"], "recipient_account": tx["recipient_account"]})
    return _summary(tx)


@router.get("")
def list_transactions(
    status: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: Dict[str, Any] = Depends(require_roles("accountant", "manager", "director")),
):
    if status is not None and status not in rules.ALL_STATUSES:
        raise AppError("VALIDATION_ERROR", "Trạng thái lọc không hợp lệ.", {"allowed": list(rules.ALL_STATUSES)})
    rules.expire_overdue()

    where, params = [], []
    if user["role"] == "accountant":
        where.append("creator_id = ?")
        params.append(user["id"])
    elif user["role"] == "manager":
        where.append("(status = 'PENDING_L1' OR id IN (SELECT transaction_id FROM approvals WHERE approver_id = ?)"
                     " OR rejected_by = ?)")
        params += [user["id"], user["id"]]
    if status:
        where.append("status = ?")
        params.append(status)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    total = db.query_one(f"SELECT COUNT(*) AS n FROM transactions {clause}", params)["n"]
    rows = db.query_all(
        f"SELECT * FROM transactions {clause} ORDER BY id DESC LIMIT ? OFFSET ?", params + [limit, offset]
    )
    return {"transactions": [_summary(r) for r in rows], "total": total}


@router.get("/{tx_id}")
def get_transaction(tx_id: int, user: Dict[str, Any] = Depends(current_user)):
    rules.expire_overdue()
    tx = rules.get_tx_or_404(tx_id)
    if not _can_view(tx, user):
        raise AppError("FORBIDDEN_ROLE")
    approvals = db.query_all("SELECT * FROM approvals WHERE transaction_id = ? ORDER BY level", (tx_id,))
    result = _summary(tx)
    result.update(
        {
            "note": tx["note"],
            "created_by": _user_brief(tx["creator_id"]),
            "reject_reason": tx["reject_reason"],
            "approvals": [
                {
                    "level": a["level"],
                    "approver": _user_brief(a["approver_id"]),
                    "device_id": a["device_id"],
                    "created_at": a["created_at"],
                }
                for a in approvals
            ],
        }
    )
    return result


# ---------------------------------------------------------------- challenge (xin chuỗi cần ký)
@router.post("/{tx_id}/challenge")
def challenge(tx_id: int, body: ChallengeIn, user: Dict[str, Any] = Depends(require_roles("manager", "director"))):
    rules.expire_overdue()
    with db.transaction():
        tx = rules.get_tx_or_404(tx_id)
        level = rules.check_state_and_level(tx, user)
        rules.check_separation_of_duties(tx, user)
        rules.check_device(user, body.device_id)

        nonce = random_hex(16)
        expires_at = in_minutes(settings.nonce_ttl_minutes)
        signing_string = build_signing_string(tx, level, user["id"], body.device_id, nonce, expires_at)
        db.execute(
            """INSERT INTO nonces (nonce, purpose, user_id, tx_id, level, device_id,
                                   signing_string, created_at, expires_at)
               VALUES (?, 'TX_APPROVE', ?, ?, ?, ?, ?, ?, ?)""",
            (nonce, user["id"], tx_id, level, body.device_id, signing_string, now_iso(), expires_at),
        )
    return {"nonce": nonce, "expires_at": expires_at, "level": level, "signing_string": signing_string}


# ---------------------------------------------------------------- duyệt (có chữ ký)
def _approve_checked(tx_id: int, body: ApproveIn, user: Dict[str, Any]) -> Dict[str, Any]:
    """Chạy toàn bộ trong MỘT transaction (giữ khóa DB) nên hai request song song cùng nonce
    không thể cùng thành công. Thứ tự kiểm tra: xem docs/INTERFACE-TV2.md."""
    # Bước 2 (thô): chỉ người duyệt mới được đến đây. Làm trong khối này để lần từ chối cũng được ghi audit.
    if user["role"] not in ("manager", "director"):
        raise AppError("FORBIDDEN_ROLE")

    device_id, nonce = body.device_id, body.nonce
    if not isinstance(device_id, int) or isinstance(device_id, bool) or device_id <= 0:
        raise AppError("VALIDATION_ERROR", "device_id không hợp lệ.")
    if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
        raise AppError("VALIDATION_ERROR", "nonce không hợp lệ.")

    # Bước 2.5: phát hiện replay SỚM. Nonce đã dùng thì báo NONCE_USED ngay (nếu không, request replay
    # sẽ bị các bước sau chặn bằng lỗi khác vì trạng thái giao dịch đã đổi, làm mất thông tin tấn công).
    nrow = db.query_one("SELECT * FROM nonces WHERE nonce = ?", (nonce,))
    if nrow and nrow["used_at"]:
        raise AppError("NONCE_USED")

    tx = rules.get_tx_or_404(tx_id)                                # 3
    level = rules.check_state_and_level(tx, user)                  # 3, 4 và vai trò theo cấp
    rules.check_separation_of_duties(tx, user)                     # 5, 6
    device = rules.check_device(user, device_id)                   # 7

    # 8: nonce do hệ thống phát hành cho ĐÚNG giao dịch, người, thiết bị, cấp này
    if (not nrow or nrow["purpose"] != "TX_APPROVE" or nrow["tx_id"] != tx["id"]
            or nrow["user_id"] != user["id"] or nrow["device_id"] != device_id or nrow["level"] != level):
        raise AppError("NONCE_UNKNOWN")
    if is_past(nrow["expires_at"]):
        raise AppError("NONCE_EXPIRED")

    # 9: dựng lại chuỗi ký từ DB hiện tại, so với bản đã phát hành. Dữ liệu giao dịch bị sửa sau khi phát hành => lệch.
    expected = build_signing_string(tx, level, user["id"], device_id, nonce, nrow["expires_at"])
    if expected != nrow["signing_string"]:
        raise AppError("SIGNING_PAYLOAD_MISMATCH")

    # 10: chữ ký phải hợp lệ với khóa công khai của thiết bị, trên chuỗi do SERVER phát hành
    signature = body.signature
    if not isinstance(signature, str) or not signature:
        raise AppError("SIGNATURE_INVALID", "Yêu cầu không có chữ ký số.")
    if not verify_signature(device["public_key"], expected, signature):
        raise AppError("SIGNATURE_INVALID")

    # 11: ghi nhận (nonce nguyên tử + approval + trạng thái + audit)
    now = now_iso()
    used = db.execute("UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL", (now, nonce))
    if used.rowcount != 1:
        raise AppError("NONCE_USED")
    db.execute(
        """INSERT INTO approvals (transaction_id, level, approver_id, device_id, nonce, signature,
                                  signing_string, created_at) VALUES (?,?,?,?,?,?,?,?)""",
        (tx["id"], level, user["id"], device_id, nonce, signature, expected, now),
    )
    final = level >= tx["required_levels"]
    new_status = "APPROVED" if final else "PENDING_L2"
    db.execute("UPDATE transactions SET status = ? WHERE id = ?", (new_status, tx["id"]))
    append_audit("TX_APPROVED", user["id"], {"tx_id": tx["id"], "level": level, "device_id": device_id})
    if final:
        append_audit("TX_FULLY_APPROVED", user["id"], {"tx_id": tx["id"]})
    return {
        "id": tx["id"],
        "status": new_status,
        "approval": {"level": level, "approver_id": user["id"], "device_id": device_id, "created_at": now},
    }


@router.post("/{tx_id}/approve")
def approve(tx_id: int, body: ApproveIn, user: Dict[str, Any] = Depends(current_user)):
    rules.expire_overdue()
    try:
        with db.transaction():
            return _approve_checked(tx_id, body, user)
    except AppError as err:
        # Mọi lần hệ thống chặn một yêu cầu duyệt đều để lại dấu vết (transaction trên đã rollback nên ghi ở đây).
        append_audit(
            "APPROVAL_REJECTED_BY_SYSTEM",
            user["id"],
            {"tx_id": tx_id, "error_code": err.code,
             "device_id": body.device_id if isinstance(body.device_id, int) else None},
        )
        raise


# ---------------------------------------------------------------- từ chối / hủy
@router.post("/{tx_id}/reject")
def reject(tx_id: int, body: RejectIn, user: Dict[str, Any] = Depends(require_roles("manager", "director"))):
    """Không cần chữ ký: từ chối là hướng an toàn (fail-safe)."""
    rules.expire_overdue()
    with db.transaction():
        tx = rules.get_tx_or_404(tx_id)
        if tx["status"] == "EXPIRED":
            raise AppError("TX_EXPIRED")
        if tx["status"] not in rules.PENDING:
            raise AppError("TX_WRONG_STATE")
        db.execute(
            "UPDATE transactions SET status = 'REJECTED', reject_reason = ?, rejected_by = ? WHERE id = ?",
            (body.reason, user["id"], tx_id),
        )
        append_audit("TX_REJECTED", user["id"], {"tx_id": tx_id, "reason": body.reason})
    return {"id": tx_id, "status": "REJECTED"}


@router.post("/{tx_id}/cancel")
def cancel(tx_id: int, user: Dict[str, Any] = Depends(require_roles("accountant"))):
    rules.expire_overdue()
    with db.transaction():
        tx = rules.get_tx_or_404(tx_id)
        if tx["creator_id"] != user["id"]:
            raise AppError("FORBIDDEN_ROLE")
        if tx["status"] == "EXPIRED":
            raise AppError("TX_EXPIRED")
        if tx["status"] not in rules.PENDING:
            raise AppError("TX_WRONG_STATE")
        db.execute("UPDATE transactions SET status = 'CANCELLED' WHERE id = ?", (tx_id,))
        append_audit("TX_CANCELLED", user["id"], {"tx_id": tx_id})
    return {"id": tx_id, "status": "CANCELLED"}
