"""Audit log dạng hash chain (mục 11 của docs/API.md). TV2 sở hữu.

    hash = SHA256( prev_hash | event | actor_id | canonical(data) | created_at )

Dòng đầu (genesis) có prev_hash = 64 ký tự '0'. Sửa hoặc xóa một dòng giữa chuỗi sẽ làm đứt chuỗi.
Giới hạn: cắt bớt các dòng CUỐI chuỗi thì không tự phát hiện được; muốn chống phải neo hash ra ngoài
(dịch vụ timestamp bên thứ ba) - nêu trong báo cáo ở mục hướng phát triển dài hạn.
"""
import json
from typing import Any, Dict, Optional

from app import db
from app.services.crypto import canonicalize, sha256_hex
from app.timeutil import now_iso

GENESIS_HASH = "0" * 64


def compute_hash(prev_hash: str, event: str, actor_id: Optional[int], data: Any, created_at: str) -> str:
    parts = [prev_hash, event, str(actor_id or 0), canonicalize(data if data is not None else {}), created_at]
    return sha256_hex("|".join(parts))


def append_audit(event: str, actor_id: Optional[int] = 0, data: Optional[Dict[str, Any]] = None) -> None:
    """Ghi một dòng log. Tuần tự hóa bằng transaction; gọi lồng trong transaction khác được."""
    data = data or {}
    with db.transaction():
        last = db.query_one("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
        prev_hash = last["hash"] if last else GENESIS_HASH
        created_at = now_iso()
        actor = actor_id or 0
        digest = compute_hash(prev_hash, event, actor, data, created_at)
        db.execute(
            "INSERT INTO audit_log (event, actor_id, data_json, prev_hash, hash, created_at) VALUES (?,?,?,?,?,?)",
            (event, actor, canonicalize(data), prev_hash, digest, created_at),
        )


def verify_chain() -> Dict[str, Any]:
    """Duyệt lại từ đầu. Trả {valid, checked, broken_at, reason?}."""
    rows = db.query_all("SELECT * FROM audit_log ORDER BY id ASC")
    expected_prev = GENESIS_HASH
    checked = 0
    for row in rows:
        checked += 1
        if row["prev_hash"] != expected_prev:
            return {"valid": False, "checked": checked, "broken_at": row["id"], "reason": "PREV_HASH_MISMATCH"}
        recomputed = compute_hash(
            row["prev_hash"], row["event"], row["actor_id"], json.loads(row["data_json"]), row["created_at"]
        )
        if recomputed != row["hash"]:
            return {"valid": False, "checked": checked, "broken_at": row["id"], "reason": "HASH_MISMATCH"}
        expected_prev = row["hash"]
    return {"valid": True, "checked": checked, "broken_at": None}
