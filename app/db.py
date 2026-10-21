"""Truy cập SQLite (TV1 sở hữu).

Thiết kế: MỘT kết nối dùng chung + MỘT khóa toàn cục (RLock). Mọi thao tác DB và mọi transaction
đều tuần tự hóa qua khóa này. Nhờ vậy:
  - ghi audit log hash chain luôn tuần tự (prev_hash đúng),
  - đánh dấu nonce 'đã dùng' là nguyên tử (chống replay song song).
Đánh đổi: không song song hóa được, đủ cho đồ án/demo.

Dùng:
    from app import db
    row  = db.query_one("SELECT * FROM users WHERE id = ?", (1,))
    rows = db.query_all("SELECT * FROM devices")
    with db.transaction():            # có thể lồng nhau; lỗi => ROLLBACK toàn bộ
        db.execute("UPDATE ...", (...))
"""
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None
_depth = 0

_SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")
# Thứ tự xóa an toàn với khóa ngoại (con trước, cha sau)
_TABLES = ["approvals", "nonces", "audit_log", "sessions", "transactions", "devices", "users"]


def init(path: str) -> None:
    """Mở DB và tạo bảng. Gọi nhiều lần vẫn an toàn."""
    global _conn
    with _lock:
        if _conn is not None:
            return
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
        with open(_SCHEMA, encoding="utf-8") as f:
            conn.executescript(f.read())
        _conn = conn


def _c() -> sqlite3.Connection:
    if _conn is None:
        raise RuntimeError("DB chưa khởi tạo: gọi db.init(path) trước.")
    return _conn


def execute(sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
    with _lock:
        return _c().execute(sql, tuple(params))


def query_one(sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
    with _lock:
        row = _c().execute(sql, tuple(params)).fetchone()
        return dict(row) if row else None


def query_all(sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    with _lock:
        return [dict(r) for r in _c().execute(sql, tuple(params)).fetchall()]


@contextmanager
def transaction():
    """BEGIN IMMEDIATE ... COMMIT; gặp lỗi thì ROLLBACK. Gọi lồng trong transaction khác được."""
    global _depth
    with _lock:
        if _depth > 0:  # đã trong transaction: dùng chung, lỗi sẽ làm ROLLBACK ở lớp ngoài
            _depth += 1
            try:
                yield
            finally:
                _depth -= 1
            return
        conn = _c()
        conn.execute("BEGIN IMMEDIATE")
        _depth = 1
        try:
            yield
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
        finally:
            _depth = 0


def reset_for_tests() -> None:
    """Xóa sạch dữ liệu (chỉ dùng trong test)."""
    with _lock:
        for t in _TABLES:
            _c().execute(f"DELETE FROM {t}")
        _c().execute("DELETE FROM sqlite_sequence")
