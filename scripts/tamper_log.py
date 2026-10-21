"""DÙNG ĐỂ DEMO: sửa trực tiếp một dòng audit_log trong SQLite, giả lập kẻ xấu xóa dấu vết.
Sau đó gọi GET /api/audit/verify để thấy chuỗi bị đứt đúng tại dòng đó.

    python -m scripts.tamper_log <id_dong_log>
"""
import sqlite3
import sys

from app.config import settings

if len(sys.argv) != 2:
    sys.exit("Cách dùng: python -m scripts.tamper_log <id_dong_log>")
conn = sqlite3.connect(settings.db_path)
cur = conn.execute("UPDATE audit_log SET data_json = '{\"tampered\":true}' WHERE id = ?", (int(sys.argv[1]),))
conn.commit()
print(f"Đã sửa {cur.rowcount} dòng (id={sys.argv[1]}).")
