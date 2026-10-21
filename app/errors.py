"""Bảng mã lỗi dùng chung - khớp với mục 9 của docs/API.md.

Mỗi mã: (HTTP status, thông báo tiếng Việt hiển thị cho người dùng).
Dùng:  raise AppError("NONCE_USED")
"""
from typing import Any, Dict, Optional

CATALOG = {
    "VALIDATION_ERROR": (400, "Dữ liệu gửi lên sai định dạng."),
    "NOT_AUTHENTICATED": (401, "Chưa đăng nhập hoặc chưa hoàn tất xác thực MFA."),
    "AUTH_INVALID_CREDENTIALS": (401, "Sai tên đăng nhập hoặc mật khẩu."),
    "MFA_INVALID": (401, "Mã xác thực sai, hết hạn hoặc đã được sử dụng."),
    "MFA_DELIVERY_FAILED": (503, "Không gửi được mã xác thực qua email. Vui lòng thử lại hoặc liên hệ quản trị viên."),
    "FORBIDDEN_ROLE": (403, "Vai trò của bạn không được phép thực hiện thao tác này."),
    "SELF_APPROVAL": (403, "Người tạo giao dịch không được tự duyệt."),
    "DUPLICATE_APPROVER": (403, "Một người không được duyệt hai cấp của cùng một giao dịch."),
    "DEVICE_NOT_REGISTERED": (403, "Thiết bị chưa được đăng ký hoặc không thuộc về bạn."),
    "DEVICE_REVOKED": (403, "Thiết bị đã bị thu hồi."),
    "SIGNATURE_INVALID": (403, "Chữ ký không hợp lệ (sai khóa hoặc nội dung đã bị sửa)."),
    "SIGNING_PAYLOAD_MISMATCH": (403, "Nội dung được ký không khớp với giao dịch trong hệ thống."),
    "NONCE_UNKNOWN": (400, "Nonce không do hệ thống phát hành."),
    "NONCE_EXPIRED": (400, "Nonce đã hết hạn."),
    "NONCE_USED": (409, "Nonce đã được sử dụng, nghi ngờ tấn công replay."),
    "TX_NOT_FOUND": (404, "Không tìm thấy giao dịch."),
    "DEVICE_NOT_FOUND": (404, "Không tìm thấy thiết bị."),
    "TX_WRONG_STATE": (409, "Giao dịch không ở trạng thái cho phép thao tác này."),
    "TX_EXPIRED": (410, "Giao dịch đã hết hạn."),
    "USERNAME_TAKEN": (409, "Tên đăng nhập đã tồn tại."),
    "EMAIL_TAKEN": (409, "Email đã được gán cho tài khoản khác."),
    "DEVICE_LIMIT": (409, "Đã đạt số thiết bị tối đa."),
    "ACCOUNT_LOCKED": (423, "Tài khoản đang bị khóa tạm thời."),
    "RATE_LIMITED": (429, "Thử quá nhiều lần, vui lòng chờ một lát."),
    "INTERNAL_ERROR": (500, "Lỗi hệ thống."),
}


class AppError(Exception):
    def __init__(self, code: str, message: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        if code not in CATALOG:
            raise KeyError(f"Mã lỗi không có trong CATALOG: {code}")
        self.code = code
        self.status = CATALOG[code][0]
        self.message = message or CATALOG[code][1]
        self.details = details or {}
        super().__init__(self.message)
