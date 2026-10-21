"""Dịch vụ mật mã dùng chung (TV2 sở hữu).

Điểm sống còn: chuỗi cần ký phải GIỐNG TỪNG BYTE giữa server (Python) và trình duyệt (JavaScript).
Vì vậy server luôn là bên tạo `signing_string`; trình duyệt chỉ ký nguyên văn chuỗi đó.
"""
import base64
import hashlib
import json
import secrets
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def canonicalize(value: Any) -> str:
    """Canonical JSON: khóa sắp xếp theo bảng chữ cái (đệ quy), không khoảng trắng, UTF-8.
    ensure_ascii=False BẮT BUỘC để chuỗi tiếng Việt có dấu khớp với JSON.stringify của JavaScript."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def random_hex(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


def _load_public_key(public_key_b64: str) -> ec.EllipticCurvePublicKey:
    der = base64.b64decode(public_key_b64, validate=True)
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Khóa phải là ECDSA P-256")
    return key


def is_valid_p256_public_key(public_key_b64: str) -> bool:
    try:
        _load_public_key(public_key_b64)
        return True
    except Exception:
        return False


def verify_signature(public_key_b64: str, signing_string: str, signature_b64: str) -> bool:
    """Kiểm tra chữ ký ECDSA P-256 / SHA-256, định dạng IEEE P1363 (r‖s, 64 byte) như WebCrypto trả về.
    Thư viện `cryptography` cần dạng DER nên phải đổi r‖s -> DER (đây là chỗ nhiều nhóm sai)."""
    try:
        raw = base64.b64decode(signature_b64, validate=True)
        if len(raw) != 64:
            return False
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        der = encode_dss_signature(r, s)
        _load_public_key(public_key_b64).verify(der, signing_string.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def build_signing_string(
    tx: Dict[str, Any],
    level: int,
    approver_id: int,
    device_id: int,
    nonce: str,
    nonce_expires_at: str,
    action: str = "APPROVE",
) -> str:
    """Dựng chuỗi cần ký (mục 3 của docs/API.md) TỪ DỮ LIỆU TRONG DB, không bao giờ từ dữ liệu client."""
    return canonicalize(
        {
            "action": action,
            "amount": int(tx["amount"]),
            "approver_id": int(approver_id),
            "currency": tx["currency"],
            "device_id": int(device_id),
            "expires_at": nonce_expires_at,
            "level": int(level),
            "nonce": nonce,
            "recipient_account": tx["recipient_account"],
            "recipient_name": tx["recipient_name"],
            "tx_created_at": tx["created_at"],
            "tx_id": int(tx["id"]),
            "v": 1,
        }
    )
