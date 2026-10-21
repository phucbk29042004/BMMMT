"""Kiểm thử chéo Python <-> JavaScript (WebCrypto). Vector tạo bằng chính WebCrypto của Node.js,
chứng minh server Python kiểm tra đúng chữ ký do TRÌNH DUYỆT tạo ra và canonical JSON khớp từng byte."""
import json
import os

from app.services.crypto import build_signing_string, canonicalize, verify_signature

VECTOR = json.load(open(os.path.join(os.path.dirname(__file__), "vectors", "webcrypto_vector.json"), encoding="utf-8"))


def test_signature_created_by_webcrypto_verifies_in_python():
    assert verify_signature(VECTOR["spki"], VECTOR["s"], VECTOR["sig"]) is True


def test_webcrypto_signature_fails_if_one_character_changes():
    assert verify_signature(VECTOR["spki"], VECTOR["s"].replace("200000000", "200000001"), VECTOR["sig"]) is False


def test_canonical_json_matches_javascript_byte_for_byte_including_vietnamese():
    obj = {
        "action": "APPROVE", "amount": 200000000, "approver_id": 3, "currency": "VND", "device_id": 7,
        "expires_at": "2026-10-02T08:35:00.000Z", "level": 1, "nonce": "b3f1c2d4e5a60718293a4b5c6d7e8f90",
        "recipient_account": "0123456789", "recipient_name": 'CÔNG TY TNHH Ánh Dương "ABC" & Đối tác',
        "tx_created_at": "2026-10-02T08:30:00.000Z", "tx_id": 15, "v": 1,
    }
    shuffled = dict(reversed(list(obj.items())))
    assert canonicalize(shuffled) == VECTOR["s"]


def test_signing_string_matches_api_md_example():
    tx = {"id": 15, "amount": 200000000, "currency": "VND", "recipient_account": "0123456789",
          "recipient_name": "CONG TY ABC", "created_at": "2026-10-02T08:30:00.000Z"}
    expected = (
        '{"action":"APPROVE","amount":200000000,"approver_id":3,"currency":"VND","device_id":7,'
        '"expires_at":"2026-10-02T08:35:00.000Z","level":1,"nonce":"b3f1c2d4e5a60718293a4b5c6d7e8f90",'
        '"recipient_account":"0123456789","recipient_name":"CONG TY ABC",'
        '"tx_created_at":"2026-10-02T08:30:00.000Z","tx_id":15,"v":1}'
    )
    got = build_signing_string(tx, 1, 3, 7, "b3f1c2d4e5a60718293a4b5c6d7e8f90", "2026-10-02T08:35:00.000Z")
    assert got == expected


def test_wrong_length_signature_rejected():
    assert verify_signature(VECTOR["spki"], VECTOR["s"], "AAAA") is False
