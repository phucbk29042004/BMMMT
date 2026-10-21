"""Cấu hình chung cho test. Đặt biến môi trường TRƯỚC khi import app."""
import base64
import os

os.environ["DB_PATH"] = ":memory:"
os.environ["RATE_LIMIT_MAX"] = "1000"  # tắt rate limit mặc định; test_ratelimit tự hạ xuống
os.environ["ADMIN_EMAIL"] = ""

import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from app import db, ratelimit
from app.config import settings
from app.main import app
from app.routers import auth as auth_router
from scripts.seed import DEV_PASSWORD, seed

_PW_HASH = PasswordHasher().hash(DEV_PASSWORD)  # băm một lần cho cả phiên test
_EMAIL_CODES = {}


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    db.reset_for_tests()
    ratelimit.reset()
    _EMAIL_CODES.clear()
    monkeypatch.setattr(settings, "admin_email", "")
    monkeypatch.setattr(
        auth_router,
        "send_login_code",
        lambda recipient, username, code: _EMAIL_CODES.__setitem__(username, code),
    )
    seed(password_hash=_PW_HASH)
    yield


@pytest.fixture
def make_client():
    clients = []

    def _make():
        c = TestClient(app)
        clients.append(c)
        return c

    yield _make
    for c in clients:
        c.close()


def login(client, username, password=DEV_PASSWORD):
    """Đăng nhập đầy đủ bằng email OTP."""
    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
               (username,))
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    r = client.post("/api/auth/mfa", json={"code": _EMAIL_CODES[username]})
    assert r.status_code == 200, r.text
    return client


@pytest.fixture
def login_as(make_client):
    def _login(username):
        return login(make_client(), username)

    return _login


class Key:
    """Cặp khóa ECDSA P-256 giả lập thiết bị/trình duyệt: ký theo định dạng IEEE P1363 như WebCrypto."""

    def __init__(self):
        self._private = ec.generate_private_key(ec.SECP256R1())
        self.public_key_b64 = base64.b64encode(
            self._private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()

    def sign(self, text: str) -> str:
        der = self._private.sign(text.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


@pytest.fixture
def make_key():
    return Key


def register_device(client, key, label="Laptop"):
    ch = client.post("/api/devices/challenge")
    assert ch.status_code == 200, ch.text
    challenge = ch.json()["challenge"]
    res = client.post(
        "/api/devices/register",
        json={"label": label, "public_key": key.public_key_b64, "challenge": challenge, "signature": key.sign(challenge)},
    )
    return challenge, res


def err(res):
    return res.json()["error"]["code"]
