"""Test phần TV1: đăng ký / thu hồi thiết bị."""
from app import db
from app.timeutil import iso, now
from datetime import timedelta

from conftest import err, register_device


def test_register_device_with_proof_of_possession(login_as, make_key):
    c = login_as("giamdoc01")
    _, res = register_device(c, make_key(), "Laptop giám đốc")
    assert res.status_code == 201 and res.json()["status"] == "active"
    listed = c.get("/api/devices").json()["devices"]
    assert any(d["id"] == res.json()["id"] for d in listed)


def test_tc07_device_challenge_replay(login_as, make_key):
    c = login_as("giamdoc01")
    key = make_key()
    challenge, res = register_device(c, key)
    assert res.status_code == 201
    replay = c.post("/api/devices/register", json={"label": "Replay", "public_key": make_key().public_key_b64,
                                                   "challenge": challenge, "signature": key.sign(challenge)})
    assert replay.status_code == 409 and err(replay) == "NONCE_USED"


def test_tc09_register_public_key_without_private_key(login_as, make_key):
    c = login_as("quanly01")
    victim, attacker = make_key(), make_key()
    challenge = c.post("/api/devices/challenge").json()["challenge"]
    r = c.post("/api/devices/register", json={"label": "Giả mạo", "public_key": victim.public_key_b64,
                                              "challenge": challenge, "signature": attacker.sign(challenge)})
    assert r.status_code == 403 and err(r) == "SIGNATURE_INVALID"


def test_unknown_challenge(login_as, make_key):
    c = login_as("quanly01")
    key, fake = make_key(), "a" * 32
    r = c.post("/api/devices/register", json={"label": "X", "public_key": key.public_key_b64,
                                              "challenge": fake, "signature": key.sign(fake)})
    assert r.status_code == 400 and err(r) == "NONCE_UNKNOWN"


def test_challenge_issued_to_another_user_is_unknown(login_as, make_key):
    a, b = login_as("quanly01"), login_as("quanly02")
    challenge = a.post("/api/devices/challenge").json()["challenge"]
    key = make_key()
    r = b.post("/api/devices/register", json={"label": "X", "public_key": key.public_key_b64,
                                              "challenge": challenge, "signature": key.sign(challenge)})
    assert err(r) == "NONCE_UNKNOWN"


def test_expired_challenge(login_as, make_key):
    c = login_as("quanly01")
    key = make_key()
    challenge = c.post("/api/devices/challenge").json()["challenge"]
    db.execute("UPDATE nonces SET expires_at = ? WHERE nonce = ?", (iso(now() - timedelta(seconds=1)), challenge))
    r = c.post("/api/devices/register", json={"label": "X", "public_key": key.public_key_b64,
                                              "challenge": challenge, "signature": key.sign(challenge)})
    assert r.status_code == 400 and err(r) == "NONCE_EXPIRED"


def test_garbage_key_rejected(login_as):
    c = login_as("quanly01")
    challenge = c.post("/api/devices/challenge").json()["challenge"]
    r = c.post("/api/devices/register", json={"label": "X", "public_key": "AAAA", "challenge": challenge,
                                              "signature": "AAAA"})
    assert r.status_code == 400 and err(r) == "VALIDATION_ERROR"


def test_device_limit(login_as, make_key):
    c = login_as("ketoan01")
    for i in range(3):
        assert register_device(c, make_key(), f"Máy {i}")[1].status_code == 201
    res = register_device(c, make_key(), "Máy 4")[1]
    assert res.status_code == 409 and err(res) == "DEVICE_LIMIT"


def test_tc11_revoke_device_permissions(login_as, make_key):
    owner, other, admin = login_as("quanly02"), login_as("quanly01"), login_as("admin01")
    device_id = register_device(owner, make_key(), "Điện thoại")[1].json()["id"]
    denied = other.post(f"/api/devices/{device_id}/revoke")
    assert denied.status_code == 403 and err(denied) == "FORBIDDEN_ROLE"
    assert owner.post(f"/api/devices/{device_id}/revoke").json()["status"] == "revoked"
    status = {d["id"]: d["status"] for d in owner.get("/api/devices").json()["devices"]}
    assert status[device_id] == "revoked"
    nf = owner.post("/api/devices/99999/revoke")
    assert nf.status_code == 404 and err(nf) == "DEVICE_NOT_FOUND"
    # admin thu hồi được thiết bị của người khác
    d2 = register_device(owner, make_key(), "Máy 2")[1].json()["id"]
    assert admin.post(f"/api/devices/{d2}/revoke").status_code == 200


def test_device_endpoints_require_login(make_client):
    r = make_client().post("/api/devices/challenge")
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"
