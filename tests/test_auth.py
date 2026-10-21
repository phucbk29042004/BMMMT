"""Test phần TV1: xác thực email OTP, khóa tài khoản, người dùng."""
from app import db, ratelimit
from app.config import settings
from app.routers import auth as auth_router
from app.services.email import EmailDeliveryError
from scripts.seed import DEV_PASSWORD
from conftest import _EMAIL_CODES, err, login


def test_login_password_then_email_otp(make_client):
    c = make_client()
    r1 = c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD})
    assert r1.status_code == 200
    assert r1.json() == {"status": "MFA_REQUIRED", "email_hint": "q*******@example.test"}
    code = _EMAIL_CODES["quanly01"]
    r2 = c.post("/api/auth/mfa", json={"code": code})
    assert r2.status_code == 200
    assert r2.json()["user"] == {"id": 3, "username": "quanly01", "role": "manager"}
    me = c.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["username"] == "quanly01"
    assert code not in r1.text and "password_hash" not in r2.text


def test_wrong_password_and_unknown_user_give_same_error(make_client):
    c = make_client()
    a = c.post("/api/auth/login", json={"username": "quanly01", "password": "sai-mat-khau"})
    b = c.post("/api/auth/login", json={"username": "khong-ton-tai", "password": "sai-mat-khau"})
    assert a.status_code == b.status_code == 401
    assert err(a) == err(b) == "AUTH_INVALID_CREDENTIALS"
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_tc12_password_ok_but_wrong_email_code(make_client):
    c = make_client()
    c.post("/api/auth/login", json={"username": "giamdoc01", "password": DEV_PASSWORD})
    wrong_code = "000000" if _EMAIL_CODES["giamdoc01"] != "000000" else "000001"
    r = c.post("/api/auth/mfa", json={"code": wrong_code})
    assert r.status_code == 401 and err(r) == "MFA_INVALID"
    assert c.get("/api/auth/me").status_code == 401


def test_password_only_session_cannot_call_other_apis(make_client):
    c = make_client()
    c.post("/api/auth/login", json={"username": "admin01", "password": DEV_PASSWORD})
    r = c.get("/api/users")
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"


def test_mfa_without_login_step_one(make_client):
    r = make_client().post("/api/auth/mfa", json={"code": "123456"})
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"


def test_email_code_cannot_be_reused(make_client):
    c = make_client()
    c.post("/api/auth/login", json={"username": "quanly02", "password": DEV_PASSWORD})
    code = _EMAIL_CODES["quanly02"]
    assert c.post("/api/auth/mfa", json={"code": code}).status_code == 200
    r = c.post("/api/auth/mfa", json={"code": code})
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"


def test_email_code_resend_replaces_previous_code(make_client, monkeypatch):
    codes = iter((123456, 654321))
    monkeypatch.setattr(auth_router.secrets, "randbelow", lambda _: next(codes))
    c = make_client()
    c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD})
    old_code = _EMAIL_CODES["quanly01"]
    r = c.post("/api/auth/mfa/resend")
    assert r.status_code == 200
    new_code = _EMAIL_CODES["quanly01"]
    assert new_code != old_code
    assert err(c.post("/api/auth/mfa", json={"code": old_code})) == "MFA_INVALID"
    assert c.post("/api/auth/mfa", json={"code": new_code}).status_code == 200


def test_email_delivery_failure_is_reported(make_client, monkeypatch):
    def fail_delivery(*args):
        raise EmailDeliveryError("SMTP unavailable")

    monkeypatch.setattr(auth_router, "send_login_code", fail_delivery)
    r = make_client().post("/api/auth/login", json={"username": "admin01", "password": DEV_PASSWORD})
    assert r.status_code == 503 and err(r) == "MFA_DELIVERY_FAILED"


def test_expired_email_code_is_rejected(make_client):
    import json

    c = make_client()
    c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD})
    row = db.query_one("SELECT id, data_json FROM sessions ORDER BY created_at DESC LIMIT 1")
    data = json.loads(row["data_json"])
    data["pending"]["otp_expires_at"] = "2000-01-01T00:00:00.000Z"
    db.execute("UPDATE sessions SET data_json = ? WHERE id = ?", (json.dumps(data), row["id"]))
    r = c.post("/api/auth/mfa", json={"code": _EMAIL_CODES["quanly01"]})
    assert r.status_code == 401 and err(r) == "MFA_INVALID"


def test_logout_destroys_session_even_for_stolen_cookie(make_client):
    victim = login(make_client(), "ketoan01")
    stolen = victim.cookies.get("connect.sid")
    assert stolen
    assert victim.post("/api/auth/logout").status_code == 204
    thief = make_client()
    thief.cookies.set("connect.sid", stolen)
    r = thief.get("/api/auth/me")
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"


def test_session_cookie_flags(make_client):
    c = make_client()
    r = c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_new_session_issued_after_login_steps(make_client):
    c = make_client()
    r = c.post(
        "/api/auth/login",
        json={"username": "quanly01", "password": DEV_PASSWORD},
        headers={"Cookie": "connect.sid=fixated-by-attacker"},
    )
    issued = r.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    assert issued and issued != "fixated-by-attacker"


def test_tc17_lock_after_five_wrong_passwords(login_as, make_client):
    admin = login_as("admin01")
    admin.post("/api/users", json={
        "username": "nan.nhan", "password": "MatKhau@12345", "role": "manager",
        "email": "nan.nhan@example.test",
    })
    c = make_client()
    for _ in range(settings.max_login_attempts):
        r = c.post("/api/auth/login", json={"username": "nan.nhan", "password": "sai-mat-khau"})
        assert err(r) == "AUTH_INVALID_CREDENTIALS"
    locked = c.post("/api/auth/login", json={"username": "nan.nhan", "password": "MatKhau@12345"})
    assert locked.status_code == 423 and err(locked) == "ACCOUNT_LOCKED"


def test_admin_is_never_account_locked(make_client):
    db.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = 'admin01'",
        (settings.max_login_attempts - 1, "2099-01-01T00:00:00.000Z"),
    )
    c = make_client()
    for _ in range(settings.max_login_attempts + 1):
        r = c.post("/api/auth/login", json={"username": "admin01", "password": "sai-mat-khau"})
        assert r.status_code == 401 and err(r) == "AUTH_INVALID_CREDENTIALS"

    row = db.query_one("SELECT failed_attempts, locked_until FROM users WHERE username = 'admin01'")
    assert row["failed_attempts"] == 0 and row["locked_until"] is None
    c.post("/api/auth/login", json={"username": "admin01", "password": DEV_PASSWORD})
    wrong_code = "000000" if _EMAIL_CODES["admin01"] != "000000" else "000001"
    for _ in range(settings.max_login_attempts + 1):
        r = c.post("/api/auth/mfa", json={"code": wrong_code})
        assert r.status_code == 401 and err(r) == "MFA_INVALID"

    row = db.query_one("SELECT failed_attempts, locked_until FROM users WHERE username = 'admin01'")
    assert row["failed_attempts"] == 0 and row["locked_until"] is None
    assert c.post("/api/auth/mfa", json={"code": _EMAIL_CODES["admin01"]}).status_code == 200


def test_tc17_rate_limit_on_real_route(make_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_max", 3)
    ratelimit.reset()
    c = make_client()
    for _ in range(3):
        assert c.post("/api/auth/login", json={"username": "ai-do", "password": "sai"}).status_code == 401
    r = c.post("/api/auth/login", json={"username": "ai-do", "password": "sai"})
    assert r.status_code == 429 and err(r) == "RATE_LIMITED"


def test_tc16_non_admin_cannot_manage_users(login_as):
    r = login_as("ketoan01").post(
        "/api/users",
        json={"username": "ke.tan.cong", "password": "MatKhau@12345", "role": "admin",
              "email": "ke.tan.cong@example.test"},
    )
    assert r.status_code == 403 and err(r) == "FORBIDDEN_ROLE"


def test_admin_creates_user_duplicate_and_weak_password(login_as):
    admin = login_as("admin01")
    payload = {"username": "ketoan02", "password": "MatKhau@12345", "role": "accountant",
               "email": "ketoan02@example.test"}
    ok = admin.post("/api/users", json=payload)
    assert ok.status_code == 201
    dup = admin.post("/api/users", json=payload)
    assert dup.status_code == 409 and err(dup) == "USERNAME_TAKEN"
    duplicate_email = admin.post(
        "/api/users",
        json={**payload, "username": "ketoan03", "email": "KETOAN02@example.test"},
    )
    assert duplicate_email.status_code == 409 and err(duplicate_email) == "EMAIL_TAKEN"
    weak = admin.post("/api/users", json={**payload, "username": "ketoan03", "password": "123"})
    assert weak.status_code == 400 and err(weak) == "VALIDATION_ERROR"
    users = admin.get("/api/users").json()["users"]
    assert all("password_hash" not in u for u in users)


def test_password_stored_as_argon2(fresh_db):
    row = db.query_one("SELECT password_hash FROM users WHERE username = 'ketoan01'")
    assert row["password_hash"].startswith("$argon2") and DEV_PASSWORD not in row["password_hash"]


def test_error_format_for_unknown_route_and_broken_json(make_client):
    c = make_client()
    r = c.get("/api/khong-co")
    assert err(r) == "VALIDATION_ERROR"
    bad = c.post("/api/auth/login", content="{broken", headers={"Content-Type": "application/json"})
    assert bad.status_code == 400 and err(bad) == "VALIDATION_ERROR"
    assert set(bad.json()["error"]) == {"code", "message", "details"}
