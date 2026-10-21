"""Test phần TV1: xác thực, TOTP, khóa tài khoản, người dùng."""
import pyotp

from app import db, ratelimit
from app.config import settings
from scripts.seed import DEV_PASSWORD, DEV_TOTP_SECRET

from conftest import err, login


def totp():
    return pyotp.TOTP(DEV_TOTP_SECRET).now()


def test_tc01_login_password_and_totp(make_client):
    c = make_client()
    r1 = c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD})
    assert r1.status_code == 200 and r1.json() == {"status": "MFA_REQUIRED"}
    r2 = c.post("/api/auth/mfa", json={"code": totp()})
    assert r2.status_code == 200
    assert r2.json()["user"] == {"id": 3, "username": "quanly01", "role": "manager"}
    me = c.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["username"] == "quanly01"
    assert "password_hash" not in r2.text and "totp_secret" not in r2.text


def test_wrong_password_and_unknown_user_give_same_error(make_client):
    c = make_client()
    a = c.post("/api/auth/login", json={"username": "quanly01", "password": "sai-mat-khau"})
    b = c.post("/api/auth/login", json={"username": "khong-ton-tai", "password": "sai-mat-khau"})
    assert a.status_code == b.status_code == 401
    assert err(a) == err(b) == "AUTH_INVALID_CREDENTIALS"
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_tc12_password_ok_but_wrong_totp(make_client):
    c = make_client()
    c.post("/api/auth/login", json={"username": "giamdoc01", "password": DEV_PASSWORD})
    r = c.post("/api/auth/mfa", json={"code": "000000"})
    assert r.status_code == 401 and err(r) == "MFA_INVALID"
    assert c.get("/api/auth/me").status_code == 401


def test_password_only_session_cannot_call_other_apis(make_client):
    c = make_client()
    c.post("/api/auth/login", json={"username": "admin01", "password": DEV_PASSWORD})
    r = c.get("/api/users")
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"


def test_mfa_without_login_step_one(make_client):
    r = make_client().post("/api/auth/mfa", json={"code": totp()})
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"


def test_totp_code_cannot_be_reused(make_client):
    code = totp()
    c1, c2 = make_client(), make_client()
    c1.post("/api/auth/login", json={"username": "quanly02", "password": DEV_PASSWORD})
    assert c1.post("/api/auth/mfa", json={"code": code}).status_code == 200
    c2.post("/api/auth/login", json={"username": "quanly02", "password": DEV_PASSWORD})
    r = c2.post("/api/auth/mfa", json={"code": code})
    assert r.status_code == 401 and err(r) == "MFA_INVALID"


def test_first_login_totp_setup_and_confirm(login_as, make_client):
    admin = login_as("admin01")
    assert admin.post("/api/users", json={"username": "nhanvien.moi", "password": "MatKhau@Moi123",
                                          "role": "accountant"}).status_code == 201
    c = make_client()
    r1 = c.post("/api/auth/login", json={"username": "nhanvien.moi", "password": "MatKhau@Moi123"})
    assert r1.json()["status"] == "TOTP_SETUP_REQUIRED"
    setup = c.post("/api/auth/totp/setup")
    assert setup.status_code == 200
    assert setup.json()["otpauth_url"].startswith("otpauth://totp/")
    assert setup.json()["qr_data_url"].startswith("data:image/png;base64,")
    secret = setup.json()["otpauth_url"].split("secret=")[1].split("&")[0]
    r = c.post("/api/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200 and r.json()["user"]["username"] == "nhanvien.moi"


def test_logout_destroys_session_even_for_stolen_cookie(make_client):
    victim = login(make_client(), "ketoan01")
    stolen = victim.cookies.get("connect.sid")
    assert stolen
    assert victim.post("/api/auth/logout").status_code == 204
    thief = make_client()
    thief.cookies.set("connect.sid", stolen)
    r = thief.get("/api/auth/me")
    assert r.status_code == 401 and err(r) == "NOT_AUTHENTICATED"  # phiên lưu server nên bị hủy thật


def test_session_cookie_flags(make_client):
    c = make_client()
    r = c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_new_session_issued_after_login_steps(make_client):
    """Chống session fixation: kẻ tấn công cài sẵn cookie, server vẫn phải cấp token MỚI sau khi đăng nhập."""
    c = make_client()
    r = c.post("/api/auth/login", json={"username": "quanly01", "password": DEV_PASSWORD},
               headers={"Cookie": "connect.sid=fixated-by-attacker"})
    issued = r.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    assert issued and issued != "fixated-by-attacker"


def test_tc17_lock_after_five_wrong_passwords(login_as, make_client):
    admin = login_as("admin01")
    admin.post("/api/users", json={"username": "nan.nhan", "password": "MatKhau@12345", "role": "manager"})
    c = make_client()
    for _ in range(settings.max_login_attempts):
        r = c.post("/api/auth/login", json={"username": "nan.nhan", "password": "sai-mat-khau"})
        assert err(r) == "AUTH_INVALID_CREDENTIALS"
    locked = c.post("/api/auth/login", json={"username": "nan.nhan", "password": "MatKhau@12345"})
    assert locked.status_code == 423 and err(locked) == "ACCOUNT_LOCKED"


def test_tc17_rate_limit_on_real_route(make_client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_max", 3)
    ratelimit.reset()
    c = make_client()
    for _ in range(3):
        assert c.post("/api/auth/login", json={"username": "ai-do", "password": "sai"}).status_code == 401
    r = c.post("/api/auth/login", json={"username": "ai-do", "password": "sai"})
    assert r.status_code == 429 and err(r) == "RATE_LIMITED"


def test_tc16_non_admin_cannot_manage_users(login_as):
    r = login_as("ketoan01").post("/api/users", json={"username": "ke.tan.cong", "password": "MatKhau@12345",
                                                      "role": "admin"})
    assert r.status_code == 403 and err(r) == "FORBIDDEN_ROLE"


def test_admin_creates_user_duplicate_and_weak_password(login_as):
    admin = login_as("admin01")
    ok = admin.post("/api/users", json={"username": "ketoan02", "password": "MatKhau@12345", "role": "accountant"})
    assert ok.status_code == 201
    dup = admin.post("/api/users", json={"username": "ketoan02", "password": "MatKhau@12345", "role": "accountant"})
    assert dup.status_code == 409 and err(dup) == "USERNAME_TAKEN"
    weak = admin.post("/api/users", json={"username": "ketoan03", "password": "123", "role": "accountant"})
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
