"""Test phần TV2: luồng giao dịch, chữ ký, chống giả mạo. Mã TC-xx khớp bảng ở mục 12 của docs/API.md."""
import threading
from datetime import timedelta

from app import db
from app.timeutil import iso, now

from conftest import err, register_device


# ----------------------------------------------------------------- hàm trợ giúp
class World:
    """Dựng sẵn: kế toán, quản lý (có thiết bị), giám đốc (có thiết bị)."""

    def __init__(self, login_as, make_key):
        self.acct = login_as("ketoan01")
        self.mgr = login_as("quanly01")
        self.dir = login_as("giamdoc01")
        self.mgr_key, self.dir_key = make_key(), make_key()
        self.mgr_dev = register_device(self.mgr, self.mgr_key, "PC quản lý")[1].json()["id"]
        self.dir_dev = register_device(self.dir, self.dir_key, "PC giám đốc")[1].json()["id"]

    def create(self, amount=200_000_000, name="CONG TY ABC"):
        r = self.acct.post("/api/transactions", json={"amount": amount, "recipient_account": "0123456789",
                                                      "recipient_name": name, "note": "HĐ 09/2026"})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def challenge(self, client, tx_id, device_id):
        return client.post(f"/api/transactions/{tx_id}/challenge", json={"device_id": device_id})

    def approve(self, client, tx_id, device_id, key):
        """Luồng đúng: challenge -> ký nguyên văn signing_string -> approve."""
        ch = self.challenge(client, tx_id, device_id)
        assert ch.status_code == 200, ch.text
        body = ch.json()
        res = client.post(f"/api/transactions/{tx_id}/approve",
                          json={"device_id": device_id, "nonce": body["nonce"],
                                "signature": key.sign(body["signing_string"])})
        return body, res


import pytest


@pytest.fixture
def w(login_as, make_key):
    return World(login_as, make_key)


def audit_events():
    return [r["event"] for r in db.query_all("SELECT event FROM audit_log ORDER BY id")]


# ----------------------------------------------------------------- tình huống bình thường
def test_tc02_small_transaction_needs_one_approval(w):
    tx = w.create(20_000_000)
    assert w.acct.get(f"/api/transactions/{tx}").json()["required_levels"] == 1
    _, res = w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    assert res.status_code == 200 and res.json()["status"] == "APPROVED"


def test_tc03_large_transaction_needs_two_independent_approvals(w):
    tx = w.create(200_000_000)
    _, r1 = w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    assert r1.status_code == 200 and r1.json()["status"] == "PENDING_L2"
    _, r2 = w.approve(w.dir, tx, w.dir_dev, w.dir_key)
    assert r2.status_code == 200 and r2.json()["status"] == "APPROVED"
    detail = w.dir.get(f"/api/transactions/{tx}").json()
    assert [a["level"] for a in detail["approvals"]] == [1, 2]
    assert [a["approver"]["username"] for a in detail["approvals"]] == ["quanly01", "giamdoc01"]


def test_threshold_boundary(w):
    below = w.create(49_999_999)
    exact = w.create(50_000_000)
    assert w.acct.get(f"/api/transactions/{below}").json()["required_levels"] == 1
    assert w.acct.get(f"/api/transactions/{exact}").json()["required_levels"] == 2


def test_tc04_audit_chain_valid_after_normal_flow(w, login_as):
    tx = w.create()
    w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    w.approve(w.dir, tx, w.dir_dev, w.dir_key)
    admin = login_as("admin01")
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] is True and v["broken_at"] is None and v["checked"] > 5
    events = audit_events()
    for e in ("TX_CREATED", "TX_APPROVED", "TX_FULLY_APPROVED", "DEVICE_REGISTERED"):
        assert e in events


# ----------------------------------------------------------------- tấn công
def test_tc05_voice_impersonation_request_without_signature(w):
    """'Cuộc gọi giả giọng sếp': yêu cầu gấp, không có chữ ký số -> bị từ chối, giao dịch không đổi, có dấu vết."""
    tx = w.create()
    body = w.challenge(w.mgr, tx, w.mgr_dev).json()
    r = w.mgr.post(f"/api/transactions/{tx}/approve", json={"device_id": w.mgr_dev, "nonce": body["nonce"]})
    assert r.status_code == 403 and err(r) == "SIGNATURE_INVALID"
    forged = w.mgr.post(f"/api/transactions/{tx}/approve", json={"device_id": w.mgr_dev, "nonce": body["nonce"],
                                                                  "signature": "A" * 86 + "=="})
    assert err(forged) == "SIGNATURE_INVALID"
    assert db.query_one("SELECT status FROM transactions WHERE id = ?", (tx,))["status"] == "PENDING_L1"
    log = db.query_all("SELECT data_json FROM audit_log WHERE event = 'APPROVAL_REJECTED_BY_SYSTEM'")
    assert len(log) == 2 and all('"SIGNATURE_INVALID"' in r["data_json"] for r in log)


def test_tc06a_amount_changed_after_challenge_is_detected(w):
    """Số tiền bị sửa trong DB sau khi chuỗi ký đã phát hành -> chuỗi dựng lại không còn khớp."""
    tx = w.create(200_000_000)
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    sig = w.mgr_key.sign(ch["signing_string"])
    db.execute("UPDATE transactions SET amount = 900000000 WHERE id = ?", (tx,))
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": sig})
    assert r.status_code == 403 and err(r) == "SIGNING_PAYLOAD_MISMATCH"
    assert db.query_one("SELECT status FROM transactions WHERE id = ?", (tx,))["status"] == "PENDING_L1"


def test_tc06b_signature_over_different_content_is_rejected(w):
    """Người duyệt bị lừa ký nội dung KHÁC (số tiền nhỏ hơn) rồi gửi kèm nonce của giao dịch thật."""
    tx = w.create(200_000_000)
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    tampered = ch["signing_string"].replace('"amount":200000000', '"amount":2000000')
    assert tampered != ch["signing_string"]
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": w.mgr_key.sign(tampered)})
    assert r.status_code == 403 and err(r) == "SIGNATURE_INVALID"


def test_tc07_replay_of_approved_request(w):
    tx = w.create(20_000_000)
    ch, res = w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    assert res.status_code == 200
    replay = w.mgr.post(f"/api/transactions/{tx}/approve",
                        json={"device_id": w.mgr_dev, "nonce": ch["nonce"],
                              "signature": w.mgr_key.sign(ch["signing_string"])})
    assert replay.status_code == 409 and err(replay) == "NONCE_USED"


def test_tc07b_replay_across_levels_is_still_nonce_used(w):
    tx = w.create(200_000_000)
    ch, res = w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    assert res.json()["status"] == "PENDING_L2"
    replay = w.mgr.post(f"/api/transactions/{tx}/approve",
                        json={"device_id": w.mgr_dev, "nonce": ch["nonce"],
                              "signature": w.mgr_key.sign(ch["signing_string"])})
    assert err(replay) == "NONCE_USED"


def test_tc08_expired_nonce(w):
    tx = w.create()
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    db.execute("UPDATE nonces SET expires_at = ? WHERE nonce = ?", (iso(now() - timedelta(seconds=1)), ch["nonce"]))
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": w.mgr_key.sign(ch["signing_string"])})
    assert r.status_code == 400 and err(r) == "NONCE_EXPIRED"


def test_nonce_from_another_transaction_is_unknown(w):
    tx1, tx2 = w.create(), w.create()
    ch = w.challenge(w.mgr, tx1, w.mgr_dev).json()
    r = w.mgr.post(f"/api/transactions/{tx2}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": w.mgr_key.sign(ch["signing_string"])})
    assert err(r) == "NONCE_UNKNOWN"


def test_made_up_nonce_is_unknown(w, make_key):
    tx = w.create()
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": "f" * 32, "signature": w.mgr_key.sign("x")})
    assert err(r) == "NONCE_UNKNOWN"


def test_tc09_signature_by_unknown_key(w, make_key):
    tx = w.create()
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    attacker = make_key()
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": attacker.sign(ch["signing_string"])})
    assert r.status_code == 403 and err(r) == "SIGNATURE_INVALID"


def test_tc10_device_not_registered_or_not_owned(w, login_as, make_key):
    tx = w.create()
    # thiết bị không tồn tại
    assert err(w.challenge(w.mgr, tx, 9999)) == "DEVICE_NOT_REGISTERED"
    # thiết bị của người khác (giám đốc) mà quản lý đem ra dùng
    assert err(w.challenge(w.mgr, tx, w.dir_dev)) == "DEVICE_NOT_REGISTERED"
    # trực tiếp ở bước approve với thiết bị của người khác
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.dir_dev, "nonce": ch["nonce"], "signature": w.dir_key.sign(ch["signing_string"])})
    assert err(r) == "DEVICE_NOT_REGISTERED"


def test_tc11_revoked_device(w):
    tx = w.create()
    w.mgr.post(f"/api/devices/{w.mgr_dev}/revoke")
    assert err(w.challenge(w.mgr, tx, w.mgr_dev)) == "DEVICE_REVOKED"


def test_tc11b_device_revoked_between_challenge_and_approve(w):
    tx = w.create()
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    w.mgr.post(f"/api/devices/{w.mgr_dev}/revoke")  # mất máy ngay sau khi xin challenge
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": w.mgr_key.sign(ch["signing_string"])})
    assert r.status_code == 403 and err(r) == "DEVICE_REVOKED"


def test_tc13_account_takeover_without_device(w, make_client):
    """Kẻ có phiên đăng nhập của quản lý nhưng KHÔNG có khóa riêng của thiết bị đã đăng ký."""
    tx = w.create()
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    # cùng phiên, nhưng kẻ tấn công chỉ có thể ký bằng khóa tự sinh
    from conftest import Key
    r = w.mgr.post(f"/api/transactions/{tx}/approve",
                   json={"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": Key().sign(ch["signing_string"])})
    assert err(r) == "SIGNATURE_INVALID"
    assert db.query_one("SELECT status FROM transactions WHERE id = ?", (tx,))["status"] == "PENDING_L1"


def test_tc14_self_approval(w):
    tx = w.create()
    db.execute("UPDATE users SET role = 'manager' WHERE username = 'ketoan01'")  # người tạo sau đó có quyền duyệt
    from conftest import Key
    key = Key()
    dev = register_device(w.acct, key, "PC kế toán")[1].json()["id"]
    r = w.challenge(w.acct, tx, dev)
    assert r.status_code == 403 and err(r) == "SELF_APPROVAL"


def test_tc15_same_person_cannot_approve_both_levels(w):
    tx = w.create(200_000_000)
    w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    db.execute("UPDATE users SET role = 'director' WHERE username = 'quanly01'")  # quản lý được thăng làm giám đốc
    r = w.challenge(w.mgr, tx, w.mgr_dev)
    assert r.status_code == 403 and err(r) == "DUPLICATE_APPROVER"


def test_tc16_roles(w):
    tx = w.create()
    assert err(w.challenge(w.acct, tx, w.mgr_dev)) == "FORBIDDEN_ROLE"
    r = w.acct.post(f"/api/transactions/{tx}/approve", json={"device_id": 1, "nonce": "a" * 32, "signature": "AAAA"})
    assert err(r) == "FORBIDDEN_ROLE"
    assert err(w.mgr.post("/api/transactions", json={"amount": 1000000, "recipient_account": "0123456789",
                                                     "recipient_name": "ABC"})) == "FORBIDDEN_ROLE"
    # giám đốc không được duyệt thay cấp 1; quản lý không được duyệt cấp 2
    assert err(w.challenge(w.dir, tx, w.dir_dev)) == "FORBIDDEN_ROLE"
    w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    tx2 = w.create(300_000_000)
    w.approve(w.mgr, tx2, w.mgr_dev, w.mgr_key)
    assert err(w.challenge(w.mgr, tx2, w.mgr_dev)) == "FORBIDDEN_ROLE"


def test_admin_cannot_approve_or_view_transactions(w, login_as):
    admin = login_as("admin01")
    tx = w.create()
    assert err(admin.get("/api/transactions")) == "FORBIDDEN_ROLE"
    assert err(admin.get(f"/api/transactions/{tx}")) == "FORBIDDEN_ROLE"
    assert err(admin.post(f"/api/transactions/{tx}/challenge", json={"device_id": 1})) == "FORBIDDEN_ROLE"


def test_tc18_audit_log_tampering_is_detected(w, login_as):
    tx = w.create()
    w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    admin = login_as("admin01")
    assert admin.get("/api/audit/verify").json()["valid"] is True
    victim = db.query_one("SELECT id FROM audit_log WHERE event = 'TX_CREATED'")["id"]
    db.execute("UPDATE audit_log SET data_json = ? WHERE id = ?", ('{"amount":1,"tx_id":1}', victim))
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] is False and v["broken_at"] == victim and v["reason"] == "HASH_MISMATCH"


def test_tc18b_deleted_log_row_is_detected(w, login_as):
    tx = w.create()
    w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    admin = login_as("admin01")
    rows = db.query_all("SELECT id FROM audit_log ORDER BY id")
    middle = rows[len(rows) // 2]["id"]
    db.execute("DELETE FROM audit_log WHERE id = ?", (middle,))
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] is False and v["reason"] == "PREV_HASH_MISMATCH"


def test_tc19_expired_transaction(w):
    tx = w.create()
    db.execute("UPDATE transactions SET expires_at = ? WHERE id = ?", (iso(now() - timedelta(minutes=1)), tx))
    r = w.challenge(w.mgr, tx, w.mgr_dev)
    assert r.status_code == 410 and err(r) == "TX_EXPIRED"
    assert w.acct.get(f"/api/transactions/{tx}").json()["status"] == "EXPIRED"
    assert err(w.challenge(w.mgr, tx, w.mgr_dev)) == "TX_EXPIRED"  # gọi lại vẫn báo hết hạn
    assert "TX_EXPIRED" in audit_events()


def test_tc20_two_parallel_approvals_with_same_nonce(w, make_client):
    """Hai request song song cùng nonce: đúng một cái thành công, cái còn lại NONCE_USED."""
    tx = w.create(20_000_000)
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    payload = {"device_id": w.mgr_dev, "nonce": ch["nonce"], "signature": w.mgr_key.sign(ch["signing_string"])}
    other = make_client()
    other.cookies.set("connect.sid", w.mgr.cookies.get("connect.sid"))
    barrier, results = threading.Barrier(2), []

    def fire(client):
        barrier.wait()
        results.append(client.post(f"/api/transactions/{tx}/approve", json=payload))

    threads = [threading.Thread(target=fire, args=(c,)) for c in (w.mgr, other)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 409], [r.text for r in results]
    assert db.query_one("SELECT COUNT(*) AS n FROM approvals WHERE transaction_id = ?", (tx,))["n"] == 1


# ----------------------------------------------------------------- tạo, xem, từ chối, hủy
@pytest.mark.parametrize("payload", [
    {"amount": "100000000", "recipient_account": "0123456789", "recipient_name": "ABC"},   # số tiền là chuỗi
    {"amount": 1000.5, "recipient_account": "0123456789", "recipient_name": "ABC"},        # số thực
    {"amount": -5, "recipient_account": "0123456789", "recipient_name": "ABC"},
    {"amount": 0, "recipient_account": "0123456789", "recipient_name": "ABC"},
    {"amount": 10_000_000_001, "recipient_account": "0123456789", "recipient_name": "ABC"},
    {"amount": 1000000, "recipient_account": "12ab", "recipient_name": "ABC"},
    {"amount": 1000000, "recipient_account": "0123456789", "recipient_name": "A"},
    {"amount": True, "recipient_account": "0123456789", "recipient_name": "ABC"},
])
def test_create_validation(w, payload):
    r = w.acct.post("/api/transactions", json=payload)
    assert r.status_code == 400 and err(r) == "VALIDATION_ERROR"


def test_visibility_rules(w, login_as):
    mine = w.create()
    other_acct_tx = None
    admin = login_as("admin01")
    admin.post("/api/users", json={"username": "ketoan02", "password": "MatKhau@12345",
                                   "role": "accountant", "email": "ketoan02@example.test"})
    from conftest import login
    from fastapi.testclient import TestClient
    from app.main import app
    c2 = login(TestClient(app), "ketoan02")
    assert err(c2.get(f"/api/transactions/{mine}")) == "FORBIDDEN_ROLE"
    assert c2.get("/api/transactions").json()["total"] == 0
    assert w.acct.get("/api/transactions").json()["total"] == 1
    assert w.mgr.get("/api/transactions?status=PENDING_L1").json()["total"] == 1
    assert w.dir.get("/api/transactions").json()["total"] == 1
    assert err(w.dir.get("/api/transactions?status=BAD")) == "VALIDATION_ERROR"


def test_wrong_state_after_final_decision(w):
    tx = w.create(10_000_000)
    w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    assert err(w.challenge(w.mgr, tx, w.mgr_dev)) == "TX_WRONG_STATE"
    assert err(w.mgr.post(f"/api/transactions/{tx}/reject", json={"reason": "muộn"})) == "TX_WRONG_STATE"
    assert err(w.acct.post(f"/api/transactions/{tx}/cancel")) == "TX_WRONG_STATE"
    assert err(w.mgr.post("/api/transactions/9999/reject", json={"reason": "x"})) == "TX_NOT_FOUND"


def test_reject_without_signature_and_blocks_further_approval(w):
    tx = w.create()
    r = w.mgr.post(f"/api/transactions/{tx}/reject", json={"reason": "Không khớp với hợp đồng"})
    assert r.status_code == 200 and r.json()["status"] == "REJECTED"
    assert err(w.challenge(w.mgr, tx, w.mgr_dev)) == "TX_WRONG_STATE"
    d = w.mgr.get(f"/api/transactions/{tx}").json()  # người từ chối vẫn xem được
    assert d["reject_reason"] == "Không khớp với hợp đồng"
    assert err(w.mgr.post(f"/api/transactions/{tx}/reject", json={})) == "VALIDATION_ERROR"


def test_cancel_only_by_creator_while_pending(w, login_as):
    tx = w.create()
    assert err(w.mgr.post(f"/api/transactions/{tx}/cancel")) == "FORBIDDEN_ROLE"
    r = w.acct.post(f"/api/transactions/{tx}/cancel")
    assert r.status_code == 200 and r.json()["status"] == "CANCELLED"
    assert "TX_CANCELLED" in audit_events()


def test_note_is_not_part_of_signed_content(w):
    tx = w.create()
    ch = w.challenge(w.mgr, tx, w.mgr_dev).json()
    assert "HĐ 09/2026" not in ch["signing_string"]
    assert '"recipient_name":"CONG TY ABC"' in ch["signing_string"]


def test_vietnamese_recipient_name_round_trip(w):
    tx = w.create(name='CÔNG TY TNHH Ánh Dương "ABC" & Đối tác')
    _, res = w.approve(w.mgr, tx, w.mgr_dev, w.mgr_key)
    assert res.status_code == 200


def test_audit_list_permissions_and_filter(w, login_as):
    w.create()
    assert err(w.acct.get("/api/audit")) == "FORBIDDEN_ROLE"
    assert err(w.mgr.get("/api/audit/verify")) == "FORBIDDEN_ROLE"
    r = w.dir.get("/api/audit?event=TX_CREATED")
    assert r.status_code == 200 and r.json()["total"] == 1
    entry = r.json()["entries"][0]
    assert entry["data"]["amount"] == 200_000_000 and len(entry["hash"]) == 64
