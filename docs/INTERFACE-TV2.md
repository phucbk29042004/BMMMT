# Giao diện của TV2 (Luồng giao dịch & Mật mã)

Tài liệu này trả lời: **TV2 trả ra những gì, nhận vào những gì**. Chi tiết JSON từng endpoint xem `docs/API.md`
(mục 7 và 8). File này nói về **cách ghép nối và các quy tắc không được phá**.

---

## 1. TV2 cung cấp gì

| Hạng mục | Vị trí | Ai dùng |
|---|---|---|
| Tạo, xem, từ chối, hủy giao dịch | `/api/transactions/*` | TV3, TV4 |
| Xin chuỗi cần ký (challenge) | `POST /api/transactions/{id}/challenge` | TV3 |
| Duyệt giao dịch bằng chữ ký số | `POST /api/transactions/{id}/approve` | TV3, TV4 |
| Xem và kiểm tra audit log | `GET /api/audit`, `GET /api/audit/verify` | TV3, TV4 |
| Dựng chuỗi cần ký, canonical JSON, kiểm tra chữ ký | `app/services/crypto.py` | TV1 |
| Ghi audit hash chain, kiểm tra chuỗi | `app/services/audit.py` | TV1 |
| Luật duyệt (ngưỡng, cấp, tách nhiệm vụ) | `app/services/approval.py` | nội bộ TV2 |

---

## 2. Dành cho TV3 (giao diện): luồng duyệt giao dịch

```
1. POST /transactions/{id}/challenge  {device_id}
        -> {nonce, expires_at, level, signing_string}
2. HIỂN THỊ nội dung giao dịch cho người duyệt (lấy từ JSON.parse(signing_string)):
        số tiền, người nhận, số tài khoản
3. Người duyệt đồng ý -> ký NGUYÊN VĂN signing_string bằng khóa riêng của thiết bị
4. POST /transactions/{id}/approve  {device_id, nonce, signature}
        -> {id, status, approval}
```

Ba điều **bắt buộc** với TV3:

1. **Ký nguyên văn `signing_string`**, không parse rồi dựng lại. Server là bên duy nhất tạo ra chuỗi này; dựng lại ở client rất dễ lệch một byte.
2. **Phải hiển thị nội dung cho người duyệt trước khi ký** (nguyên tắc *What You See Is What You Sign*). Nội dung hiển thị lấy từ chính `signing_string` để người dùng thấy đúng cái sẽ ký.
3. Mỗi `nonce` chỉ dùng **một lần** và **5 phút**. Nếu `approve` lỗi thì phải gọi `challenge` lại để lấy nonce mới, không gửi lại nonce cũ.

Ví dụ chạy thật: `docs/examples/browser_flow.mjs`.

### Việc từng vai trò được làm

| Vai trò | Được làm |
|---|---|
| `accountant` | Tạo giao dịch; hủy giao dịch **của mình**; xem giao dịch **của mình** |
| `manager` | Duyệt **cấp 1**; từ chối; xem giao dịch chờ cấp 1 và giao dịch mình đã xử lý |
| `director` | Duyệt **cấp 2**; từ chối; xem tất cả |
| `admin` | **Không** xem, không duyệt giao dịch. Chỉ xem và kiểm tra audit log |

### Trạng thái cần hiển thị

`PENDING_L1`, `PENDING_L2`, `APPROVED`, `REJECTED`, `CANCELLED`, `EXPIRED` (sơ đồ chuyển trạng thái ở mục 10 của `API.md`).

Giao dịch quá hạn được chuyển `EXPIRED` ngay khi có request liên quan, nên danh sách luôn hiện đúng.

### Audit log cho màn hình lịch sử

`GET /api/audit?limit=50&offset=0&order=desc&event=TX_APPROVED`, mặc định **mới nhất trước** (`order=asc` để xem theo thứ tự chuỗi). Chỉ `admin` và `director` gọi được. Mỗi dòng có `event`, `actor_id`, `data`, `prev_hash`, `hash`, `created_at`.

---

## 3. Chuỗi cần ký (`signing_string`)

Canonical JSON của đối tượng dưới đây, **một dòng, khóa theo bảng chữ cái, không khoảng trắng, UTF-8**:

| Trường | Nguồn | Ghi chú |
|---|---|---|
| `action` | cố định `"APPROVE"` | |
| `amount` | DB | Số nguyên (đồng) |
| `approver_id` | phiên đăng nhập | Người đang xin ký |
| `currency` | DB | `"VND"` |
| `device_id` | request | Thiết bị sẽ ký |
| `expires_at` | server | Hạn của nonce |
| `level` | **server quyết định** | Theo trạng thái giao dịch |
| `nonce` | server | |
| `recipient_account`, `recipient_name` | DB | |
| `tx_created_at`, `tx_id` | DB | |
| `v` | cố định `1` | Phiên bản định dạng |

`note` **không** nằm trong chuỗi ký (ghi chú không ảnh hưởng tiền).

Tính tương thích: chuỗi do Python tạo ra khớp **từng byte** với `JSON.stringify` của JavaScript, kể cả tiếng Việt có dấu và dấu nháy kép. Kiểm chứng bằng vector tạo từ WebCrypto thật tại `tests/test_crypto.py`.

---

## 4. Thứ tự kiểm tra khi `approve` (TV4 dùng để viết test)

Server dừng ở lỗi đầu tiên. Toàn bộ chạy trong **một transaction**; mọi lần bị từ chối đều được ghi audit `APPROVAL_REJECTED_BY_SYSTEM` kèm `error_code`.

| # | Kiểm tra | Mã lỗi |
|---|---|---|
| 1 | Đã đăng nhập đầy đủ | `NOT_AUTHENTICATED` (không ghi audit vì chưa biết là ai) |
| 2 | Vai trò thuộc `manager` hoặc `director` | `FORBIDDEN_ROLE` |
| 2a | `device_id` và `nonce` đúng định dạng | `VALIDATION_ERROR` |
| 2.5 | **Phát hiện replay sớm**: nonce đã dùng | `NONCE_USED` |
| 3 | Giao dịch tồn tại, đang chờ duyệt | `TX_NOT_FOUND`, `TX_WRONG_STATE` |
| 4 | Giao dịch chưa hết hạn | `TX_EXPIRED` |
| 4a | Vai trò khớp với cấp hiện tại (cấp 1 = manager, cấp 2 = director) | `FORBIDDEN_ROLE` |
| 5 | Người duyệt không phải người tạo | `SELF_APPROVAL` |
| 6 | Người duyệt chưa duyệt cấp nào của giao dịch này | `DUPLICATE_APPROVER` |
| 7 | Thiết bị tồn tại, của người duyệt, còn `active` | `DEVICE_NOT_REGISTERED`, `DEVICE_REVOKED` |
| 8 | Nonce do hệ thống phát hành cho đúng giao dịch, người, thiết bị, cấp; chưa hết hạn | `NONCE_UNKNOWN`, `NONCE_EXPIRED` |
| 9 | Dựng lại chuỗi ký từ DB hiện tại, so với bản đã phát hành | `SIGNING_PAYLOAD_MISMATCH` |
| 10 | Có chữ ký và chữ ký hợp lệ với khóa công khai của thiết bị | `SIGNATURE_INVALID` |
| 11 | Đánh dấu nonce đã dùng (nguyên tử), ghi approval, đổi trạng thái, ghi audit | `NONCE_USED` |

**Hai điểm khác bản nháp ban đầu của `API.md` (cố ý, có lý do):**

- **Bước 2.5 (replay sớm).** Nếu để kiểm tra nonce ở bước 8, một request replay sẽ bị chặn bởi `TX_WRONG_STATE` hoặc `FORBIDDEN_ROLE` (vì trạng thái giao dịch đã đổi sau lần duyệt thật), làm mất thông tin "đây là replay". Đặt sớm thì replay luôn được báo đúng là `NONCE_USED`, và hai request song song cùng nonce (TC-20) cũng cho đúng một thành công, một `NONCE_USED`.
- **Thiếu chữ ký** trả `SIGNATURE_INVALID` (403) thay vì `VALIDATION_ERROR`, để lần giả mạo được ghi vào audit thay vì bị chặn im lặng ở lớp kiểm tra dữ liệu.

### Hai cơ chế "tin nhưng phải kiểm chứng" (điểm nhấn của đồ án)

- **Bước 9** bắt được trường hợp dữ liệu giao dịch bị sửa **sau khi** chuỗi ký đã phát hành (TC-06a).
- **Bước 10** bắt được trường hợp người duyệt bị lừa ký nội dung **khác** (TC-06b), hoặc ký bằng khóa lạ (TC-09, TC-13).

---

## 5. Audit log (hash chain)

```
hash = SHA256( prev_hash | event | actor_id | canonical(data) | created_at )
```

- Dòng đầu có `prev_hash` = 64 ký tự `0`.
- `GET /api/audit/verify` trả `{valid, checked, broken_at, reason}`; `reason` là `HASH_MISMATCH` (dòng bị sửa) hoặc `PREV_HASH_MISMATCH` (dòng bị xóa hoặc chèn).
- Demo cho hội đồng: chạy `python -m scripts.tamper_log 8` (sửa trực tiếp dòng 8 trong SQLite) rồi gọi `/audit/verify`.
- **Giới hạn:** cắt bớt các dòng **cuối** chuỗi thì không tự phát hiện được. Muốn chống phải neo hash ra ngoài (dịch vụ timestamp bên thứ ba). Nêu trong phần hướng phát triển.

Sự kiện TV2 ghi: `TX_CREATED`, `TX_APPROVED`, `TX_FULLY_APPROVED`, `TX_REJECTED`, `TX_CANCELLED`, `TX_EXPIRED`, `APPROVAL_REJECTED_BY_SYSTEM`.

---

## 6. TV2 cần gì từ người khác (đầu vào)

| Từ ai | TV2 cần |
|---|---|
| TV1 | `current_user` / `require_roles` trong `app/deps.py`; `db.transaction()` và `db.query_*`; bảng `devices`, `nonces` giữ nguyên cột; `AppError` |
| TV3 | Gọi `challenge` trước `approve`; ký nguyên văn; gửi đúng `device_id`; hiển thị nội dung trước khi ký |
| TV4 | Báo TV2 nếu cần thêm mã lỗi hoặc endpoint phục vụ kịch bản demo |

---

## 7. Bảng test: kịch bản, mã lỗi, hàm test

| Mã | Kịch bản | Mã lỗi mong đợi | Hàm test |
|---|---|---|---|
| TC-02 | Giao dịch nhỏ, 1 người duyệt | thành công, `APPROVED` | `test_tc02_small_transaction_needs_one_approval` |
| TC-03 | Giao dịch lớn, 2 cấp độc lập | thành công, `APPROVED` | `test_tc03_large_transaction_needs_two_independent_approvals` |
| TC-04 | Audit hợp lệ sau luồng bình thường | `valid: true` | `test_tc04_audit_chain_valid_after_normal_flow` |
| TC-05 | Giả giọng sếp, không chữ ký | `SIGNATURE_INVALID` | `test_tc05_voice_impersonation_request_without_signature` |
| TC-06a | Số tiền bị sửa sau khi phát hành chuỗi ký | `SIGNING_PAYLOAD_MISMATCH` | `test_tc06a_amount_changed_after_challenge_is_detected` |
| TC-06b | Ký nội dung khác | `SIGNATURE_INVALID` | `test_tc06b_signature_over_different_content_is_rejected` |
| TC-07 | Replay request cũ | `NONCE_USED` | `test_tc07_replay_of_approved_request`, `test_tc07b_*` |
| TC-08 | Nonce hết hạn | `NONCE_EXPIRED` | `test_tc08_expired_nonce` |
| TC-09 | Chữ ký bằng khóa lạ | `SIGNATURE_INVALID` | `test_tc09_signature_by_unknown_key` |
| TC-10 | Thiết bị chưa đăng ký / của người khác | `DEVICE_NOT_REGISTERED` | `test_tc10_device_not_registered_or_not_owned` |
| TC-11 | Thiết bị đã thu hồi | `DEVICE_REVOKED` | `test_tc11_revoked_device`, `test_tc11b_*` |
| TC-12 | Đúng mật khẩu, sai TOTP | `MFA_INVALID` | `test_tc12_password_ok_but_wrong_totp` (TV1) |
| TC-13 | Có phiên nhưng không có khóa thiết bị | `SIGNATURE_INVALID` | `test_tc13_account_takeover_without_device` |
| TC-14 | Tự duyệt | `SELF_APPROVAL` | `test_tc14_self_approval` |
| TC-15 | Một người duyệt hai cấp | `DUPLICATE_APPROVER` | `test_tc15_same_person_cannot_approve_both_levels` |
| TC-16 | Sai vai trò | `FORBIDDEN_ROLE` | `test_tc16_roles` |
| TC-17 | Dò mật khẩu | `RATE_LIMITED`, `ACCOUNT_LOCKED` | `test_tc17_*` (TV1) |
| TC-18 | Sửa / xóa dòng audit | `valid: false` | `test_tc18_*`, `test_tc18b_*` |
| TC-19 | Giao dịch hết hạn | `TX_EXPIRED` | `test_tc19_expired_transaction` |
| TC-20 | Hai request song song cùng nonce | một `200`, một `409 NONCE_USED` | `test_tc20_two_parallel_approvals_with_same_nonce` |

Chạy riêng phần TV2: `python -m pytest tests/test_transactions.py tests/test_crypto.py`

---

## 8. Giới hạn đã biết (đưa vào báo cáo)

1. **Không chống được cả hai người duyệt cùng bị lừa**, hoặc thiết bị đã nhiễm mã độc (ký hộ kẻ tấn công).
2. **Người duyệt bị lừa ký chính nội dung hiển thị**: hệ thống chỉ đảm bảo ký đúng cái được hiển thị, không đảm bảo người duyệt hiểu đúng nội dung.
3. **Chưa chuyển tiền thật**: trạng thái `APPROVED` là điểm kết thúc của hệ thống này.
4. **Thu hồi thiết bị chặn duyệt ngay**, nhưng chữ ký **đã** hợp lệ trước đó vẫn được giữ làm bằng chứng.
5. Giao dịch quá hạn chuyển `EXPIRED` theo kiểu "lười" (khi có request), không có tiến trình nền.
