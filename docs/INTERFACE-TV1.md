# Giao diện của TV1 (Backend nền tảng & Xác thực)

Tài liệu này trả lời: **TV1 trả ra những gì, nhận vào những gì**, để TV2, TV3, TV4 biết cách dùng mà không cần đọc code.
Chi tiết từng endpoint (JSON vào ra, mã lỗi) nằm ở `docs/API.md`; file này nói về **cách ghép nối**.

---

## 1. TV1 cung cấp gì

| Hạng mục | Vị trí | Ai dùng |
|---|---|---|
| Đăng nhập 2 bước bằng email OTP, khóa tài khoản, rate limit | `POST /api/auth/*` | TV3, TV4 |
| Quản lý người dùng (admin) | `/api/users` | TV3, TV4 |
| Đăng ký / thu hồi thiết bị | `/api/devices/*` | TV3, TV4 |
| Phiên đăng nhập lưu phía server | `app/session.py` | TV2 (gián tiếp) |
| Xác định người dùng và vai trò cho mỗi request | `app/deps.py` | TV2 |
| Truy cập CSDL + transaction | `app/db.py` | TV2 |
| Toàn bộ schema SQLite | `app/schema.sql` | TV2 |
| Bảng mã lỗi + `AppError` | `app/errors.py` | TV2, TV3 |
| Dữ liệu mẫu | `scripts/seed.py` | TV3, TV4 |

---

## 2. Dành cho TV2 (gọi trực tiếp bằng code Python)

### 2.1 Lấy người dùng hiện tại trong một route

```python
from fastapi import Depends
from app.deps import current_user, require_roles

@router.post("/ví-dụ")
def handler(user = Depends(require_roles("manager", "director"))):
    user["id"], user["username"], user["role"]     # luôn nạp lại từ DB mỗi request
```

| Dependency | Khi nào dùng | Lỗi tự ném |
|---|---|---|
| `current_user` | Chỉ cần đã đăng nhập đầy đủ (qua cả email OTP) | `NOT_AUTHENTICATED` |
| `require_roles("a", "b")` | Giới hạn theo vai trò | `NOT_AUTHENTICATED`, `FORBIDDEN_ROLE` |

Lưu ý:
- Phiên "mới qua mật khẩu, chưa xác minh email OTP" **không** được coi là đã đăng nhập.
- `user["role"]` được đọc lại từ DB ở mỗi request, nên đổi vai trò có hiệu lực ngay. Các test TC-14 và TC-15 dựa vào tính chất này.

### 2.2 Truy cập CSDL

```python
from app import db

row  = db.query_one("SELECT * FROM transactions WHERE id = ?", (tx_id,))   # dict hoặc None
rows = db.query_all("SELECT * FROM devices WHERE user_id = ?", (uid,))     # list[dict]
db.execute("UPDATE ... WHERE ...", (...))                                  # trả cursor: .rowcount, .lastrowid

with db.transaction():          # BEGIN IMMEDIATE ... COMMIT; lỗi thì ROLLBACK
    ...                         # gọi lồng nhau được
```

Quy tắc quan trọng:
- Chỉ **một kết nối** và **một khóa toàn cục**: mọi transaction chạy tuần tự. Nhờ vậy việc đánh dấu nonce "đã dùng" và ghi hash chain là nguyên tử mà không cần xử lý đua luồng riêng.
- **Mọi lỗi ném trong `with db.transaction()` làm rollback toàn bộ.** Muốn ghi audit cho một lần bị từ chối thì phải ghi **bên ngoài** khối transaction (xem cách `approve` làm).
- Luôn dùng tham số `?`, không nối chuỗi SQL.

### 2.3 Bảng `nonces` dùng chung (đã mở rộng so với bản nháp ban đầu)

| Cột | Ý nghĩa |
|---|---|
| `nonce` | PRIMARY KEY, 32 ký tự hex |
| `purpose` | `DEVICE_REG` (TV1 dùng) hoặc `TX_APPROVE` (TV2 dùng) |
| `user_id`, `tx_id`, `level`, `device_id` | Nonce được cấp cho ai, giao dịch nào, cấp nào, thiết bị nào |
| `signing_string` | Chuỗi server đã phát hành để ký (chỉ `TX_APPROVE`) |
| `expires_at`, `used_at` | Hết hạn và đã dùng chưa |

### 2.4 Hàm và lỗi dùng chung

```python
from app.errors import AppError
raise AppError("NONCE_USED")                      # mã, HTTP status, thông báo lấy từ CATALOG
raise AppError("VALIDATION_ERROR", "Thông báo riêng", {"field": "x"})
```

TV1 **gọi** (do TV2 sở hữu): `append_audit(...)`, `verify_signature(...)`, `is_valid_p256_public_key(...)`, `random_hex(...)`.
TV1 **ghi** các sự kiện audit sau (đã có trong code): `LOGIN_SUCCESS`, `LOGIN_FAILED`, `MFA_SUCCESS`, `MFA_FAILED`, `ACCOUNT_LOCKED`, `USER_CREATED`, `DEVICE_REGISTERED`, `DEVICE_REVOKED`.

---

## 3. Dành cho TV3 (giao diện)

### 3.1 Luồng đăng nhập

```
POST /api/auth/login {username, password}
   -> {"status":"MFA_REQUIRED", "email_hint":"..."} (server gửi OTP vào email)
   -> người dùng nhập OTP trong email
   -> POST /api/auth/mfa {code} -> {user}
```

- Cookie phiên tên `connect.sid` do server tự đặt (`httpOnly`), `fetch` cùng origin tự gửi kèm. **JavaScript không đọc được cookie này, đó là chủ ý.**
- Sau `/auth/mfa` thành công, gọi `GET /api/auth/me` để lấy `{id, username, role}` và quyết định hiển thị màn hình nào.
- FE chỉ hiện ô nhập mã; không có API trả mã OTP. Có thể gọi `POST /api/auth/mfa/resend` để gửi mã mới.
- Mọi lỗi có dạng `{"error": {"code", "message", "details"}}`. Dùng `code` để ánh xạ thông báo và biểu tượng (bảng mã lỗi ở mục 9 của `API.md`).

### 3.2 Đăng ký thiết bị (phần của TV3 phải làm đúng)

| Việc | Yêu cầu |
|---|---|
| Sinh khóa | `crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign','verify'])` với `extractable = false` |
| Lưu khóa | `CryptoKey` lưu vào **IndexedDB**, không dùng localStorage |
| Gửi `public_key` | `exportKey('spki', publicKey)` rồi base64 chuẩn |
| Ký challenge | Ký chuỗi `challenge` (UTF-8) bằng `{name:'ECDSA', hash:'SHA-256'}`; kết quả là **64 byte r‖s**, mã hóa base64 |
| Thứ tự gọi | `POST /devices/challenge` -> ký -> `POST /devices/register` |

Ví dụ chạy được, đúng luồng này: `docs/examples/browser_flow.mjs` (đã chạy thật với server).

### 3.3 Ràng buộc khác với giao diện

- Server bật CSP chặt (`script-src 'self'`): **không viết JavaScript inline**, hãy để JS ở file riêng trong `public/`.
- Thử API bằng tay tại `http://localhost:3000/docs` (Swagger do FastAPI sinh).
- Cần hiển thị lý do bị từ chối rõ ràng khi demo, đặc biệt `ACCOUNT_LOCKED` (có `details.locked_until`) và `RATE_LIMITED`.

---

## 4. Dành cho TV4 (test và tấn công mô phỏng)

| Cần gì | Lấy ở đâu |
|---|---|
| Tài khoản mẫu | `python -m scripts.seed`. Mật khẩu `MatKhau@12345`. Users: `admin01`, `ketoan01`, `quanly01`, `giamdoc01`, `quanly02` |
| Email nhận OTP cho user mẫu | Cấu hình `ADMIN_EMAIL` và SMTP trong `.env`; các mã mẫu được chuyển tới địa chỉ này |
| Test đã có cho phần TV1 | `tests/test_auth.py`, `tests/test_devices.py` |

Lưu ý khi viết script tấn công:
- **Email OTP hết hạn sau 10 phút và chỉ dùng một lần.** Script nên đăng nhập một lần rồi dùng lại cookie, không đăng nhập lại liên tục.
- Rate limit mặc định 5 lần/phút/IP cho `/auth/login`, `/auth/mfa`, `/auth/mfa/resend`. Muốn mô phỏng dò mật khẩu/MFA xem `test_tc17_*`.
- Khóa tài khoản sau 5 lần sai (15 phút). Muốn mở khóa khi demo: `UPDATE users SET locked_until = NULL, failed_attempts = 0`.

---

## 5. TV1 cần gì từ người khác (đầu vào)

| Từ ai | TV1 cần |
|---|---|
| TV2 | `append_audit`, `verify_signature`, `is_valid_p256_public_key`, `random_hex` trong `app/services/` giữ nguyên chữ ký hàm. Nếu đổi tên hay tham số phải báo TV1 |
| TV3 | `public_key` là SPKI base64; `signature` là r‖s 64 byte base64; `challenge` được ký dưới dạng chuỗi UTF-8 nguyên văn |
| TV4 | Báo TV1 nếu cần thêm endpoint phục vụ demo (ví dụ mở khóa tài khoản) |

---

## 6. Giới hạn đã biết (đưa vào báo cáo)

1. **Khóa tài khoản có thể bị lợi dụng để khóa người khác (DoS).** Đây là trade-off giữa chống dò mật khẩu và tính sẵn sàng.
2. **Email MFA phụ thuộc vào bảo mật hộp thư và cấu hình SMTP.** Nếu email bị chiếm, kẻ tấn công có thể nhận mã xác thực.
3. **Kẻ chiếm được mật khẩu và hộp thư của người duyệt có thể đăng ký thiết bị MỚI** (vì có proof of possession với khóa của chính họ) rồi ký duyệt. Hướng khắc phục dài hạn: thiết bị mới phải chờ một khoảng (ví dụ 24 giờ) và cần admin xác nhận qua kênh khác trước khi được dùng để duyệt.
4. **Rate limit lưu trong bộ nhớ theo IP**: khởi động lại server là mất; sau reverse proxy cần cấu hình lấy IP thật.
5. **Cookie chưa đặt `Secure`** vì demo chạy `http://localhost`; triển khai thật phải dùng HTTPS và `secure=True` trong `app/session.py`.
