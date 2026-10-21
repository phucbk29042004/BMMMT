# Giao diện của TV3 (Frontend & Demo)

Tài liệu này mô tả giao diện TrustSign do TV3 cung cấp và hợp đồng ghép nối với TV1, TV2, TV4.

---

## 1. TV3 cung cấp gì

| Hạng mục | Vị trí | Ai dùng |
|---|---|---|
| Giao diện đăng nhập, TOTP, giao dịch, thiết bị, audit | `public/index.html`, `public/css/app.css`, `public/js/app.js` | Người dùng demo |
| Lớp gọi API cùng origin và lỗi thống nhất | `public/js/api/client.js` | Mọi màn hình |
| WebCrypto, base64, SHA-256 | `public/js/crypto/encoding.js` | Đăng ký thiết bị và duyệt |
| IndexedDB lưu `CryptoKey` không xuất được | `public/js/crypto/key-store.js` | Đăng ký thiết bị và duyệt |
| Ánh xạ mã lỗi sang hướng dẫn tiếng Việt | `public/js/app.js` (`ERROR_COPY`) | Màn hình lỗi và demo |
| Cờ bật/tắt demo mode (mặc định tắt) | `public/js/config.js` | TV3, TV4 |
| Tài liệu ghép nối TV3 | `docs/INTERFACE-TV3.md` | TV1, TV2, TV4 |
| Kịch bản trình diễn | `docs/DEMO_SCRIPT.md` | Người thuyết trình, TV4 |
| Giả định và đề nghị tích hợp | `docs/TV3_NOTES.md` | TV1, TV2 |
| Slide trình bày | `docs/TrustSign-TV3.pptx` | Nhóm demo |
| Ảnh minh họa | `docs/screenshots/` | Slide và báo cáo |

TV3 dùng HTML/CSS/JavaScript ES modules thuần, không cần bước build và không tải tài nguyên từ CDN.

---

## 2. Cách chạy giao diện

Từ thư mục gốc, cài dependencies theo README nếu chưa cài, rồi chạy:

```powershell
python -m scripts.seed --dev-totp
python run.py
```

- Giao diện: `http://localhost:3000`
- Swagger: `http://localhost:3000/docs`
- Tài khoản dev: `admin01`, `ketoan01`, `quanly01`, `giamdoc01`, `quanly02`
- Mật khẩu dev: `MatKhau@12345`
- Mã TOTP dev: chạy `python -m scripts.totp`; mã chỉ dùng được một lần trong một chu kỳ 30 giây cho mỗi tài khoản.
- `python -m scripts.seed` (không có `--dev-totp`) tạo người dùng chưa cấu hình TOTP để thử nhánh quét QR lần đầu.

Lệnh seed dùng `INSERT OR IGNORE`; không xóa hoặc làm mới dữ liệu cũ. Để reset hoàn toàn, dừng server, sao lưu nếu cần rồi làm theo quy trình reset dữ liệu của nhóm (xóa `data/` và seed lại). Không reset DB khi đang demo hoặc khi còn dữ liệu cần giữ.

Demo mode tắt mặc định tại `public/js/config.js`:

```js
export const DEMO_MODE = false;
```

Chỉ trong môi trường demo mới đổi thành `true`; sau demo phải trả về `false`. Cờ này chỉ hiện các điều khiển mô phỏng phía giao diện, không phải kiểm soát bảo mật phía server.

---

## 3. Dành cho TV1

### 3.1 Auth và phiên

| Bước | Endpoint | Dữ liệu TV3 sử dụng |
|---|---|---|
| Đăng nhập mật khẩu | `POST /api/auth/login` | `{username, password}`; phản hồi `MFA_REQUIRED` hoặc `TOTP_SETUP_REQUIRED` |
| Cài TOTP lần đầu | `POST /api/auth/totp/setup` | Hiển thị `qr_data_url` và `otpauth_url` |
| Xác nhận TOTP mới | `POST /api/auth/totp/confirm` | `{code}`; phản hồi `{user}` |
| MFA khi đã cài TOTP | `POST /api/auth/mfa` | `{code}`; phản hồi `{user}` |
| Người dùng hiện tại | `GET /api/auth/me` | `{id, username, role}` |
| Đăng xuất | `POST /api/auth/logout` | HTTP 204 |

`fetch` dùng cùng origin và credentials cùng origin. Cookie `connect.sid` là `httpOnly`; JavaScript không đọc hoặc tự lưu cookie phiên. Giao diện chỉ giữ thông tin người dùng trong bộ nhớ JavaScript.

### 3.2 Đăng ký và liệt kê thiết bị

| Bước | Endpoint | Dữ liệu |
|---|---|---|
| Xin challenge đăng ký | `POST /api/devices/challenge` | Không có body; trả `{challenge, expires_at}` |
| Đăng ký | `POST /api/devices/register` | `{label, public_key, challenge, signature}` |
| Liệt kê thiết bị của người dùng hiện tại | `GET /api/devices` | `{devices: [{id, label, status, created_at}]}` |
| Thu hồi thiết bị | `POST /api/devices/{id}/revoke` | Trả `{id, status}` |

TV3 sinh khóa bằng `crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])`. Khóa riêng `extractable=false` được lưu trực tiếp dưới dạng `CryptoKey` trong IndexedDB, theo khóa ghép tài khoản + `device_id`; khóa không đi vào localStorage, sessionStorage, cookie, log hoặc URL.

- `public_key`: `exportKey("spki", publicKey)` rồi base64 chuẩn.
- `signature`: ECDSA P-256 / SHA-256; WebCrypto trả 64 byte IEEE P1363 `r‖s`, được base64 hóa, không đổi sang DER.
- Challenge đăng ký được ký trên chính chuỗi UTF-8 `challenge`.
- CSP hiện hành có `script-src 'self'`, nên script được đặt trong file riêng. `img-src 'self' data:` cho phép hiển thị QR data URL. CSS là file cùng origin.

TV3 cần TV1 giữ ổn định tên endpoint, tên field, cookie `connect.sid`, định dạng `qr_data_url`, SPKI base64 và lỗi thiết bị. Server chỉ lưu public key; lỗi sau khi server đăng ký thành công nhưng IndexedDB không lưu được cần thu hồi thiết bị đó rồi đăng ký lại.

---

## 4. Dành cho TV2

### 4.1 Endpoint giao dịch và audit

| Mục đích | Endpoint | Dữ liệu chính |
|---|---|---|
| Tạo giao dịch | `POST /api/transactions` | `{amount, recipient_account, recipient_name, note?}`; chỉ accountant |
| Liệt kê theo role/trạng thái | `GET /api/transactions?status=...&limit=100&offset=0` | `{transactions, total}` |
| Chi tiết | `GET /api/transactions/{id}` | Giao dịch, `note`, `reject_reason`, `approvals` |
| Xin nonce và chuỗi ký | `POST /api/transactions/{id}/challenge` | `{device_id}` → `{nonce, expires_at, level, signing_string}` |
| Nộp chữ ký | `POST /api/transactions/{id}/approve` | `{device_id, nonce, signature}` |
| Từ chối | `POST /api/transactions/{id}/reject` | `{reason}` |
| Hủy giao dịch | `POST /api/transactions/{id}/cancel` | Không có body |
| Liệt kê audit | `GET /api/audit?limit=50&offset=0&order=desc&event=...` | `{entries, total}` |
| Kiểm tra hash chain | `GET /api/audit/verify` | `{valid, checked, broken_at, reason?}` |

### 4.2 Duyệt theo nguyên tắc WYSIWYS

1. Client gọi challenge bằng device đang active.
2. Client parse `signing_string` chỉ để trình bày; nội dung hiển thị lấy từ đối tượng đó: `amount`, `currency`, `recipient_name`, `recipient_account`, `tx_id`, `level`, `approver_id`, `device_id`, `expires_at`. Hiển thị nonce countdown.
3. Người duyệt xác nhận đã đọc. Giao diện có phần mở rộng hiển thị chuỗi thô và SHA-256 của chính chuỗi đó.
4. Ký UTF-8 của nguyên văn `signing_string`, không serialize lại đối tượng hiển thị; gửi `device_id`, nonce server cấp và signature.
5. Nonce sống 5 phút và dùng một lần. Khi approve lỗi, preview cũ bị loại bỏ; người dùng phải xin challenge mới.

`note` không nằm trong signing string. Giao diện ghi rõ “không được ký”. Khi demo TC-06b, client cố ý ký nội dung hiển thị đã đổi số tiền, còn backend sẽ kiểm tra chữ ký trên signing string gốc.

### 4.3 Ánh xạ mã lỗi

Mã không có bản dịch riêng vẫn hiển thị nguyên văn mã và `message` từ server. Các lỗi duyệt có `tx_id` được đánh dấu là đã ghi audit; link audit chỉ hiện cho director/admin.

| Mã lỗi | Thông báo/giải thích trên giao diện |
|---|---|
| `NOT_AUTHENTICATED` | Phiên chưa đăng nhập hoặc chưa qua TOTP; đăng nhập lại. |
| `AUTH_INVALID_CREDENTIALS` | Tên đăng nhập hoặc mật khẩu chưa chính xác. |
| `FORBIDDEN_ROLE` | Vai trò hiện tại không được phép thực hiện thao tác. |
| `VALIDATION_ERROR` | Dữ liệu gửi lên chưa đúng định dạng. |
| `MFA_INVALID` | TOTP sai, hết hạn hoặc đã dùng; lấy mã mới. |
| `ACCOUNT_LOCKED` | Tài khoản bị khóa tạm thời; hiển thị `details.locked_until` nếu server trả về. |
| `RATE_LIMITED` | Đã thử quá nhiều; chờ hết cửa sổ giới hạn. |
| `NONCE_USED` | Nonce đã dùng; có thể là replay, xin challenge mới. |
| `NONCE_UNKNOWN` | Nonce không do server phát hành; xin challenge mới. |
| `NONCE_EXPIRED` | Nonce hết hạn; xin challenge mới. |
| `TX_NOT_FOUND` | Không tìm thấy giao dịch; tải lại danh sách. |
| `TX_WRONG_STATE` | Trạng thái giao dịch không cho phép thao tác. |
| `TX_EXPIRED` | Giao dịch đã hết hạn. |
| `SELF_APPROVAL` | Người tạo không được tự duyệt. |
| `DUPLICATE_APPROVER` | Cần người duyệt độc lập cho cấp tiếp theo. |
| `DEVICE_NOT_REGISTERED` | Thiết bị chưa đăng ký hoặc không thuộc tài khoản. |
| `DEVICE_REVOKED` | Thiết bị đã bị thu hồi. |
| `SIGNING_PAYLOAD_MISMATCH` | Nội dung hiện tại không còn khớp dữ liệu giao dịch lúc phát hành. |
| `SIGNATURE_INVALID` | Chữ ký sai khóa hoặc ký nội dung khác. |
| `DEVICE_NOT_FOUND` | Không tìm thấy thiết bị. |
| `DEVICE_LIMIT` | Đã đạt giới hạn thiết bị đang hoạt động. |
| `USERNAME_TAKEN` | Tên người dùng đã tồn tại. |
| `INTERNAL_ERROR` | Lỗi hệ thống; thử lại hoặc báo quản trị viên. |

TV3 cần TV2 giữ ổn định tên field trong signing string, canonical JSON, định dạng challenge/nonce, status và các mã lỗi. Không được đưa `note` vào signing string nếu chưa thống nhất thay đổi hợp đồng.

---

## 5. Dành cho TV4 (demo và tấn công)

| Mã | Thao tác | Mã lỗi/kết quả mong đợi | Màn hình hiển thị |
|---|---|---|---|
| TC-01 | Đăng nhập mật khẩu rồi nhập TOTP | `MFA_REQUIRED`, sau đó thành công | Đăng nhập / nhập TOTP |
| TC-02/03 | Kế toán tạo giao dịch; manager rồi director ký đúng cấp | `APPROVED` | Danh sách và preview WYSIWYS |
| TC-05/13 | Nộp approve không có chữ ký | `SIGNATURE_INVALID` | Thẻ từ chối và audit |
| TC-06a | TV4 sửa DB sau challenge | `SIGNING_PAYLOAD_MISMATCH` | Thẻ từ chối và audit |
| TC-06b | Chạy demo đổi nội dung ký | `SIGNATURE_INVALID` | Preview và kết quả backend |
| TC-07 | Gửi lại request approve đã thành công | `NONCE_USED` | Kết quả demo/audit |
| TC-08 | Đợi nonce quá 5 phút rồi approve | `NONCE_EXPIRED` | Thẻ từ chối và audit |
| TC-09 | Xin challenge hợp lệ rồi ký rỗng hoặc dùng khóa chưa đăng ký | `SIGNATURE_INVALID` | Kết quả demo/audit |
| TC-10 | Xin challenge với `device_id` không tồn tại | `DEVICE_NOT_REGISTERED` | Kết quả demo |
| TC-11 | Thu hồi thiết bị rồi thử duyệt | `DEVICE_REVOKED` | Thiết bị / thẻ từ chối |
| TC-12 | Đúng mật khẩu, nhập TOTP sai | `MFA_INVALID` | Nhập TOTP |
| TC-14/15 | Thử tự duyệt / một người duyệt hai cấp | `SELF_APPROVAL` / `DUPLICATE_APPROVER` | Thẻ từ chối và audit |
| TC-16 | Tài khoản accountant thử gọi duyệt | `FORBIDDEN_ROLE` | Thẻ từ chối |
| TC-17 | Nhập sai nhiều lần bằng tài khoản không phải admin | `RATE_LIMITED`, sau đó `ACCOUNT_LOCKED` | Đăng nhập |
| TC-18 | TV4 chạy `python -m scripts.tamper_log 8`, sau đó bấm kiểm tra | `valid: false` | Audit log, dòng lỗi được tô nổi bật |

Thứ tự demo thành công, tài khoản mẫu và cách reset dữ liệu được mô tả từng bước trong [DEMO_SCRIPT.md](./DEMO_SCRIPT.md). TOTP chỉ dùng một lần cho mỗi bước 30 giây; không tái sử dụng cùng mã sau lần đăng nhập đầu.

---

## 6. Cấu trúc thư mục frontend

```text
public/
├── index.html                 # khung trang, không có JavaScript inline
├── css/
│   └── app.css                # giao diện responsive
└── js/
    ├── app.js                 # màn hình, luồng role, WYSIWYS, audit, demo
    ├── config.js              # cờ DEMO_MODE, mặc định false
    ├── api/
    │   └── client.js          # fetch cùng origin và ApiError
    └── crypto/
        ├── encoding.js        # base64, WebCrypto, SHA-256
        └── key-store.js       # IndexedDB CryptoKey
```

---

## 7. TV3 cần gì từ người khác (đầu vào)

| Từ ai | TV3 cần |
|---|---|
| TV1 | Giữ ổn định auth/TOTP/device endpoints, cookie httpOnly, schema phản hồi lỗi, CSP và luồng setup QR. Làm rõ việc trả `ACCOUNT_LOCKED` ngay lần chạm ngưỡng. |
| TV2 | Giữ ổn định endpoint giao dịch/audit, trạng thái, tên field, canonical signing string, r‖s 64 byte base64 và mã lỗi. |
| TV4 | Seed/reset dữ liệu demo có kiểm soát, hỗ trợ các kịch bản yêu cầu sửa DB hoặc chờ hết hạn, lưu TOTP mới nhất và kiểm tra hash chain. |

---

## 8. Giới hạn đã biết (đưa vào báo cáo)

1. Khóa non-extractable ngăn ứng dụng đọc/export private key, nhưng không ngăn mã độc đang chạy trong cùng trang gọi hàm ký.
2. XSS vẫn là rủi ro chính. Trang tránh inline script và dựng nội dung động bằng `textContent`; CSP server là lớp bảo vệ bổ sung, không thay thế việc xử lý XSS an toàn.
3. Xóa dữ liệu trình duyệt làm mất khóa trong IndexedDB; cần thu hồi/đăng ký lại thiết bị.
4. Người duyệt vẫn có thể ký nội dung họ không hiểu; WYSIWYS chỉ đảm bảo ký đúng byte của nội dung được trình bày.
5. Demo mode bật các nút mô phỏng client-side nhưng không phải feature flag bảo mật; tuyệt đối không bật ở production.
6. `note` không nằm trong signing string, nên không phải nội dung được chữ ký bảo vệ.
7. Hash chain không tự phát hiện việc cắt bỏ các dòng cuối; cần neo hash ra ngoài để chống sửa lịch sử toàn bộ.
8. Giao dịch chuyển sang `EXPIRED` kiểu lazy khi có request, không có job nền.
9. Phiên demo hiện dùng cookie không có `Secure` do chạy HTTP localhost; production cần HTTPS và cookie Secure.
10. Backend hiện có thể chỉ trả `ACCOUNT_LOCKED` ở request sau khi lần sai thứ năm đã kích hoạt khóa; xem [TV3_NOTES.md](./TV3_NOTES.md).
