# TrustSign – Tài liệu API chung

> **Nguyên tắc của hệ thống:** Không tin thứ trông có vẻ thật, chỉ tin thứ kiểm chứng được bằng mật mã.
> Giọng nói, tin nhắn, ảnh chụp màn hình **không có giá trị**. Một giao dịch chỉ được duyệt khi có chữ ký số từ khóa riêng của thiết bị đã đăng ký.

**Phiên bản:** 1.0 (bản nháp đầu, cả nhóm cùng chốt)
**Công nghệ:** Python (FastAPI) + SQLite (`sqlite3`)

> ⚠️ **Quy tắc sửa file này:** Muốn đổi endpoint, tên trường hoặc mã lỗi thì báo cả nhóm và ghi vào mục *Lịch sử thay đổi* ở cuối file. Không tự ý đổi rồi để người khác phát hiện khi code chạy lỗi.

---

## Mục lục

1. [Quy ước chung](#1-quy-ước-chung)
2. [Vai trò và quy tắc nghiệp vụ](#2-vai-trò-và-quy-tắc-nghiệp-vụ)
3. [Định dạng nội dung cần ký (quan trọng nhất)](#3-định-dạng-nội-dung-cần-ký-quan-trọng-nhất)
4. [API xác thực (Auth)](#4-api-xác-thực-auth)
5. [API người dùng (Users)](#5-api-người-dùng-users)
6. [API thiết bị (Devices)](#6-api-thiết-bị-devices)
7. [API giao dịch (Transactions)](#7-api-giao-dịch-transactions)
8. [API nhật ký (Audit)](#8-api-nhật-ký-audit)
9. [Bảng mã lỗi](#9-bảng-mã-lỗi)
10. [Máy trạng thái của giao dịch](#10-máy-trạng-thái-của-giao-dịch)
11. [Hash chain của audit log](#11-hash-chain-của-audit-log)
12. [Bảng tấn công, mã lỗi, test case](#12-bảng-tấn-công-mã-lỗi-test-case)
13. [Cấu hình dùng chung](#13-cấu-hình-dùng-chung)
14. [Lịch sử thay đổi](#14-lịch-sử-thay-đổi)

---

## 1. Quy ước chung

| Mục | Quy ước |
|---|---|
| Base URL | `http://localhost:3000/api` |
| Định dạng | JSON (`Content-Type: application/json`), mã hóa UTF-8 |
| Xác thực | Cookie phiên `connect.sid` (`httpOnly`, `SameSite=Strict`) |
| Thời gian | ISO 8601 UTC, ví dụ `2026-10-02T08:30:00.000Z` |
| Tiền tệ | Số nguyên, đơn vị **đồng (VND)**, không dùng số thực. Ví dụ `200000000` |
| ID | Số nguyên tự tăng (SQLite `INTEGER PRIMARY KEY`) |
| Khóa công khai | Định dạng **SPKI**, mã hóa **base64** chuẩn |
| Chữ ký | ECDSA P-256 + SHA-256, định dạng **IEEE P1363 (r‖s, 64 byte)**, mã hóa **base64** |

### Định dạng phản hồi

**Thành công:** mã HTTP 2xx, thân là JSON dữ liệu.

**Lỗi:** luôn theo một khuôn duy nhất để TV3 hiển thị lý do từ chối:

```json
{
  "error": {
    "code": "NONCE_USED",
    "message": "Nonce này đã được sử dụng, nghi ngờ replay.",
    "details": {}
  }
}
```

- `code`: mã lỗi cố định (xem [mục 9](#9-bảng-mã-lỗi)), dùng cho code và test.
- `message`: câu tiếng Việt hiển thị cho người dùng.
- `details`: thông tin thêm, có thể rỗng.

### Quy tắc bảo mật chung cho mọi endpoint

- Mọi endpoint (trừ `/auth/login` và `/auth/mfa`) yêu cầu phiên đăng nhập **đã qua TOTP**.
- Dữ liệu vào đều được kiểm tra bằng `pydantic`; sai định dạng trả `VALIDATION_ERROR`.
- Không trả `password_hash`, `totp_secret` ở bất kỳ phản hồi nào.
- Giới hạn tốc độ (`app/ratelimit.py`): đăng nhập và TOTP tối đa 5 lần/phút/IP, quá thì trả `RATE_LIMITED`.
- Thông báo đăng nhập sai **không** tiết lộ username hay mật khẩu sai (luôn trả `AUTH_INVALID_CREDENTIALS`).

---

## 2. Vai trò và quy tắc nghiệp vụ

### Vai trò

| Role | Quyền |
|---|---|
| `accountant` (kế toán) | Tạo giao dịch, hủy giao dịch do mình tạo, xem giao dịch của mình |
| `manager` (quản lý) | Duyệt cấp 1, từ chối, xem giao dịch chờ duyệt |
| `director` (giám đốc) | Duyệt cấp 2, từ chối, xem tất cả giao dịch |
| `admin` | Tạo người dùng, thu hồi thiết bị, xem và kiểm tra audit log. **Không** được duyệt giao dịch |

### Quy tắc duyệt

| Số tiền (VND) | Số cấp duyệt | Người duyệt |
|---|---|---|
| `< 50.000.000` | 1 cấp | `manager` |
| `>= 50.000.000` | 2 cấp | Cấp 1: `manager`, cấp 2: `director` |

Ngưỡng 50.000.000 là cấu hình (xem [mục 13](#13-cấu-hình-dùng-chung)).

Các luật bắt buộc (server kiểm tra, không tin client):

1. Người tạo giao dịch **không được** duyệt giao dịch của chính mình (`SELF_APPROVAL`).
2. Một người **không được** duyệt cả hai cấp của cùng một giao dịch (`DUPLICATE_APPROVER`).
3. Mỗi lần duyệt phải có chữ ký từ **thiết bị đã đăng ký và còn hiệu lực** của chính người duyệt.
4. Giao dịch hết hạn (mặc định 24 giờ) thì không duyệt được (`TX_EXPIRED`).
5. Từ chối (`reject`) chỉ cần phiên đăng nhập, không cần ký, vì đây là hướng an toàn (fail-safe): làm sai thì chỉ mất thời gian, không mất tiền.

---

## 3. Định dạng nội dung cần ký (quan trọng nhất)

> **TV2 và TV3 đọc kỹ mục này.** Sai một ký tự là chữ ký không khớp.

### Nguyên tắc "server đưa chuỗi, trình duyệt ký đúng chuỗi đó"

Để tránh trình duyệt và server tạo chuỗi khác nhau:

1. Trình duyệt gọi `POST /transactions/:id/challenge`.
2. Server trả về `signing_string` (chuỗi đã chuẩn hóa) và `nonce`.
3. Trình duyệt **hiển thị nội dung giao dịch cho người duyệt đọc** (số tiền, người nhận, ...), sau đó ký **nguyên văn** `signing_string` (không sửa, không dựng lại).
4. Trình duyệt gửi `signature` và `nonce` lên.
5. Server **tự dựng lại** chuỗi từ dữ liệu trong CSDL, so khớp với chuỗi đã phát hành, rồi mới kiểm tra chữ ký. Không dùng bất kỳ giá trị nào do client gửi lên để dựng chuỗi ký.

Nguyên tắc này gọi là *What You See Is What You Sign*: người duyệt thấy gì thì ký đúng cái đó.

### Cấu trúc `signing_string`

Là **canonical JSON** của đối tượng sau:

```json
{
  "action": "APPROVE",
  "amount": 200000000,
  "approver_id": 3,
  "currency": "VND",
  "device_id": 7,
  "expires_at": "2026-10-02T08:35:00.000Z",
  "level": 1,
  "nonce": "b3f1c2d4e5a60718293a4b5c6d7e8f90",
  "recipient_account": "0123456789",
  "recipient_name": "CONG TY ABC",
  "tx_created_at": "2026-10-02T08:30:00.000Z",
  "tx_id": 15,
  "v": 1
}
```

### Quy tắc canonical JSON

| Quy tắc | Chi tiết |
|---|---|
| Thứ tự khóa | Sắp xếp **theo bảng chữ cái** (như ví dụ trên) |
| Khoảng trắng | Không có khoảng trắng hay xuống dòng thừa |
| Mã hóa | UTF-8 |
| Số tiền | Số nguyên, không dấu chấm phẩy |
| Thời gian | ISO 8601 UTC có mili giây, hậu tố `Z` |
| Chuỗi | Dùng `JSON.stringify` mặc định, không tự chèn ký tự thoát |
| Phiên bản | Trường `v` hiện là `1` |

Kết quả của ví dụ trên là **một dòng duy nhất**:

```
{"action":"APPROVE","amount":200000000,"approver_id":3,"currency":"VND","device_id":7,"expires_at":"2026-10-02T08:35:00.000Z","level":1,"nonce":"b3f1c2d4e5a60718293a4b5c6d7e8f90","recipient_account":"0123456789","recipient_name":"CONG TY ABC","tx_created_at":"2026-10-02T08:30:00.000Z","tx_id":15,"v":1}
```

Hàm canonical dùng chung ở server (TV2 viết trong `app/services/crypto.py`, dạng `json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`; bản JavaScript dưới đây chỉ để tham khảo):

```js
function canonicalize(obj) {
  const sorted = Object.keys(obj).sort().reduce((acc, k) => {
    acc[k] = obj[k];
    return acc;
  }, {});
  return JSON.stringify(sorted);
}
```

(Đối tượng ký chỉ có các trường phẳng nên cách này đủ dùng. Nếu sau này thêm đối tượng lồng nhau thì phải sắp xếp đệ quy.)

### Ký ở trình duyệt (TV3)

```js
// Sinh khóa một lần khi đăng ký thiết bị. extractable:false để không đọc được khóa riêng
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['sign', 'verify']
);
// Lưu keyPair (CryptoKey) vào IndexedDB. KHÔNG dùng localStorage.

// Xuất khóa công khai gửi lên server
const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
const publicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(spki)));

// Ký nguyên văn signing_string do server đưa
const data = new TextEncoder().encode(signingString);
const sig = await crypto.subtle.sign(
  { name: 'ECDSA', hash: 'SHA-256' },
  keyPair.privateKey,
  data
);
const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
```

> WebCrypto chỉ chạy ở `localhost` hoặc HTTPS. Khi demo hãy dùng `http://localhost:3000`.

### Kiểm tra chữ ký ở server (TV2)

> Đoạn Node.js dưới đây chỉ để tham khảo. Bản Python đang dùng nằm ở `app/services/crypto.py` (`verify_signature`, đã đổi chữ ký r‖s sang DER) và được kiểm thử chéo với WebCrypto trong `tests/test_crypto.py`.

```js
const crypto = require('crypto');

function verifySignature(publicKeyB64, signingString, signatureB64) {
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyB64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(
    'sha256',
    Buffer.from(signingString, 'utf8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' }, // BẮT BUỘC, nếu thiếu thì chữ ký đúng cũng bị báo sai
    Buffer.from(signatureB64, 'base64')
  );
}
```

---

## 4. API xác thực (Auth)

Phụ trách: **TV1**

Đăng nhập gồm 2 bước: mật khẩu, rồi TOTP. Sau bước 1 phiên ở trạng thái "chờ MFA", chưa gọi được các API khác.

### `POST /auth/login`

Bước 1: kiểm tra mật khẩu.

**Request**
```json
{ "username": "ketoan01", "password": "MatKhau@123" }
```

**Response 200**
```json
{ "status": "MFA_REQUIRED" }
```

Nếu tài khoản chưa cài TOTP:
```json
{ "status": "TOTP_SETUP_REQUIRED" }
```

**Lỗi:** `AUTH_INVALID_CREDENTIALS` (401), `ACCOUNT_LOCKED` (423), `RATE_LIMITED` (429), `VALIDATION_ERROR` (400)

Quy tắc: sai mật khẩu 5 lần thì khóa tài khoản 15 phút.

### `POST /auth/mfa`

Bước 2: nhập mã TOTP 6 số.

**Request**
```json
{ "code": "123456" }
```

**Response 200**
```json
{
  "user": { "id": 3, "username": "quanly01", "role": "manager" }
}
```

**Lỗi:** `MFA_INVALID` (401), `NOT_AUTHENTICATED` (401, chưa qua bước 1), `ACCOUNT_LOCKED` (423), `RATE_LIMITED` (429)

Quy tắc: cho phép lệch ±1 bước (30 giây). Mỗi mã TOTP chỉ dùng được **một lần** (chống dùng lại mã vừa bị nhìn trộm).

### `POST /auth/totp/setup`

Dùng ở lần đăng nhập đầu khi `status = TOTP_SETUP_REQUIRED`. Trả về mã QR để quét bằng Google Authenticator.

**Response 200**
```json
{
  "otpauth_url": "otpauth://totp/TrustSign:quanly01?secret=ABCDEF...&issuer=TrustSign",
  "qr_data_url": "data:image/png;base64,iVBORw0KGgo..."
}
```

### `POST /auth/totp/confirm`

Xác nhận đã quét QR bằng cách nhập mã đầu tiên.

**Request**
```json
{ "code": "123456" }
```

**Response 200**
```json
{ "user": { "id": 3, "username": "quanly01", "role": "manager" } }
```

### `POST /auth/logout`

**Response 204** (không có thân)

### `GET /auth/me`

Trả thông tin người dùng hiện tại.

**Response 200**
```json
{ "id": 3, "username": "quanly01", "role": "manager" }
```

**Lỗi:** `NOT_AUTHENTICATED` (401)

---

## 5. API người dùng (Users)

Phụ trách: **TV1**. Chỉ `admin` được gọi.

### `POST /users`

Tạo người dùng mới.

**Request**
```json
{ "username": "quanly01", "password": "MatKhau@123", "role": "manager" }
```

`role` thuộc `accountant | manager | director | admin`.

**Response 201**
```json
{ "id": 3, "username": "quanly01", "role": "manager" }
```

**Lỗi:** `FORBIDDEN_ROLE` (403), `VALIDATION_ERROR` (400), `USERNAME_TAKEN` (409)

Quy tắc mật khẩu: tối thiểu 10 ký tự, băm bằng `argon2`.

### `GET /users`

**Response 200**
```json
{
  "users": [
    { "id": 1, "username": "admin", "role": "admin", "locked": false }
  ]
}
```

---

## 6. API thiết bị (Devices)

Phụ trách: **TV1** (API, lưu trữ), **TV3** (sinh khóa ở trình duyệt)

"Thiết bị" ở đây là một trình duyệt có giữ khóa riêng ECDSA. Server chỉ lưu khóa công khai. Khi đăng ký phải **chứng minh sở hữu khóa riêng** (proof of possession) bằng cách ký một challenge, để không ai đăng ký được khóa công khai mà mình không giữ khóa riêng.

### `POST /devices/challenge`

Xin challenge để đăng ký thiết bị mới.

**Response 200**
```json
{
  "challenge": "7f3a9c0e1b2d4f568a9b0c1d2e3f4051",
  "expires_at": "2026-10-02T08:35:00.000Z"
}
```

Challenge hết hạn sau 5 phút, dùng một lần.

### `POST /devices/register`

**Request**
```json
{
  "label": "Laptop giám đốc",
  "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
  "challenge": "7f3a9c0e1b2d4f568a9b0c1d2e3f4051",
  "signature": "base64-chữ-ký-của-challenge"
}
```

Trình duyệt ký chuỗi `challenge` (UTF-8) bằng khóa riêng vừa sinh.

**Response 201**
```json
{
  "id": 7,
  "label": "Laptop giám đốc",
  "status": "active",
  "created_at": "2026-10-02T08:31:00.000Z"
}
```

**Lỗi:** `NOT_AUTHENTICATED` (401), `NONCE_UNKNOWN` (400), `NONCE_EXPIRED` (400), `NONCE_USED` (409), `SIGNATURE_INVALID` (400), `VALIDATION_ERROR` (400), `DEVICE_LIMIT` (409, tối đa 3 thiết bị đang hoạt động mỗi người)

### `GET /devices`

Liệt kê thiết bị của chính người dùng đang đăng nhập.

**Response 200**
```json
{
  "devices": [
    { "id": 7, "label": "Laptop giám đốc", "status": "active", "created_at": "2026-10-02T08:31:00.000Z" }
  ]
}
```

`status` thuộc `active | revoked`.

### `POST /devices/:id/revoke`

Thu hồi thiết bị (mất máy, nghi bị lộ). Người dùng thu hồi thiết bị của mình, hoặc `admin` thu hồi của bất kỳ ai.

**Response 200**
```json
{ "id": 7, "status": "revoked" }
```

**Lỗi:** `FORBIDDEN_ROLE` (403), `DEVICE_NOT_FOUND` (404)

---

## 7. API giao dịch (Transactions)

Phụ trách: **TV2** (logic), **TV3** (giao diện gọi API)

### `POST /transactions`

Tạo yêu cầu giao dịch. Chỉ `accountant`.

**Request**
```json
{
  "amount": 200000000,
  "recipient_account": "0123456789",
  "recipient_name": "CONG TY ABC",
  "note": "Thanh toán hợp đồng 09/2026"
}
```

| Trường | Quy tắc |
|---|---|
| `amount` | Số nguyên dương, tối đa 10.000.000.000 |
| `recipient_account` | Chuỗi 6 đến 20 chữ số |
| `recipient_name` | Chuỗi 2 đến 100 ký tự |
| `note` | Tùy chọn, tối đa 200 ký tự (**không** nằm trong chuỗi ký) |

**Response 201**
```json
{
  "id": 15,
  "status": "PENDING_L1",
  "amount": 200000000,
  "recipient_account": "0123456789",
  "recipient_name": "CONG TY ABC",
  "required_levels": 2,
  "created_by": 2,
  "created_at": "2026-10-02T08:30:00.000Z",
  "expires_at": "2026-10-03T08:30:00.000Z"
}
```

**Lỗi:** `FORBIDDEN_ROLE` (403), `VALIDATION_ERROR` (400)

### `GET /transactions`

Danh sách giao dịch theo quyền. Tham số lọc: `?status=PENDING_L1&limit=20&offset=0`.

- `accountant`: chỉ thấy giao dịch do mình tạo.
- `manager`: thấy giao dịch đang `PENDING_L1` và giao dịch mình đã xử lý.
- `director`: thấy tất cả.

**Response 200**
```json
{
  "transactions": [ { "id": 15, "status": "PENDING_L1", "amount": 200000000, "recipient_name": "CONG TY ABC", "created_at": "2026-10-02T08:30:00.000Z" } ],
  "total": 1
}
```

### `GET /transactions/:id`

Chi tiết giao dịch kèm lịch sử duyệt.

**Response 200**
```json
{
  "id": 15,
  "status": "PENDING_L2",
  "amount": 200000000,
  "currency": "VND",
  "recipient_account": "0123456789",
  "recipient_name": "CONG TY ABC",
  "note": "Thanh toán hợp đồng 09/2026",
  "required_levels": 2,
  "created_by": { "id": 2, "username": "ketoan01" },
  "created_at": "2026-10-02T08:30:00.000Z",
  "expires_at": "2026-10-03T08:30:00.000Z",
  "approvals": [
    {
      "level": 1,
      "approver": { "id": 3, "username": "quanly01" },
      "device_id": 7,
      "created_at": "2026-10-02T08:40:00.000Z"
    }
  ]
}
```

**Lỗi:** `TX_NOT_FOUND` (404), `FORBIDDEN_ROLE` (403)

### `POST /transactions/:id/challenge`

Xin chuỗi cần ký và nonce cho **cấp duyệt tiếp theo**. Gọi trước khi duyệt.

**Request**
```json
{ "device_id": 7 }
```

**Response 200**
```json
{
  "nonce": "b3f1c2d4e5a60718293a4b5c6d7e8f90",
  "expires_at": "2026-10-02T08:35:00.000Z",
  "level": 1,
  "signing_string": "{\"action\":\"APPROVE\",\"amount\":200000000,...,\"v\":1}"
}
```

Quy tắc:
- Nonce là 16 byte ngẫu nhiên (`crypto.randomBytes(16)`), dạng hex, **hiệu lực 5 phút, dùng một lần**.
- `level` do **server** quyết định dựa trên trạng thái giao dịch và vai trò người gọi. Client không chọn được.
- Server kiểm tra thiết bị thuộc người gọi và đang `active` ngay ở bước này.

**Lỗi:** `DEVICE_NOT_REGISTERED` (403), `DEVICE_REVOKED` (403), `FORBIDDEN_ROLE` (403), `SELF_APPROVAL` (403), `DUPLICATE_APPROVER` (403), `TX_WRONG_STATE` (409), `TX_EXPIRED` (410)

### `POST /transactions/:id/approve`

Nộp chữ ký để duyệt.

**Request**
```json
{
  "device_id": 7,
  "nonce": "b3f1c2d4e5a60718293a4b5c6d7e8f90",
  "signature": "base64-chữ-ký-ECDSA-P1363"
}
```

**Thứ tự kiểm tra ở server** (dừng ở lỗi đầu tiên, TV2 làm đúng thứ tự này để mã lỗi trong test ổn định):

| # | Kiểm tra | Mã lỗi nếu sai |
|---|---|---|
| 1 | Phiên đăng nhập hợp lệ, đã qua TOTP | `NOT_AUTHENTICATED` |
| 2 | Vai trò được phép duyệt cấp này | `FORBIDDEN_ROLE` |
| 3 | Giao dịch tồn tại, đúng trạng thái chờ duyệt | `TX_NOT_FOUND`, `TX_WRONG_STATE` |
| 4 | Giao dịch chưa hết hạn | `TX_EXPIRED` |
| 5 | Người duyệt không phải người tạo | `SELF_APPROVAL` |
| 6 | Người duyệt chưa duyệt cấp trước | `DUPLICATE_APPROVER` |
| 7 | Thiết bị tồn tại, thuộc người duyệt, còn `active` | `DEVICE_NOT_REGISTERED`, `DEVICE_REVOKED` |
| 8 | Nonce có trong hệ thống, chưa hết hạn, chưa dùng, đúng giao dịch và đúng người | `NONCE_UNKNOWN`, `NONCE_EXPIRED`, `NONCE_USED` |
| 9 | Server dựng lại `signing_string` và so khớp với bản đã phát hành | `SIGNING_PAYLOAD_MISMATCH` |
| 10 | Chữ ký ECDSA hợp lệ với khóa công khai của thiết bị | `SIGNATURE_INVALID` |
| 11 | Đánh dấu nonce đã dùng, ghi approval, cập nhật trạng thái, ghi audit log (**trong một transaction SQLite**) | `INTERNAL_ERROR` |

Bước 8 và 11 phải thuộc cùng một transaction và đánh dấu nonce bằng `INSERT`/`UPDATE ... WHERE used_at IS NULL` để hai request song song cùng nonce không cùng thành công.

> **Mọi lần từ chối ở bước 1 đến 10 đều phải ghi vào audit log** (sự kiện `APPROVAL_REJECTED_BY_SYSTEM`, kèm mã lỗi). Đây là bằng chứng hệ thống đã chặn tấn công.

**Response 200**
```json
{
  "id": 15,
  "status": "PENDING_L2",
  "approval": { "level": 1, "approver_id": 3, "device_id": 7, "created_at": "2026-10-02T08:40:00.000Z" }
}
```

Nếu đây là cấp cuối, `status` là `APPROVED`.

### `POST /transactions/:id/reject`

Từ chối giao dịch. Chỉ cần phiên đăng nhập, không cần ký (xem [mục 2](#2-vai-trò-và-quy-tắc-nghiệp-vụ)).

**Request**
```json
{ "reason": "Không khớp với hợp đồng" }
```

**Response 200**
```json
{ "id": 15, "status": "REJECTED" }
```

**Lỗi:** `FORBIDDEN_ROLE` (403), `TX_WRONG_STATE` (409), `TX_NOT_FOUND` (404)

### `POST /transactions/:id/cancel`

Người tạo hủy giao dịch khi còn chờ duyệt.

**Response 200**
```json
{ "id": 15, "status": "CANCELLED" }
```

**Lỗi:** `FORBIDDEN_ROLE` (403, không phải người tạo), `TX_WRONG_STATE` (409)

---

## 8. API nhật ký (Audit)

Phụ trách: **TV2** (hash chain), **TV3** (hiển thị)

### `GET /audit`

Chỉ `admin` và `director`. Tham số: `?limit=50&offset=0&event=...`

**Response 200**
```json
{
  "entries": [
    {
      "id": 42,
      "event": "TX_APPROVED",
      "actor_id": 3,
      "data": { "tx_id": 15, "level": 1, "device_id": 7 },
      "prev_hash": "a1b2...",
      "hash": "c3d4...",
      "created_at": "2026-10-02T08:40:00.000Z"
    }
  ],
  "total": 42
}
```

### `GET /audit/verify`

Duyệt lại toàn bộ chuỗi và kiểm tra tính toàn vẹn. Chỉ `admin` và `director`.

**Response 200 (chuỗi nguyên vẹn)**
```json
{ "valid": true, "checked": 42, "broken_at": null }
```

**Response 200 (chuỗi bị sửa)**
```json
{
  "valid": false,
  "checked": 42,
  "broken_at": 17,
  "reason": "HASH_MISMATCH"
}
```

`reason` thuộc `HASH_MISMATCH` (nội dung dòng bị sửa) hoặc `PREV_HASH_MISMATCH` (dòng bị xóa hay chèn làm đứt liên kết).

### Danh sách sự kiện audit

| Event | Khi nào ghi |
|---|---|
| `LOGIN_SUCCESS` / `LOGIN_FAILED` | Kết quả đăng nhập |
| `MFA_SUCCESS` / `MFA_FAILED` | Kết quả TOTP |
| `ACCOUNT_LOCKED` | Khóa tài khoản do nhập sai nhiều lần |
| `USER_CREATED` | Admin tạo người dùng |
| `DEVICE_REGISTERED` / `DEVICE_REVOKED` | Đăng ký, thu hồi thiết bị |
| `TX_CREATED` | Tạo giao dịch |
| `TX_APPROVED` | Một cấp duyệt thành công |
| `TX_FULLY_APPROVED` | Giao dịch đủ cấp duyệt |
| `TX_REJECTED` / `TX_CANCELLED` / `TX_EXPIRED` | Từ chối, hủy, hết hạn |
| `APPROVAL_REJECTED_BY_SYSTEM` | Hệ thống chặn một lần duyệt, kèm `data.error_code` |

---

## 9. Bảng mã lỗi

| Mã lỗi | HTTP | Ý nghĩa (hiển thị cho người dùng) |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Dữ liệu gửi lên sai định dạng |
| `NOT_AUTHENTICATED` | 401 | Chưa đăng nhập hoặc chưa qua TOTP |
| `AUTH_INVALID_CREDENTIALS` | 401 | Sai tên đăng nhập hoặc mật khẩu |
| `MFA_INVALID` | 401 | Mã TOTP sai, hết hạn hoặc đã dùng |
| `FORBIDDEN_ROLE` | 403 | Vai trò không được phép thực hiện thao tác này |
| `SELF_APPROVAL` | 403 | Người tạo giao dịch không được tự duyệt |
| `DUPLICATE_APPROVER` | 403 | Một người không được duyệt hai cấp của cùng giao dịch |
| `DEVICE_NOT_REGISTERED` | 403 | Thiết bị chưa đăng ký hoặc không thuộc về bạn |
| `DEVICE_REVOKED` | 403 | Thiết bị đã bị thu hồi |
| `SIGNATURE_INVALID` | 403 | Chữ ký không hợp lệ (sai khóa hoặc nội dung đã bị sửa) |
| `SIGNING_PAYLOAD_MISMATCH` | 403 | Nội dung ký không khớp với giao dịch trong hệ thống |
| `NONCE_UNKNOWN` | 400 | Nonce không do hệ thống phát hành |
| `NONCE_EXPIRED` | 400 | Nonce đã hết hạn |
| `NONCE_USED` | 409 | Nonce đã được dùng, nghi ngờ replay |
| `TX_NOT_FOUND` | 404 | Không tìm thấy giao dịch |
| `DEVICE_NOT_FOUND` | 404 | Không tìm thấy thiết bị |
| `TX_WRONG_STATE` | 409 | Giao dịch không ở trạng thái cho phép thao tác này |
| `TX_EXPIRED` | 410 | Giao dịch đã hết hạn |
| `USERNAME_TAKEN` | 409 | Tên đăng nhập đã tồn tại |
| `DEVICE_LIMIT` | 409 | Đã đạt số thiết bị tối đa |
| `ACCOUNT_LOCKED` | 423 | Tài khoản đang bị khóa tạm thời |
| `RATE_LIMITED` | 429 | Thử quá nhiều lần, vui lòng chờ |
| `INTERNAL_ERROR` | 500 | Lỗi hệ thống |

> TV3: giao diện nên có một bảng ánh xạ `code → thông báo + biểu tượng` để màn hình từ chối hiển thị rõ lý do khi demo.

---

## 10. Máy trạng thái của giao dịch

```
                 ┌──────────── reject ────────────► REJECTED
                 │
 (tạo) ──► PENDING_L1 ──approve L1──► PENDING_L2 ──approve L2──► APPROVED
                 │       (nếu < ngưỡng: APPROVED ngay)
                 │
                 ├──── cancel (người tạo) ──► CANCELLED
                 └──── quá hạn ──────────────► EXPIRED
```

| Trạng thái | Ý nghĩa | Chuyển được sang |
|---|---|---|
| `PENDING_L1` | Chờ cấp 1 | `PENDING_L2`, `APPROVED`, `REJECTED`, `CANCELLED`, `EXPIRED` |
| `PENDING_L2` | Chờ cấp 2 | `APPROVED`, `REJECTED`, `CANCELLED`, `EXPIRED` |
| `APPROVED` | Đủ chữ ký (trạng thái cuối) | không |
| `REJECTED` | Bị từ chối (trạng thái cuối) | không |
| `CANCELLED` | Người tạo hủy (trạng thái cuối) | không |
| `EXPIRED` | Hết hạn (trạng thái cuối) | không |

Mọi chuyển trạng thái không có trong bảng đều trả `TX_WRONG_STATE`.

---

## 11. Hash chain của audit log

Mỗi dòng log liên kết với dòng trước, nên sửa hoặc xóa một dòng sẽ làm đứt chuỗi.

```
hash = SHA256( prev_hash | event | actor_id | canonical(data) | created_at )
```

- Dấu `|` là ký tự phân cách cố định, nối các trường thành một chuỗi UTF-8.
- `actor_id` là `0` nếu không có (ví dụ đăng nhập thất bại với username không tồn tại).
- `canonical(data)` dùng cùng hàm `canonicalize` ở [mục 3](#3-định-dạng-nội-dung-cần-ký-quan-trọng-nhất).
- Dòng đầu tiên (genesis) có `prev_hash` = 64 ký tự `0`.
- Hash dạng hex thường, 64 ký tự.
- Việc ghi log phải **tuần tự** (trong transaction SQLite) để `prev_hash` luôn đúng.

```js
function computeHash(prevHash, event, actorId, data, createdAt) {
  const input = [prevHash, event, actorId ?? 0, canonicalize(data), createdAt].join('|');
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}
```

---

## 12. Bảng tấn công, mã lỗi, test case

Bảng này nối **rủi ro, cơ chế, kết quả mong đợi, test case**. TV4 hoàn thiện, TV2 đối chiếu khi code. Mã test `TC-xx` là gợi ý đặt tên, có thể điều chỉnh.

### Tình huống bình thường

| Mã | Tình huống | Kết quả mong đợi |
|---|---|---|
| TC-01 | Đăng nhập đúng mật khẩu và TOTP | 200, có phiên |
| TC-02 | Giao dịch 20 triệu, `manager` ký đúng | `APPROVED` ngay sau cấp 1 |
| TC-03 | Giao dịch 200 triệu, `manager` rồi `director` ký đúng | `PENDING_L2`, sau đó `APPROVED` |
| TC-04 | Audit log sau chuỗi thao tác bình thường | `/audit/verify` trả `valid: true` |

### Tình huống tấn công và rủi ro

| Mã | Tấn công | Cơ chế chặn | Mã lỗi mong đợi |
|---|---|---|---|
| TC-05 | **Giả giọng/tin nhắn giám đốc**: có yêu cầu "gấp" nhưng không có chữ ký | Chỉ chấp nhận duyệt kèm chữ ký thiết bị | `SIGNATURE_INVALID` hoặc `VALIDATION_ERROR` |
| TC-06 | **Sửa số tiền** sau khi người duyệt ký | Server dựng lại chuỗi ký từ CSDL, chữ ký không còn khớp | `SIGNING_PAYLOAD_MISMATCH` hoặc `SIGNATURE_INVALID` |
| TC-07 | **Replay**: gửi lại request duyệt cũ | Nonce dùng một lần | `NONCE_USED` |
| TC-08 | **Nonce hết hạn**: nộp chữ ký sau 5 phút | Nonce có thời hạn | `NONCE_EXPIRED` |
| TC-09 | **Chữ ký bằng khóa lạ** (kẻ tấn công tự sinh khóa) | Kiểm tra bằng khóa công khai đã đăng ký | `SIGNATURE_INVALID` |
| TC-10 | **Thiết bị chưa đăng ký** hoặc của người khác | Kiểm tra thiết bị thuộc người duyệt | `DEVICE_NOT_REGISTERED` |
| TC-11 | **Thiết bị đã bị thu hồi** (mất máy) | Trạng thái thiết bị | `DEVICE_REVOKED` |
| TC-12 | **Chiếm tài khoản**: có mật khẩu nhưng sai TOTP | MFA | `MFA_INVALID` |
| TC-13 | **Chiếm tài khoản**: có cả mật khẩu và phiên nhưng không có thiết bị | Duyệt cần chữ ký thiết bị | `DEVICE_NOT_REGISTERED` |
| TC-14 | **Tự duyệt**: người tạo duyệt giao dịch của chính mình | Luật tách nhiệm vụ | `SELF_APPROVAL` |
| TC-15 | **Một người duyệt cả hai cấp** | Luật 2 người độc lập | `DUPLICATE_APPROVER` |
| TC-16 | **Sai vai trò**: `accountant` gọi API duyệt | Phân quyền | `FORBIDDEN_ROLE` |
| TC-17 | **Dò mật khẩu/TOTP** (thử sai liên tục) | Rate limit và khóa tài khoản | `RATE_LIMITED`, `ACCOUNT_LOCKED` |
| TC-18 | **Sửa log trực tiếp trong SQLite** | Hash chain | `/audit/verify` trả `valid: false`, `broken_at` đúng dòng |
| TC-19 | **Duyệt giao dịch hết hạn** | Thời hạn giao dịch | `TX_EXPIRED` |
| TC-20 | **Duyệt song song cùng một nonce** (race) | Đánh dấu nonce nguyên tử trong transaction | Một request thành công, request còn lại `NONCE_USED` |

> **Kịch bản demo "wow":** chạy TC-05 trước mặt hội đồng: một "cuộc gọi giả giọng sếp" yêu cầu chuyển 200 triệu. Dù nội dung nghe rất thuyết phục, hệ thống từ chối kèm lý do. Kế đó chạy TC-06 và TC-18 để thấy phát hiện sửa dữ liệu và sửa log.

---

## 13. Cấu hình dùng chung

Đặt trong file `.env` (không commit lên GitHub, chỉ commit `.env.example`).

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` | `3000` | Cổng server |
| `SESSION_TTL_MINUTES` | `30` | Thời gian phiên hết hạn khi không hoạt động (phiên lưu phía server nên không còn cần `SESSION_SECRET`) |
| `DB_PATH` | `./data/trustsign.db` | Đường dẫn file SQLite |
| `APPROVAL_THRESHOLD_VND` | `50000000` | Ngưỡng cần 2 cấp duyệt |
| `TX_TTL_HOURS` | `24` | Thời hạn hiệu lực giao dịch |
| `NONCE_TTL_MINUTES` | `5` | Thời hạn nonce/challenge |
| `MAX_LOGIN_ATTEMPTS` | `5` | Số lần sai trước khi khóa |
| `LOCK_MINUTES` | `15` | Thời gian khóa tài khoản |
| `MAX_DEVICES_PER_USER` | `3` | Số thiết bị tối đa mỗi người |

### Dữ liệu mẫu để cả nhóm dùng chung khi dev và demo

| Username | Role | Ghi chú |
|---|---|---|
| `admin01` | `admin` | |
| `ketoan01` | `accountant` | Người tạo giao dịch |
| `quanly01` | `manager` | Duyệt cấp 1 |
| `giamdoc01` | `director` | Duyệt cấp 2 |
| `quanly02` | `manager` | Dùng cho test duyệt nhầm người |

TV1 viết script `python -m scripts.seed` để tạo các tài khoản này (mật khẩu chỉ dùng khi dev, không dùng trong báo cáo công khai).

---

## 14. Lịch sử thay đổi

| Ngày | Người sửa | Nội dung |
|---|---|---|
| 2026-10-02 | Nhóm | Tạo bản nháp 1.0 |
| 2026-10-02 | Nhóm | Chuyển backend sang Python/FastAPI. Hợp đồng API (đường dẫn, JSON, mã lỗi, chuỗi ký) giữ nguyên. Chỉ sửa các chỗ nhắc công nghệ và bỏ `SESSION_SECRET`. Xem thêm docs/INTERFACE-TV1.md và docs/INTERFACE-TV2.md cho các chi tiết cài đặt |
| | | |
