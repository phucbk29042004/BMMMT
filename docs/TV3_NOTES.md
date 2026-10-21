# Ghi chú tích hợp của TV3

Tài liệu này lưu giả định, điểm cần xác nhận và đề nghị cho TV1/TV2; không thay đổi hợp đồng backend.

---

## 1. Giả định triển khai

| Mã | Giả định |
|---|---|
| A1 | `public/index.html` là entry point duy nhất; server mount `public/` tại root sau các API router. |
| A2 | Mọi API gọi cùng origin qua `/api`; trình duyệt tự gửi cookie `connect.sid`. |
| A3 | `POST /api/devices/challenge` không nhận body; `POST /api/devices/register` nhận `label`, `public_key`, `challenge`, `signature`. |
| A4 | `GET /api/transactions` phân quyền theo user/role trên backend; frontend chỉ lọc và hiển thị. |
| A5 | Các cấp duyệt xác định từ role/trạng thái backend; client không gửi level. |
| A6 | Audit `broken_at` là ID dòng audit cần tô nổi bật. |
| A7 | Demo mode là hằng số build-time đơn giản ở `public/js/config.js`; không lưu cờ hoặc thông tin xác thực trong Web Storage. |

---

## 2. Sai khác và điểm cần theo dõi

### Khóa tài khoản khi đạt ngưỡng

Tài liệu API nói sai mật khẩu hoặc TOTP năm lần thì khóa tài khoản 15 phút. Trong code hiện tại, lần thất bại thứ năm gọi `_register_failure` và đặt `locked_until`, nhưng response của chính lần đó vẫn là `AUTH_INVALID_CREDENTIALS` hoặc `MFA_INVALID`. `ACCOUNT_LOCKED` cùng `details.locked_until` được trả ở lần request tiếp theo (trừ trường hợp endpoint rate limit trả `RATE_LIMITED` trước đó).

TV3 hiển thị đếm ngược nếu backend trả `ACCOUNT_LOCKED` với `details.locked_until`; không tự suy ra hoặc giả lập trạng thái khóa từ phía client. TC-17 cần tính đến thứ tự thực tế: rate limit IP có thể che phản hồi `ACCOUNT_LOCKED` cho đến khi cửa sổ 60 giây kết thúc.

### Audit verify

Tài liệu mẫu mô tả `{valid, checked, broken_at, reason}` nhưng response hợp lệ trong code có thể bỏ `reason`. Giao diện chỉ đọc `reason` khi có và xử lý `broken_at: null`.

### TOTP setup

`POST /api/auth/totp/setup` trả `qr_data_url` và `otpauth_url`. CSP hiện tại đã cho `img-src data:` nên QR có thể hiển thị; không cần thay đổi CSP.

---

## 3. Đề nghị cho TV1

1. Cân nhắc trả `ACCOUNT_LOCKED` ngay tại lần nhập sai đã đạt ngưỡng, kèm `details.locked_until`, thay vì trả lỗi TOTP/credential cũ. Nếu thay đổi, cập nhật test và API contract để UI/demo có kết quả rõ ràng.
2. Cân nhắc giải thích rõ trong API contract rằng `RATE_LIMITED` theo IP có thể xuất hiện trước `ACCOUNT_LOCKED`.
3. Duy trì `img-src data:` khi endpoint TOTP setup trả QR dưới dạng data URL.
4. Production cần HTTPS và cookie phiên `Secure`; demo HTTP localhost hiện chủ ý chưa bật cờ này.

---

## 4. Đề nghị cho TV2

1. Giữ nguyên format `signing_string` canonical, UTF-8, các tên trường và ECDSA IEEE P1363 64 byte base64.
2. Giữ nguyên thứ tự challenge → preview → ký nguyên văn → approve; thay đổi contract cần phối hợp TV3 trước.
3. Duy trì audit event `APPROVAL_REJECTED_BY_SYSTEM` với `data.error_code` cho lỗi approve phát sinh trong logic kiểm tra.
4. Cập nhật response ví dụ của audit verify để thống nhất việc `reason` có/không có khi `valid: true`.

---

## 5. Ngoài phạm vi

TV3 không sửa backend, schema, seed script hoặc test của TV1/TV2/TV4. TC-06a cần TV4 sửa dữ liệu DB có kiểm soát; TC-08 yêu cầu chờ nonce thật hết hạn; giao diện không giả lập hai tình huống này.
