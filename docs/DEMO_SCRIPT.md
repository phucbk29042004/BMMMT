# Kịch bản demo TrustSign (TV3)

Kịch bản dưới đây dành cho demo local trên `http://localhost:3000`. Chuẩn bị server và dữ liệu trước khi trình chiếu; không dùng cờ demo trong production.

---

## 1. Chuẩn bị

1. Mở PowerShell ở thư mục dự án; khởi động server:

   ```powershell
   python -m scripts.seed --dev-totp
   python run.py
   ```

2. Mở `http://localhost:3000`. Kiểm tra `/docs` nếu cần đối chiếu API.
3. Bật demo mode chỉ trong bản demo bằng cách đổi `DEMO_MODE` trong `public/js/config.js` thành `true`, rồi tải lại trang.
4. Dùng mật khẩu mẫu `MatKhau@12345`. Tài khoản: `ketoan01` (accountant), `quanly01` và `quanly02` (manager), `giamdoc01` (director), `admin01` (admin).
5. Lấy mã hiện tại bằng `python -m scripts.totp`. Mã chỉ dùng một lần cho một user trong chu kỳ 30 giây; mỗi user cần mã riêng/không tái sử dụng mã cũ.
6. Đăng nhập manager và director ở các cửa sổ/profile trình duyệt riêng; đăng ký thiết bị cho từng người duyệt trong mục **Thiết bị**. Không xóa browser data giữa các bước.

---

## 2. Kịch bản thành công (khoảng 4 phút)

| Bước | Ai / màn hình | Thao tác và lời dẫn | Kết quả mong đợi |
|---|---|---|---|
| 1 | Kế toán / Đăng nhập | Đăng nhập `ketoan01` với mật khẩu mẫu, nhập TOTP mới nhất. “Mật khẩu đơn lẻ chưa đủ để tạo phiên.” | Vào hệ thống sau MFA. |
| 2 | Kế toán / Thiết bị | Đăng ký thiết bị nếu chưa có. “Private key không xuất được và chỉ lưu trong IndexedDB; server nhận public key.” | Thiết bị trạng thái active. |
| 3 | Kế toán / Tạo giao dịch | Tạo giao dịch 200.000.000 VND, số tài khoản `0123456789`, người nhận `CÔNG TY ÁNH DƯƠNG`, ghi chú `HĐ demo` (ghi chú không được ký). | `PENDING_L1`, yêu cầu hai cấp. |
| 4 | Quản lý / Giao dịch | Mở giao dịch, chọn **Duyệt có ký**. Đọc số tiền, người nhận, tài khoản, cấp, device và hạn nonce; mở `signing_string`/SHA-256; tick xác nhận rồi ký. | `PENDING_L2`; thành công với ký nguyên văn chuỗi server cấp. |
| 5 | Giám đốc / Giao dịch | Mở cùng giao dịch, xem trước cấp 2 và ký trên thiết bị director. | `APPROVED`. |
| 6 | Giám đốc hoặc admin / Audit log | Lọc `TX_APPROVED`, xem event/data/hash, bấm **Kiểm tra toàn vẹn**. | Hash chain `valid: true`. |

Để demo một cấp, tạo giao dịch nhỏ hơn ngưỡng 50.000.000 VND; manager duyệt sẽ chuyển thẳng sang `APPROVED`.

---

## 3. Kịch bản tấn công (khoảng 5 phút)

Chạy với giao dịch đang chờ phù hợp và demo mode được bật. Tránh dùng tài khoản thật hoặc dữ liệu cần giữ.

| Mã | Ai / màn hình | Thao tác | Kết quả mong đợi |
|---|---|---|---|
| TC-06b | Manager / Demo mode | Chọn giao dịch, device; chạy **TC-06b**. Giao diện ký chuỗi có amount lệch 1 VND. | `SIGNATURE_INVALID`; request bị ghi `APPROVAL_REJECTED_BY_SYSTEM`. |
| TC-07 | Manager / Demo mode | Sau khi đã có một lần duyệt thành công trong phiên, chọn **TC-07** để gửi lại nguyên request. | `NONCE_USED`; replay được ghi vào audit. |
| TC-09/13 | Người duyệt / Demo mode | Dùng challenge cho device hợp lệ nhưng gửi signature rỗng. | `SIGNATURE_INVALID`. |
| TC-10 | Người duyệt / Demo mode | Chọn giao dịch đang chờ và chạy với device ID không tồn tại. | `DEVICE_NOT_REGISTERED`. |
| TC-12 | Login / TOTP | Đăng xuất; nhập đúng mật khẩu, cố ý nhập TOTP sai. | `MFA_INVALID`. |
| TC-17 | Login | Dùng `ketoan01` hoặc `quanly02`, không dùng admin; thử sai mật khẩu/TOTP. | Rate limit theo IP và khóa tài khoản. Quan sát ghi chú sai khác bên dưới. |
| TC-18 | TV4 + director/admin / Audit | TV4 chạy `python -m scripts.tamper_log 8`; người có quyền vào audit và kiểm tra. | `valid: false`, reason và dòng lỗi được hiển thị. |

TC-05 (approve không chữ ký) có thể minh họa bằng yêu cầu API thiếu chữ ký; giao diện demo TC-09/13 thực hiện cùng nhánh `SIGNATURE_INVALID`. TC-11 có thể thực hiện bằng thu hồi thiết bị rồi gửi challenge lại.

### TC-06a và TC-08: không giả lập

- **TC-06a:** TV4 dùng DB demo riêng, xin challenge, sửa dữ liệu giao dịch trong DB trước approve rồi gửi chữ ký cũ; mong đợi `SIGNING_PAYLOAD_MISMATCH`. Không làm trên DB cần giữ.
- **TC-08:** xin challenge và chờ quá 5 phút rồi mới approve; mong đợi `NONCE_EXPIRED`. Không chỉnh đồng hồ hoặc giả lập hết hạn bằng client.

---

## 4. Khóa tài khoản, reset và phương án dự phòng

### Hành vi khóa theo code hiện tại

Đạt ngưỡng sai thứ năm sẽ đặt `locked_until`, nhưng response lần thứ năm hiện vẫn có thể là `AUTH_INVALID_CREDENTIALS`/`MFA_INVALID`. Request kế tiếp mới có thể trả `ACCOUNT_LOCKED`; rate limit 5 request/phút/IP có thể trả `RATE_LIMITED` trước. Chờ hết cửa sổ rate limit rồi thử lại để quan sát phản hồi khóa. Admin không bị khóa theo số lần sai nhưng vẫn chịu rate limit IP.

Để mở khóa tài khoản demo, dừng server và dùng thao tác SQLite có kiểm soát, hoặc chạy một phiên Python:

```powershell
python -c "import sqlite3; c=sqlite3.connect('data/trustsign.db'); c.execute(\"UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE username='ketoan01'\"); c.commit(); c.close()"
```

Không dùng thao tác này trên dữ liệu production. Rate limiter lưu trong bộ nhớ; chờ đủ 60 giây hoặc khởi động lại server demo để reset rate-limit state.

### Reset dữ liệu

Seed không ghi đè user đã tồn tại. Để làm lại hoàn toàn, dừng server, sao lưu nếu cần, xóa riêng DB demo `data/trustsign.db`, rồi chạy lại seed và server. Việc reset DB làm mất users, giao dịch, audit và device server-side; xóa IndexedDB trình duyệt sẽ làm mất private keys, cần đăng ký thiết bị lại.

### Nếu demo lỗi

1. Ghi lại mã HTTP, `error.code`, mã giao dịch và thời điểm từ thẻ lỗi; không che lỗi bằng thao tác lặp lại nonce cũ.
2. Nếu lỗi nonce, bấm xin challenge mới và đọc lại preview trước khi ký.
3. Nếu không thấy device, kiểm tra đang đăng nhập đúng user/profile và thiết bị còn `active`.
4. Nếu TOTP bị từ chối, đợi bước 30 giây kế tiếp rồi lấy mã mới; không tái sử dụng mã đã gửi.
5. Nếu audit tamper đang bật, reset DB demo trước khi chạy kịch bản thành công/hash hợp lệ.
6. Nếu lỗi server, dừng demo bảo mật và chuyển sang slide/ảnh có chú thích; không mô tả một kết quả giả như thể backend đã xác nhận.

---

## 5. Thông điệp kết thúc

“TrustSign không xác minh giọng nói hay lời nhắn. Nó yêu cầu MFA, thiết bị có khóa riêng và chữ ký trên chính nội dung đã hiển thị. Nonce ngăn phát lại; audit hash chain giúp phát hiện sửa log. Các giới hạn như mã độc trong trang, XSS, thiết bị bị kiểm soát và việc người dùng ký mà không hiểu nội dung vẫn cần được xử lý bằng quy trình và lớp bảo vệ bổ sung.”
