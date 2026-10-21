# TrustSign (Python / FastAPI)

Hệ thống xác nhận giao dịch nhạy cảm chống giả mạo. Nguyên tắc: **không tin thứ trông có vẻ thật, chỉ tin thứ kiểm chứng được bằng mật mã.**

Backend: Python + FastAPI + SQLite. Hợp đồng API: `docs/API.md` (giữ nguyên so với bản Node.js).

## 1. Cài đặt trên Windows

Cần **Python 3.10 trở lên** (đã kiểm thử trên 3.12). Kiểm tra: mở PowerShell hoặc CMD, gõ `py --version`.
Nếu chưa có, tải tại python.org và nhớ tích **Add python.exe to PATH** khi cài.

```bat
cd trustsign
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Mở `.env`, đặt `ADMIN_EMAIL` thành email bạn muốn nhận mã, rồi điền thông tin SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`) do nhà cung cấp email cấp. Với SMTP cổng 587, giữ `SMTP_STARTTLS=true`; với cổng 465, đặt `SMTP_USE_SSL=true` và `SMTP_STARTTLS=false`. Không chia sẻ hoặc commit `SMTP_PASSWORD`. Sau đó chạy:

```bat
python -m scripts.seed
python run.py
```

Mở trình duyệt:
- Giao diện: http://localhost:3000
- Thử API bằng tay: http://localhost:3000/docs

**Lỗi thường gặp trên Windows**
- PowerShell báo *"running scripts is disabled"* khi `venv\Scripts\activate`: chạy `Set-ExecutionPolicy -Scope Process RemoteSigned` rồi kích hoạt lại, hoặc dùng CMD thay vì PowerShell.
- Gõ `python` mà mở Microsoft Store: dùng `py` thay cho `python`, hoặc tắt "App execution aliases" trong Settings.
- Mỗi lần mở cửa sổ terminal mới phải chạy lại `venv\Scripts\activate`.

## 2. Các lệnh hay dùng

| Việc | Lệnh |
|---|---|
| Chạy server | `python run.py` (thêm `--reload` khi đang code) |
| Tạo người dùng mẫu (mã MFA gửi tới `ADMIN_EMAIL`) | `python -m scripts.seed` |
| Chạy toàn bộ test (74 test) | `python -m pytest` |
| Chạy riêng phần TV1 / TV2 | `python -m pytest tests/test_auth.py tests/test_devices.py` / `python -m pytest tests/test_transactions.py tests/test_crypto.py` |
| Demo sửa audit log | `python -m scripts.tamper_log 8` rồi gọi `GET /api/audit/verify` |
| Xóa sạch dữ liệu làm lại | xóa thư mục `data\` rồi chạy lại seed |

Mật khẩu mọi user mẫu: `MatKhau@12345`. Users: `admin01`, `ketoan01`, `quanly01`, `giamdoc01`, `quanly02`. Khi seed dev, tài khoản `admin01` nhận mã MFA tại `ADMIN_EMAIL`; các user mẫu còn lại dùng địa chỉ giữ chỗ `@example.test`. Tài khoản tạo mới cần có email riêng và sẽ nhận mã ở địa chỉ đó.

## 3. Cấu trúc và ai sở hữu

```
trustsign/
├── run.py                      chạy server
├── app/
│   ├── main.py                 ghép router, xử lý lỗi, header bảo mật         (TV1)
│   ├── config.py, errors.py, timeutil.py                                      (TV1)
│   ├── db.py, schema.sql       SQLite, transaction, toàn bộ bảng              (TV1)
│   ├── session.py, ratelimit.py, deps.py                                      (TV1)
│   ├── routers/auth.py, users.py, devices.py                                  (TV1)
│   ├── routers/transactions.py, audit.py                                      (TV2)
│   └── services/crypto.py, audit.py, approval.py                              (TV2)
├── public/                     giao diện                                      (TV3)
├── scripts/                    seed, tamper_log                                (TV1 / TV4)
├── tests/                      71 test                                        (TV1, TV2, TV4)
└── docs/
    ├── API.md                  hợp đồng API chung của cả nhóm
    ├── INTERFACE-TV1.md        TV1 trả ra gì, nhận vào gì
    ├── INTERFACE-TV2.md        TV2 trả ra gì, nhận vào gì
    └── examples/browser_flow.mjs   ví dụ luồng ký phía trình duyệt (WebCrypto) cho TV3
```

## 4. Quyết định thiết kế đáng nói trong báo cáo

| Quyết định | Lý do |
|---|---|
| Phiên lưu **phía server**, cookie chỉ chứa token ngẫu nhiên | Đăng xuất là hủy thật; cookie bị đánh cắp cũng mất hiệu lực (có test) |
| Server là bên **duy nhất tạo chuỗi cần ký**; client ký nguyên văn | Tránh lệch từng byte giữa Python và JavaScript; đúng nguyên tắc WYSIWYS |
| Dựng lại chuỗi ký **từ DB** khi duyệt, so với bản đã phát hành | Phát hiện dữ liệu giao dịch bị sửa sau khi người duyệt thấy nội dung |
| `level` do server quyết định, vai trò đọc lại từ DB mỗi request | Không tin gì từ phía client |
| Nonce dùng một lần + nguyên tử trong transaction | Chống replay, kể cả hai request song song |
| Phát hiện replay **trước** các kiểm tra khác | Replay luôn được gọi đúng tên, không bị che bởi lỗi trạng thái |
| Mọi lần bị chặn đều ghi audit hash chain | Có bằng chứng hệ thống đã từ chối tấn công |
| Kiểm thử chéo bằng vector sinh từ WebCrypto thật | Chứng minh server Python chấp nhận đúng chữ ký của trình duyệt |

Giới hạn đã biết: xem cuối `docs/INTERFACE-TV1.md` và `docs/INTERFACE-TV2.md`.
