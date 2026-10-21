// VÍ DỤ THAM KHẢO CHO TV3: toàn bộ luồng phía trình duyệt, viết bằng WebCrypto (chạy được bằng Node 20+).
// Cách chạy: cấu hình SMTP/ADMIN_EMAIL trong .env, chạy python -m scripts.seed và python run.py,
// sau đó chạy node docs/examples/browser_flow.mjs. Nhập mã nhận trong email khi được hỏi.
// Phần ký ở đây GIỐNG HỆT code cần đưa vào trình duyệt (crypto.subtle).
import { webcrypto } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
const { subtle } = webcrypto;
const BASE = process.env.BASE || 'http://localhost:3000/api';
const PASSWORD = 'MatKhau@12345';
const prompt = createInterface({ input: process.stdin, output: process.stdout });

// ---- "trình duyệt" = một cookie jar + fetch. Trong trình duyệt thật cookie tự gửi kèm, không cần đoạn này.
class Browser {
  constructor() { this.cookie = ''; }
  async call(method, path, body) {
    const res = await fetch(BASE + path, {
      method, headers: { 'Content-Type': 'application/json', ...(this.cookie && { Cookie: this.cookie }) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const set = res.headers.getSetCookie?.() ?? [];
    if (set.length) this.cookie = set[0].split(';')[0];
    const text = await res.text();
    return { status: res.status, data: text ? JSON.parse(text) : null };
  }
  async login(username) {
    const started = await this.call('POST', '/auth/login', { username, password: PASSWORD });
    if (started.status !== 200) throw new Error('Đăng nhập bước mật khẩu lỗi: ' + JSON.stringify(started.data));
    console.log(`Mã xác thực đã gửi tới ${started.data.email_hint}`);
    const code = await prompt.question(`Nhập mã email của ${username}: `);
    const r = await this.call('POST', '/auth/mfa', { code });
    if (r.status !== 200) throw new Error('Đăng nhập thất bại: ' + JSON.stringify(r.data));
  }
}

// ---- Mã hóa base64 <-> ArrayBuffer
const b64 = (buf) => Buffer.from(buf).toString('base64'); // trình duyệt: btoa(String.fromCharCode(...new Uint8Array(buf)))

// ---- 1) Đăng ký thiết bị: sinh khóa KHÔNG xuất được, ký challenge để chứng minh sở hữu
async function registerDevice(browser, label) {
  const keyPair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  // extractable=false  => khóa riêng không đọc ra được. Trình duyệt thật: lưu keyPair vào IndexedDB (KHÔNG localStorage).
  // Khóa CÔNG KHAI luôn xuất được dù khóa riêng không xuất được:
  const publicKey = b64(await subtle.exportKey('spki', keyPair.publicKey));
  const { data: { challenge } } = await browser.call('POST', '/devices/challenge');
  const sig = b64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, new TextEncoder().encode(challenge)));
  const r = await browser.call('POST', '/devices/register', { label, public_key: publicKey, challenge, signature: sig });
  if (r.status !== 201) throw new Error('Đăng ký thiết bị lỗi: ' + JSON.stringify(r.data));
  return { deviceId: r.data.id, keyPair };
}

// ---- 2) Duyệt giao dịch: xin chuỗi -> HIỂN THỊ CHO NGƯỜI DÙNG ĐỌC -> ký NGUYÊN VĂN -> gửi
async function approve(browser, device, txId) {
  const ch = await browser.call('POST', `/transactions/${txId}/challenge`, { device_id: device.deviceId });
  if (ch.status !== 200) return ch;
  const content = JSON.parse(ch.data.signing_string); // chỉ để HIỂN THỊ (số tiền, người nhận...)
  console.log(`  [UI] Hiển thị cho người duyệt: ${content.amount.toLocaleString('vi-VN')} VND -> ${content.recipient_name} (${content.recipient_account})`);
  const sig = b64(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, device.keyPair.privateKey,
    new TextEncoder().encode(ch.data.signing_string))); // ký ĐÚNG chuỗi server đưa, không dựng lại
  const sent = { device_id: device.deviceId, nonce: ch.data.nonce, signature: sig };
  const res = await browser.call('POST', `/transactions/${txId}/approve`, sent);
  return { ...res, sent }; // giữ lại body đã gửi để demo tấn công replay
}

// ---- Kịch bản demo
const acct = new Browser(), mgr = new Browser(), dir = new Browser();
await acct.login('ketoan01'); await mgr.login('quanly01'); await dir.login('giamdoc01');
const mgrDev = await registerDevice(mgr, 'PC quản lý');
const dirDev = await registerDevice(dir, 'PC giám đốc');

const tx = await acct.call('POST', '/transactions', { amount: 200000000, recipient_account: '0123456789', recipient_name: 'CÔNG TY TNHH Ánh Dương', note: 'HĐ 09/2026' });
console.log('Tạo giao dịch:', tx.status, tx.data.status, `(cần ${tx.data.required_levels} cấp duyệt)`);

let r = await approve(mgr, mgrDev, tx.data.id);
console.log('Quản lý duyệt cấp 1:', r.status, r.data.status);
const captured = r.sent; // kẻ tấn công nghe lén được request hợp lệ này
r = await approve(dir, dirDev, tx.data.id);
console.log('Giám đốc duyệt cấp 2:', r.status, r.data.status);

// Tấn công: "cuộc gọi giả giọng sếp" -> yêu cầu duyệt không có chữ ký
const tx2 = await acct.call('POST', '/transactions', { amount: 300000000, recipient_account: '9999999999', recipient_name: 'NGUOI LA' });
const ch = await mgr.call('POST', `/transactions/${tx2.data.id}/challenge`, { device_id: mgrDev.deviceId });
r = await mgr.call('POST', `/transactions/${tx2.data.id}/approve`, { device_id: mgrDev.deviceId, nonce: ch.data.nonce });
console.log('Giả giọng sếp (không chữ ký):', r.status, r.data.error.code, '-', r.data.error.message);

// Replay: gửi lại NGUYÊN VĂN request hợp lệ đã bị nghe lén
const dup = await mgr.call('POST', `/transactions/${tx.data.id}/approve`, captured);
console.log('Gửi lại yêu cầu cũ:', dup.status, dup.data.error.code);

const v = await dir.call('GET', '/audit/verify');
console.log('Audit hash chain:', v.data);
prompt.close();
