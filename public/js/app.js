import { api, ApiError } from "./api/client.js";
import { DEMO_MODE } from "./config.js";
import { createDeviceKeyPair, exportPublicKey, sha256Hex, signUtf8 } from "./crypto/encoding.js";
import { deletePrivateKey, getPrivateKey, savePrivateKey } from "./crypto/key-store.js";

const root = document.querySelector("#app");
const sessionArea = document.querySelector("#session-area");
const state = {
  user: null,
  authStep: "login",
  pendingUsername: "",
  pendingEmailHint: "",
  view: "transactions",
  showCreateLeaveConfirmation: false,
  createLeaveDestination: "",
  createTransactionDraft: null,
  transactions: [],
  totalTransactions: 0,
  devices: [],
  auditEntries: [],
  auditTotal: 0,
  auditOffset: 0,
  auditEvent: "",
  auditVerification: null,
  txFilter: "",
  detail: null,
  preview: null,
  rejectTxId: null,
  error: null,
  notice: null,
  demoResults: [],
  demoTxId: "",
  demoDeviceId: "",
  demoTargetUser: "ketoan01",
  lastApproveRequest: null,
  busy: false,
};

let companies = [];
let companiesRequest = null;
let companiesLoadState = "loading";
let companiesLoadError = "";
async function loadCompanies(retry = false) {
  if (companies.length) return companies;
  if (companiesRequest) return companiesRequest;
  if (companiesLoadState === "error" && !retry) return [];
  companiesLoadState = "loading";
  companiesRequest = (async () => {
    try {
      const res = await fetch("/data/companies.json");
      if (!res.ok) throw new Error(`Tệp danh sách công ty trả về HTTP ${res.status}.`);
      const data = await res.json();
      if (!Array.isArray(data) || data.some((company) =>
        !company || typeof company.account !== "string" || typeof company.name !== "string"
      )) {
        throw new Error("Tệp danh sách công ty có định dạng không hợp lệ.");
      }
      companies = data;
      companiesLoadState = "loaded";
      companiesLoadError = "";
      return companies;
    } catch (error) {
      companiesLoadState = "error";
      companiesLoadError = error instanceof Error ? error.message : "Không xác định được nguyên nhân.";
      return [];
    } finally {
      companiesRequest = null;
    }
  })();
  return companiesRequest;
}
void loadCompanies();

const ERROR_COPY = {
  NOT_AUTHENTICATED: ["Phiên đăng nhập chưa hợp lệ", "Hãy đăng nhập và hoàn tất xác thực TOTP rồi thử lại.", "Đăng nhập lại."],
  AUTH_INVALID_CREDENTIALS: ["Thông tin đăng nhập không đúng", "Tên đăng nhập hoặc mật khẩu chưa chính xác.", "Kiểm tra thông tin rồi thử lại."],
  FORBIDDEN_ROLE: ["Không đủ quyền", "Vai trò hiện tại không được phép thực hiện thao tác này.", "Đăng nhập bằng tài khoản đúng vai trò."],
  VALIDATION_ERROR: ["Dữ liệu chưa hợp lệ", "Một hoặc nhiều trường không đúng định dạng máy chủ yêu cầu.", "Kiểm tra các trường nhập và thử lại."],
  MFA_INVALID: ["Mã TOTP không hợp lệ", "Mã có thể sai, hết hạn hoặc đã được dùng trong chu kỳ 30 giây hiện tại.", "Lấy mã mới từ ứng dụng xác thực."],
  ACCOUNT_LOCKED: ["Tài khoản đang bị khóa", "Hệ thống tạm khóa tài khoản sau nhiều lần xác thực thất bại.", "Chờ hết thời hạn khóa rồi thử lại."],
  RATE_LIMITED: ["Đã thử quá nhiều lần", "Máy chủ đang giới hạn số yêu cầu trong một phút.", "Chờ hết thời gian giới hạn trước khi tiếp tục."],
  NONCE_USED: ["Nonce đã được sử dụng", "Yêu cầu này có thể là replay; nonce chỉ được dùng một lần.", "Xin challenge mới và ký lại nội dung."],
  NONCE_UNKNOWN: ["Nonce không được nhận diện", "Nonce không do máy chủ phát hành cho thao tác này.", "Xin challenge mới từ giao dịch đang duyệt."],
  NONCE_EXPIRED: ["Nonce đã hết hạn", "Thời hạn ký 5 phút đã kết thúc.", "Xin challenge mới rồi kiểm tra và ký lại."],
  TX_NOT_FOUND: ["Không tìm thấy giao dịch", "Giao dịch không tồn tại hoặc mã giao dịch không chính xác.", "Tải lại danh sách giao dịch."],
  TX_WRONG_STATE: ["Giao dịch không còn chờ thao tác", "Trạng thái hiện tại không cho phép duyệt, từ chối hoặc hủy.", "Tải lại giao dịch để xem trạng thái mới."],
  TX_EXPIRED: ["Giao dịch đã hết hạn", "Thời hạn xử lý giao dịch đã kết thúc.", "Liên hệ người tạo để lập yêu cầu mới."],
  SELF_APPROVAL: ["Không thể tự duyệt", "Người tạo giao dịch không được phê duyệt giao dịch của chính mình.", "Nhờ người có thẩm quyền khác xử lý."],
  DUPLICATE_APPROVER: ["Cần người duyệt độc lập", "Một người không thể duyệt hai cấp của cùng giao dịch.", "Mời người duyệt khác ở cấp tiếp theo."],
  DEVICE_NOT_REGISTERED: ["Thiết bị chưa đăng ký", "Thiết bị không thuộc tài khoản hiện tại hoặc chưa đăng ký.", "Đăng ký thiết bị hợp lệ rồi thử lại."],
  DEVICE_REVOKED: ["Thiết bị đã bị thu hồi", "Máy chủ không chấp nhận chữ ký từ thiết bị này.", "Đăng ký thiết bị khác."],
  SIGNING_PAYLOAD_MISMATCH: ["Nội dung giao dịch đã thay đổi", "Chuỗi ký được phát hành không còn khớp dữ liệu giao dịch trên máy chủ.", "Không ký; tải lại giao dịch và báo quản trị viên."],
  SIGNATURE_INVALID: ["Chữ ký số không hợp lệ", "Chữ ký không khớp với khóa thiết bị hoặc nội dung đã ký.", "Dùng khóa đúng và ký lại challenge mới."],
  DEVICE_NOT_FOUND: ["Không tìm thấy thiết bị", "Thiết bị được yêu cầu không còn tồn tại.", "Tải lại danh sách thiết bị."],
  USERNAME_TAKEN: ["Tên đăng nhập đã được sử dụng", "Tên này đã có trong hệ thống.", "Chọn tên đăng nhập khác."],
  DEVICE_LIMIT: ["Đã đạt giới hạn thiết bị", "Mỗi người dùng chỉ được có tối đa ba thiết bị đang hoạt động.", "Thu hồi một thiết bị cũ trước khi đăng ký thêm."],
  INTERNAL_ERROR: ["Lỗi hệ thống", "Máy chủ không thể hoàn tất thao tác.", "Thử lại sau; nếu lỗi tiếp diễn, báo quản trị viên."],
};

const STATUS_LABEL = {
  PENDING_L1: "Chờ duyệt cấp 1",
  PENDING_L2: "Chờ duyệt cấp 2",
  APPROVED: "Đã duyệt",
  REJECTED: "Bị từ chối",
  CANCELLED: "Đã hủy",
  EXPIRED: "Hết hạn",
};

const EVENT_OPTIONS = [
  "LOGIN_SUCCESS", "LOGIN_FAILED", "MFA_SUCCESS", "MFA_FAILED", "ACCOUNT_LOCKED",
  "USER_CREATED", "DEVICE_REGISTERED", "DEVICE_REVOKED", "TX_CREATED", "TX_APPROVED",
  "TX_FULLY_APPROVED", "TX_REJECTED", "TX_CANCELLED", "TX_EXPIRED", "APPROVAL_REJECTED_BY_SYSTEM",
];

const AUDIT_EVENT_LABELS = {
  LOGIN_SUCCESS: {
    label: "Đăng nhập thành công (bước mật khẩu)",
    description: "Thông tin mật khẩu hợp lệ; người dùng cần tiếp tục xác thực OTP qua email.",
    level: "success",
  },
  LOGIN_FAILED: {
    label: "Đăng nhập không thành công",
    description: "Thông tin đăng nhập không được chấp nhận ở bước mật khẩu.",
    level: "error",
  },
  MFA_SUCCESS: {
    label: "Xác thực OTP qua email thành công",
    description: "Mã OTP hợp lệ và quá trình đăng nhập đã hoàn tất.",
    level: "success",
  },
  MFA_FAILED: {
    label: "Xác thực OTP không thành công",
    description: "Mã OTP nhập vào không được chấp nhận.",
    level: "error",
  },
  ACCOUNT_LOCKED: {
    label: "Tài khoản bị tạm khóa",
    description: "Tài khoản bị khóa tạm thời sau nhiều lần xác thực không thành công.",
    level: "warning",
  },
  USER_CREATED: {
    label: "Đã tạo người dùng",
    description: "Một tài khoản người dùng mới đã được tạo.",
    level: "info",
  },
  DEVICE_REGISTERED: {
    label: "Đã đăng ký thiết bị",
    description: "Thiết bị mới đã được đăng ký để sử dụng trong hệ thống.",
    level: "success",
  },
  DEVICE_REVOKED: {
    label: "Đã thu hồi thiết bị",
    description: "Thiết bị không còn được phép sử dụng trong hệ thống.",
    level: "warning",
  },
  TX_CREATED: {
    label: "Đã tạo giao dịch",
    description: "Một yêu cầu giao dịch mới đã được ghi nhận.",
    level: "info",
  },
  TX_APPROVED: {
    label: "Giao dịch được duyệt một cấp",
    description: "Một cấp phê duyệt đã hoàn tất; giao dịch có thể còn cấp duyệt tiếp theo.",
    level: "success",
  },
  TX_FULLY_APPROVED: {
    label: "Giao dịch được duyệt đầy đủ",
    description: "Giao dịch đã hoàn tất tất cả các cấp phê duyệt cần thiết.",
    level: "success",
  },
  TX_REJECTED: {
    label: "Giao dịch bị từ chối",
    description: "Người có thẩm quyền đã từ chối giao dịch.",
    level: "warning",
  },
  TX_CANCELLED: {
    label: "Giao dịch đã bị hủy",
    description: "Yêu cầu giao dịch đã được người tạo hủy.",
    level: "warning",
  },
  TX_EXPIRED: {
    label: "Giao dịch hết hạn",
    description: "Giao dịch đã quá thời hạn xử lý.",
    level: "warning",
  },
  APPROVAL_REJECTED_BY_SYSTEM: {
    label: "Yêu cầu duyệt bị hệ thống từ chối",
    description: "Hệ thống không chấp nhận yêu cầu phê duyệt nên chưa ghi nhận chữ ký.",
    level: "error",
  },
};

const AUDIT_DATA_LABELS = {
  tx_id: "Mã giao dịch",
  amount: "Số tiền",
  recipient_account: "Số tài khoản người nhận",
  attempts: "Số lần xác thực không thành công",
  locked_until: "Thời điểm tự mở khóa",
  trigger: "Nguyên nhân khóa",
  username: "Tên đăng nhập",
  reason: "Lý do",
  stage: "Giai đoạn",
  user_id: "Mã người dùng",
  role: "Vai trò",
  seeded: "Tạo từ dữ liệu khởi tạo",
  device_id: "Mã thiết bị",
  label: "Tên thiết bị",
  owner_id: "Mã chủ sở hữu",
  level: "Cấp phê duyệt",
  error_code: "Lý do hệ thống từ chối",
};

const AUDIT_DATA_VALUE_LABELS = {
  stage: { EMAIL_MFA: "Xác thực OTP qua email" },
  reason: {
    unknown_user: "Không tìm thấy tài khoản",
    locked: "Tài khoản đang bị khóa",
  },
  trigger: {
    LOGIN_FAILED: "Đăng nhập không thành công",
    MFA_FAILED: "Xác thực OTP không thành công",
  },
};

const SEEDED_ACTOR_ROLES = {
  1: "admin",
  2: "accountant",
  3: "manager",
  4: "director",
  5: "manager",
};

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined) node.textContent = String(options.text);
  if (options.type) node.type = options.type;
  if (options.name) node.name = options.name;
  if (options.value !== undefined) node.value = String(options.value);
  if (options.placeholder) node.placeholder = options.placeholder;
  if (options.required) node.required = true;
  if (options.checked) node.checked = true;
  if (options.disabled) node.disabled = true;
  if (options.href) node.href = options.href;
  if (options.src) node.src = options.src;
  if (options.alt) node.alt = options.alt;
  if (options.target) node.target = options.target;
  if (options.rel) node.rel = options.rel;
  if (options.id) node.id = options.id;
  if (options.colSpan) node.colSpan = options.colSpan;
  if (options.current) node.setAttribute("aria-current", options.current);
  if (options.attributes) {
    for (const [key, value] of Object.entries(options.attributes)) node.setAttribute(key, String(value));
  }
  for (const child of children) if (child) node.append(child);
  return node;
}

function button(label, action, className = "button") {
  const node = el("button", { className, text: label, type: "button" });
  node.dataset.action = action;
  node.disabled = state.busy;
  return node;
}

function replaceAppContent(content) {
  root.setAttribute("aria-busy", String(state.busy));
  if (state.busy) {
    content.querySelectorAll("button, input, select, textarea").forEach((control) => {
      control.disabled = true;
    });
  }
  root.replaceChildren(content);
}

function field(labelText, input, full = false) {
  return el("div", { className: `field${full ? " full" : ""}` }, [
    el("label", { text: labelText, attributes: { for: input.id } }),
    input,
  ]);
}

function input(name, type = "text", options = {}) {
  return el("input", {
    name,
    id: options.id || name,
    type,
    required: options.required ?? true,
    value: options.value,
    placeholder: options.placeholder,
    attributes: options.attributes,
  });
}

function select(name, items, selected = "") {
  const control = el("select", { name, id: name });
  for (const item of items) {
    const option = el("option", { value: item.value, text: item.label });
    option.selected = item.value === selected;
    control.append(option);
  }
  return control;
}

function backButton(action) {
  const control = button("Trở về", action, "back-button");
  control.setAttribute("aria-label", "Trở về");
  control.prepend(el("span", { className: "back-arrow", attributes: { "aria-hidden": "true" } }));
  return control;
}

function heading(title, subtitle, eyebrow = "TrustSign", backAction = null) {
  const content = el("div");
  if (backAction) content.append(backButton(backAction));
  content.append(
    el("p", { className: "eyebrow", text: eyebrow }),
    el("h1", { text: title }),
    el("p", { text: subtitle }),
  );
  return el("div", { className: "page-heading" }, [
    content,
  ]);
}

function createTransactionHasChanges() {
  const form = root.querySelector(".transaction-form");
  if (!form) return false;
  return Array.from(form.querySelectorAll("input, select, textarea"))
    .some((control) => control.value.trim() !== "");
}

function renderCreateLeaveConfirmation() {
  const stayButton = button("Ở lại", "stay-create", "button secondary");
  const leaveButton = button("Rời đi", state.createLeaveDestination || "nav:transactions", "button danger");
  leaveButton.dataset.confirmLeave = "true";
  return el("section", {
    className: "leave-confirmation",
    attributes: {
      role: "alertdialog",
      "aria-labelledby": "leave-create-title",
      "aria-describedby": "leave-create-description",
    },
  }, [
    el("div", {}, [
      el("h2", { id: "leave-create-title", text: "Rời trang tạo giao dịch?" }),
      el("p", { id: "leave-create-description", text: "Thông tin bạn đã nhập sẽ không được lưu." }),
    ]),
    el("div", { className: "toolbar" }, [stayButton, leaveButton]),
  ]);
}

function formatAmount(amount, currency = "VND") {
  return `${new Intl.NumberFormat("vi-VN").format(amount)} ${currency}`;
}

function statusBadge(status) {
  return el("span", { className: `status status-${status}`, text: STATUS_LABEL[status] || status });
}

function empty(text) {
  return el("div", { className: "empty-state", text });
}

function valueCell(label, value, className = "") {
  return el("div", { className: `preview-item${className ? ` ${className}` : ""}` }, [
    el("span", { text: label }),
    el("strong", { text: value ?? "—" }),
  ]);
}

function appendFeedback(parent) {
  if (state.error) parent.append(errorCard(state.error));
  else if (state.notice) parent.append(el("div", { className: "notice success", text: state.notice }));
}

function errorCard(error, id = null) {
  const copy = ERROR_COPY[error.code] || ["Yêu cầu bị từ chối", error.message || "Máy chủ trả về lỗi chưa được ánh xạ.", "Đối chiếu mã lỗi với tài liệu API."];
  const card = el("section", { className: "error-card", attributes: { ...(id ? { id } : {}), role: "alert" } });
  card.append(
    el("h3", { text: copy[0] }),
    el("span", { className: "error-code", text: error.code || "UNKNOWN_ERROR" }),
    el("p", { text: copy[1] }),
    el("p", { text: `Thông báo máy chủ: ${error.message || "Không có thông báo."}` }),
    el("p", { text: `Gợi ý: ${copy[2]}` }),
  );
  const meta = el("div", { className: "error-meta" });
  meta.append(
    el("span", { text: `HTTP ${error.status ?? "—"}` }),
    el("span", { text: `Thời điểm: ${error.at || new Date().toLocaleString("vi-VN")}` }),
  );
  if (error.txId !== undefined && error.txId !== null) meta.append(el("span", { text: `Giao dịch: ${error.txId}` }));
  card.append(meta);
  if (error.audit) {
    const note = el("div", { className: "notice warning", text: "Lần từ chối duyệt này được ghi vào audit với sự kiện APPROVAL_REJECTED_BY_SYSTEM." });
    if (canViewAudit()) note.append(button("Mở audit log", "nav:audit", "button small secondary"));
    card.append(note);
  }
  if (error.code === "ACCOUNT_LOCKED" && error.details?.locked_until) {
    const countdown = el("p", { className: "mono", id: "lock-countdown" });
    card.append(countdown);
    updateCountdown(countdown, error.details.locked_until);
  }
  return card;
}

function setError(error, txId = null, audit = false) {
  const source = error instanceof ApiError
    ? { code: error.code, message: error.message, status: error.status, details: error.details }
    : { code: "CLIENT_ERROR", message: error.message || String(error), status: "client" };
  state.error = {
    ...source,
    at: new Date().toLocaleString("vi-VN"),
    txId,
    audit: Boolean(audit && txId),
  };
  state.notice = null;
}

function updateCountdown(node, timestamp) {
  let timer;
  const update = () => {
    const remaining = Math.max(0, Math.ceil((Date.parse(timestamp) - Date.now()) / 1000));
    node.textContent = remaining ? `Còn khóa: ${Math.floor(remaining / 60)} phút ${remaining % 60} giây` : "Thời hạn khóa đã kết thúc; hãy thử đăng nhập lại.";
    if (remaining <= 0) clearInterval(timer);
  };
  update();
  timer = setInterval(update, 1000);
}

function canViewAudit() {
  return ["admin", "director"].includes(state.user?.role);
}

function roleName(role) {
  return ({ accountant: "Kế toán", manager: "Quản lý", director: "Giám đốc", admin: "Quản trị viên" })[role] || role;
}

function setSession() {
  sessionArea.replaceChildren();
  if (!state.user) return;
  const username = state.user.username;
  sessionArea.append(
    el("span", { className: "session-identity" }, [
      el("span", { className: "user-avatar", text: username.slice(0, 1).toUpperCase(), attributes: { "aria-hidden": "true" } }),
      el("span", { text: `${username} · ${roleName(state.user.role)}` }),
    ]),
    button("Đăng xuất", "logout", "icon-button"),
  );
}

function setBusy(value) {
  state.busy = value;
  setSession();
}

async function perform(action, txId = null, audit = false) {
  if (state.busy) return;
  state.busy = true;
  state.error = null;
  state.notice = null;
  render();
  try {
    await action();
  } catch (error) {
    setError(error, txId, audit || Boolean(state.error?.audit));
  } finally {
    state.busy = false;
    render();
  }
}

function renderAuth() {
  setSession();
  const main = el("div", { className: "auth-layout" });
  const story = el("aside", { className: "auth-story", attributes: { "aria-label": "Thông tin về TrustSign" } }, [
    el("div", { className: "auth-story-top" }, [
      el("span", { className: "auth-story-mark", text: "TS", attributes: { "aria-hidden": "true" } }),
      el("span", { text: "Giao dịch có thể kiểm chứng" }),
    ]),
    el("div", { className: "auth-story-copy" }, [
      el("p", { className: "auth-story-title", text: "Mỗi chữ ký đều bắt đầu bằng sự tin cậy." }),
      el("p", { text: "TrustSign giúp mỗi quyết định quan trọng được xác thực, minh bạch và có thể kiểm chứng." }),
      el("ul", { className: "auth-principles" }, [
        el("li", {}, [el("span", {}, [
          el("strong", { text: "Xác thực hai bước" }),
          el("span", { text: "Mật khẩu kết hợp mã OTP gửi qua email." }),
        ])]),
        el("li", {}, [el("span", {}, [
          el("strong", { text: "Nội dung rõ ràng trước khi ký" }),
          el("span", { text: "Kiểm tra thông tin giao dịch trước khi phê duyệt." }),
        ])]),
        el("li", {}, [el("span", {}, [
          el("strong", { text: "Phiên được bảo vệ" }),
          el("span", { text: "Phiên đăng nhập được quản lý bằng cookie httpOnly." }),
        ])]),
      ]),
    ]),
    el("div", { className: "auth-story-foot", text: "Bảo mật cho từng quyết định" }),
  ]);
  const panel = el("section", { className: "auth-panel" });
  const authHeading = heading("Đăng nhập TrustSign", "Xác thực gồm mật khẩu và mã OTP qua email; phiên được quản lý bằng cookie httpOnly.", "Không có giao dịch nào được ký ở bước này");
  authHeading.classList.add("auth-heading");
  panel.append(authHeading);
  const currentStep = state.authStep === "login" ? 1 : 2;
  const progress = el("ol", { className: "auth-progress", attributes: { "aria-label": "Tiến trình đăng nhập" } });
  for (const [step, label] of [[1, "Mật khẩu"], [2, "OTP qua email"]]) {
    const item = el("li", {
      text: label,
      attributes: { "data-step": step, ...(step === currentStep ? { "aria-current": "step" } : {}) },
    });
    if (step < currentStep) item.classList.add("is-complete");
    progress.append(item);
  }
  panel.append(progress);
  const card = el("section", { className: "card auth-card", attributes: { "aria-labelledby": "auth-title" } });
  const inlineError = state.error && (
    state.authStep === "mfa"
    || ["AUTH_INVALID_CREDENTIALS", "ACCOUNT_LOCKED", "RATE_LIMITED"].includes(state.error.code)
  );
  if (!inlineError || state.notice) appendFeedback(card);
  const form = el("form", { className: "form-grid auth-form", attributes: { "aria-busy": state.busy } });

  if (state.authStep === "login") {
    card.append(el("h2", { id: "auth-title", text: "Bước 1 · Mật khẩu" }));
    const usernameField = field("Tên đăng nhập", input("username", "text", { attributes: { autocomplete: "username" } }));
    const passwordInput = input("password", "password", { attributes: { autocomplete: "current-password" } });
    const passwordField = field("Mật khẩu", passwordInput);
    if (inlineError) {
      passwordInput.setAttribute("aria-invalid", "true");
      passwordInput.setAttribute("aria-describedby", "form-error");
      passwordField.append(errorCard(state.error, "form-error"));
    }
    form.append(
      usernameField,
      passwordField,
      el("div", { className: "field full" }, [el("button", { className: "button", text: "Tiếp tục", type: "submit", disabled: state.busy })]),
    );
  } else {
    // authStep === "mfa"
    card.append(el("h2", { id: "auth-title", text: "Bước 2 · Xác thực Email OTP" }));
    card.append(el("p", { className: "help", text: `Mã 6 số đã gửi tới ${state.pendingEmailHint || "email của bạn"}. Mã có hiệu lực 10 phút và chỉ dùng được một lần.` }));
    const codeInput = input("code", "text", { attributes: { inputmode: "numeric", pattern: "[0-9]{6}", maxlength: 6, autocomplete: "one-time-code" } });
    const codeField = field("Mã OTP 6 số", codeInput);
    if (inlineError) {
      codeInput.setAttribute("aria-invalid", "true");
      codeInput.setAttribute("aria-describedby", "form-error");
      codeField.append(errorCard(state.error, "form-error"));
    }
    form.append(
      codeField,
      el("div", { className: "field full toolbar" }, [
        el("button", { className: "button", text: "Xác thực", type: "submit", disabled: state.busy }),
        button("Gửi lại mã", "resend-mfa", "button secondary"),
      ]),
    );
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    perform(async () => {
      if (state.authStep === "login") {
        const result = await api.login(data);
        state.pendingUsername = data.username;
        state.pendingEmailHint = result.email_hint || "";
        state.error = null;
        if (result.status === "MFA_REQUIRED") {
          state.authStep = "mfa";
        } else {
          throw new Error(`Trạng thái đăng nhập không được hỗ trợ: ${result.status}`);
        }
        return;
      }
      // authStep === "mfa"
      const result = await api.mfa({ code: data.code });
      state.user = result.user;
      state.authStep = "login";
      state.pendingEmailHint = "";
      const current = await api.me();
      state.user = current;
      state.view = current.role === "admin" ? "audit" : "transactions";
      if (state.view === "audit") await loadAudit();
      else await loadTransactions();
    });
  });
  card.append(form);
  panel.append(card);
  if (DEMO_MODE) panel.append(renderLoginDemo());
  main.append(story, panel);
  replaceAppContent(main);
}

function renderLoginDemo() {
  const card = el("section", { className: "card demo-panel" });
  card.append(
    el("h2", { text: "Demo mode · xác thực" }),
    el("p", { className: "help", text: "TC-12: dùng đúng mật khẩu rồi nhập một mã TOTP sai để minh họa MFA_INVALID. TC-17: dùng tài khoản không phải admin; mã sai liên tục có thể khóa tài khoản." }),
  );
  return card;
}

function navItems() {
  const items = state.user.role === "admin" ? [] : [{ id: "transactions", label: "Giao dịch" }];
  if (state.user.role !== "admin") items.push({ id: "devices", label: "Thiết bị" });
  if (canViewAudit()) items.push({ id: "audit", label: "Audit log" });
  if (DEMO_MODE && state.user.role !== "admin") items.push({ id: "demo", label: "Demo mode" });
  return items;
}

function render() {
  if (!state.user) {
    renderAuth();
    return;
  }
  setSession();
  const shell = el("div");
  const title = state.view === "devices"
    ? ["Thiết bị tin cậy", "Khóa riêng được lưu trong IndexedDB của trình duyệt; máy chủ chỉ nhận khóa công khai.", "Quản lý thiết bị"]
    : state.view === "audit"
      ? ["Audit log", "Theo dõi sự kiện và xác minh tính liên tục của hash chain.", "Bằng chứng kiểm toán"]
      : state.view === "demo"
        ? ["Bảng demo", "Các phép thử chỉ gửi yêu cầu API từ client; không sửa dữ liệu/backend ngoài thao tác API đã nêu.", "Mô phỏng có kiểm soát"]
        : state.view === "create"
          ? ["Tạo giao dịch", "Nhập nội dung yêu cầu thanh toán; người duyệt sẽ thấy trước khi ký.", "Dành cho kế toán"]
          : ["Giao dịch", "Danh sách và thao tác được hiển thị theo vai trò; backend vẫn là nơi quyết định quyền.", "Trung tâm phê duyệt"];
  shell.append(heading(...title, state.view === "create" ? "nav:transactions" : null));
  if (state.view === "create" && state.showCreateLeaveConfirmation) {
    shell.append(renderCreateLeaveConfirmation());
  }
  appendFeedback(shell);

  const nav = el("nav", { className: "nav-list", attributes: { "aria-label": "Điều hướng chính" } });
  for (const item of navItems()) {
    const navButton = button(item.label, `nav:${item.id}`, "nav-button");
    if (state.view === item.id) navButton.setAttribute("aria-current", "page");
    nav.append(navButton);
  }
  shell.append(nav);

  if (state.view === "devices") shell.append(renderDevices());
  else if (state.view === "audit") shell.append(renderAudit());
  else if (state.view === "create") shell.append(renderCreateTransaction());
  else if (state.view === "demo" && DEMO_MODE) shell.append(renderDemoPanel());
  else shell.append(renderTransactions());
  replaceAppContent(shell);
}

async function loadTransactions() {
  const suffix = state.txFilter ? `?status=${encodeURIComponent(state.txFilter)}&limit=100&offset=0` : "?limit=100&offset=0";
  const result = await api.transactions(suffix);
  state.transactions = result.transactions;
  state.totalTransactions = result.total;
}

async function loadDevices() {
  const result = await api.devices();
  state.devices = result.devices;
}

function renderTransactions() {
  const panel = el("section", { className: "card" });
  const filters = [
    { value: "", label: "Tất cả trạng thái" },
    ...Object.entries(STATUS_LABEL).map(([value, label]) => ({ value, label })),
  ];
  const filterControl = select("tx-filter", filters, state.txFilter);
  filterControl.className = "filter-control";
  filterControl.addEventListener("change", () => perform(async () => {
    state.txFilter = filterControl.value;
    await loadTransactions();
  }));
  const actions = el("div", { className: "toolbar" }, [filterControl]);
  if (state.user.role === "accountant") actions.append(button("Tạo giao dịch", "new-transaction", "button success"));
  panel.append(
    el("div", { className: "toolbar-spread" }, [
      el("div", {}, [el("h2", { text: "Danh sách giao dịch" }), el("p", { className: "help", text: `Tổng ${state.totalTransactions} giao dịch` })]),
      actions,
    ]),
  );
  if (state.detail) panel.append(renderDetail(state.detail));
  if (state.preview) panel.append(renderPreview(state.preview));
  if (state.rejectTxId !== null) panel.append(renderRejectForm(state.rejectTxId));
  if (!state.transactions.length) {
    panel.append(empty("Không có giao dịch nào phù hợp. Hãy thử bộ lọc khác hoặc tạo giao dịch mới."));
    return panel;
  }
  const table = el("table");
  table.className = "transaction-table";
  table.append(el("thead", {}, [el("tr", {}, [
    el("th", { text: "Mã / trạng thái" }), el("th", { text: "Số tiền" }), el("th", { text: "Người nhận" }),
    el("th", { text: "Tạo lúc" }), el("th", { text: "Thao tác" }),
  ])]));
  const body = el("tbody");
  for (const tx of state.transactions) {
    const status = el("div", {}, [statusBadge(tx.status)]);
    const detailButton = button("Chi tiết", `tx-detail:${tx.id}`, "button small secondary");
    const rowActions = el("div", { className: "toolbar" }, [detailButton]);
    if (state.user.role === "accountant" && ["PENDING_L1", "PENDING_L2"].includes(tx.status)) {
      rowActions.append(button("Hủy", `tx-cancel:${tx.id}`, "button small danger"));
    }
    if (state.user.role === "manager" && tx.status === "PENDING_L1") {
      rowActions.append(button("Duyệt có ký", `tx-approve:${tx.id}`, "button small success"));
    }
    if (state.user.role === "director" && tx.status === "PENDING_L2") {
      rowActions.append(button("Duyệt có ký", `tx-approve:${tx.id}`, "button small success"));
    }
    if (["manager", "director"].includes(state.user.role) && ["PENDING_L1", "PENDING_L2"].includes(tx.status)) {
      rowActions.append(button("Từ chối", `tx-reject:${tx.id}`, "button small danger"));
    }
    body.append(el("tr", {}, [
      el("td", { attributes: { "data-label": "Mã / trạng thái" } }, [el("strong", { text: `#${tx.id}` }), el("br"), status]),
      el("td", { text: formatAmount(tx.amount, tx.currency), attributes: { "data-label": "Số tiền" } }),
      el("td", { attributes: { "data-label": "Người nhận" } }, [el("strong", { text: tx.recipient_name }), el("br"), el("span", { className: "mono", text: tx.recipient_account })]),
      el("td", { text: new Date(tx.created_at).toLocaleString("vi-VN"), attributes: { "data-label": "Tạo lúc" } }),
      el("td", { attributes: { "data-label": "Thao tác" } }, [rowActions]),
    ]));
  }
  table.append(body);
  panel.append(el("div", {
    className: "table-wrap",
    attributes: { role: "region", tabindex: "0", "aria-label": "Bảng giao dịch, có thể cuộn ngang để xem thêm cột" },
  }, [table]));
  return panel;
}

function renderCreateTransaction() {
  const card = el("section", { className: "card" });
  card.append(
    el("div", { className: "transaction-card-heading" }, [
      el("div", {}, [
        el("p", { className: "eyebrow", text: "Yêu cầu thanh toán" }),
        el("h2", { text: "Thông tin giao dịch" }),
      ]),
      el("span", { className: "secure-badge", text: "Giao dịch bảo mật" }),
    ]),
  );
  const form = el("form", { className: "form-grid transaction-form" });
  const amount = input("amount", "text", { attributes: { inputmode: "numeric", autocomplete: "off" } });
  amount.required = true;
  const formatAmountInput = (value) => String(value || "")
    .replace(/\D/g, "")
    .replace(/\B(?=(\d{3})+(?!\d))/g, ".");
  amount.value = formatAmountInput(state.createTransactionDraft?.amount);
  const amountControl = el("div", { className: "amount-control" }, [
    amount,
    el("span", { className: "amount-suffix", text: "VND", attributes: { "aria-hidden": "true" } }),
  ]);
  const validateAmount = () => {
    const digits = amount.value.replace(/\D/g, "");
    const value = Number(digits);
    amount.setCustomValidity(
      digits && (!Number.isSafeInteger(value) || value < 1 || value > 10000000000)
        ? "Số tiền phải từ 1 đến 10.000.000.000 VND."
        : "",
    );
  };
  amount.addEventListener("input", () => {
    const selectionStart = amount.selectionStart ?? amount.value.length;
    const digitsBeforeCursor = amount.value.slice(0, selectionStart).replace(/\D/g, "").length;
    amount.value = formatAmountInput(amount.value);
    let caretPosition = 0;
    let digitsSeen = 0;
    while (caretPosition < amount.value.length && digitsSeen < digitsBeforeCursor) {
      if (/\d/.test(amount.value[caretPosition])) digitsSeen += 1;
      caretPosition += 1;
    }
    amount.setSelectionRange(caretPosition, caretPosition);
    validateAmount();
  });
  validateAmount();

  const account = select("recipient_account", [], "");
  account.className = "company-select";
  account.required = true;
  account.value = state.createTransactionDraft?.recipient_account || "";
  account.setAttribute("aria-describedby", "company-account-status");
  const name = input("recipient_name", "text", {
    required: true,
    placeholder: "Tự động hiển thị sau khi chọn số tài khoản",
    attributes: { minlength: 2, maxlength: 100 },
  });
  name.value = state.createTransactionDraft?.recipient_name || "";
  name.readOnly = Boolean(state.createTransactionDraft?.recipient_account);
  const companyStatus = el("div", {
    id: "company-account-status",
    className: "field-status",
    attributes: { "aria-live": "polite" },
  });

  const refreshCompanySelect = () => {
    if (!account.isConnected) return;
    const selectedAccount = account.value || state.createTransactionDraft?.recipient_account || "";
    account.replaceChildren(
      el("option", { value: "", text: "Chọn số tài khoản", attributes: { disabled: "", selected: "" } }),
      ...companies.map((company) => el("option", {
        value: company.account,
        text: company.account,
      })),
    );
    if (companies.some((company) => company.account === selectedAccount)) {
      account.value = selectedAccount;
    }
    account.disabled = companiesLoadState !== "loaded";
    companyStatus.replaceChildren();
    if (companiesLoadState === "loading") {
      companyStatus.append(el("span", { className: "help", text: "Đang tải danh sách số tài khoản…" }));
    } else if (companiesLoadState === "error") {
      companyStatus.classList.add("is-error");
      companyStatus.append(
        el("p", { className: "help", text: `Không thể tải danh sách số tài khoản: ${companiesLoadError}` }),
        button("Thử tải lại", "retry-companies", "button small secondary"),
      );
    } else {
      companyStatus.classList.remove("is-error");
    }
  };
  let dispatchingSelectionEvents = false;
  const updateRecipientName = () => {
    if (dispatchingSelectionEvents) return;
    const matched = companies.find((company) => company.account === account.value);
    name.value = matched ? matched.name : "";
    name.readOnly = Boolean(matched);
    dispatchingSelectionEvents = true;
    try {
      for (const control of [account, name]) {
        control.dispatchEvent(new Event("input", { bubbles: true }));
        control.dispatchEvent(new Event("change", { bubbles: true }));
      }
    } finally {
      dispatchingSelectionEvents = false;
    }
  };
  account.addEventListener("change", updateRecipientName);
  void loadCompanies().then(refreshCompanySelect);

  const note = el("textarea", { name: "note", id: "note", attributes: { maxlength: 200 } });
  note.value = state.createTransactionDraft?.note || "";
  form.append(
    el("div", { className: "field" }, [
      el("label", { text: "Số tiền (VND, số nguyên)", attributes: { for: amount.id } }),
      amountControl,
    ]),
    el("div", { className: "field" }, [
      el("label", { text: "Số tài khoản người nhận", attributes: { for: account.id } }),
      account,
      companyStatus,
    ]),
    el("div", { className: "field full recipient-name-field" }, [
      el("label", { text: "Tên người nhận", attributes: { for: name.id } }),
      name,
    ]),
    el("div", { className: "field full" }, [
      el("div", { className: "field-label-row" }, [
        el("label", { text: "Ghi chú", attributes: { for: note.id } }),
        el("span", { className: "note-badge", text: "(không được ký)" }),
      ]),
      note,
    ]),
    el("div", { className: "field full toolbar" }, [
      el("button", { className: "button success", text: "Tạo giao dịch", type: "submit" }),
      button("Quay lại danh sách", "nav:transactions", "button secondary"),
    ]),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const raw = Object.fromEntries(new FormData(form).entries());
    state.createTransactionDraft = raw;
    perform(async () => {
      const created = await api.createTransaction({
        amount: Number(String(raw.amount).replace(/\D/g, "")),
        recipient_account: raw.recipient_account,
        recipient_name: raw.recipient_name,
        ...(raw.note ? { note: raw.note } : {}),
      });
      state.createTransactionDraft = null;
      state.view = "transactions";
      state.txFilter = "";
      await loadTransactions();
      state.notice = `Đã tạo giao dịch #${created.id} · ${STATUS_LABEL[created.status] || created.status}.`;
    });
  });
  card.append(form);
  return card;
}

function renderDetail(tx) {
  const card = el("section", { className: "card", attributes: { "aria-label": `Chi tiết giao dịch ${tx.id}` } });
  card.append(el("div", { className: "toolbar-spread" }, [
    el("h3", { text: `Chi tiết giao dịch #${tx.id}` }),
    button("Đóng", "detail-close", "button small secondary"),
  ]));
  const details = el("div", { className: "preview-grid" });
  details.append(
    valueCell("Trạng thái", STATUS_LABEL[tx.status] || tx.status),
    valueCell("Số tiền", formatAmount(tx.amount, tx.currency)),
    valueCell("Người nhận", tx.recipient_name),
    valueCell("Số tài khoản", tx.recipient_account),
    valueCell("Người tạo", tx.created_by?.username || tx.created_by),
    valueCell("Hạn giao dịch", new Date(tx.expires_at).toLocaleString("vi-VN")),
    valueCell("Ghi chú", tx.note ? `${tx.note} · không được ký` : "Không có"),
  );
  card.append(details);
  if (tx.reject_reason) card.append(el("div", { className: "notice warning", text: `Lý do từ chối: ${tx.reject_reason}` }));
  if (tx.approvals?.length) {
    card.append(el("h3", { text: "Các cấp đã duyệt" }));
    for (const approval of tx.approvals) {
      card.append(el("p", { text: `Cấp ${approval.level} · ${approval.approver.username} · thiết bị #${approval.device_id} · ${new Date(approval.created_at).toLocaleString("vi-VN")}` }));
    }
  }
  return card;
}

function renderRejectForm(txId) {
  const card = el("section", { className: "card" });
  card.append(el("h3", { text: `Từ chối giao dịch #${txId}` }));
  const form = el("form", { className: "form-grid" });
  const reason = el("textarea", { name: "reason", id: "reject-reason", required: true, attributes: { maxlength: 200 } });
  form.append(field("Lý do từ chối", reason, true));
  form.append(el("div", { className: "toolbar" }, [
    el("button", { className: "button danger", text: "Xác nhận từ chối", type: "submit" }),
    button("Hủy thao tác", "reject-close", "button secondary"),
  ]));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const why = new FormData(form).get("reason");
    perform(async () => {
      await api.reject(txId, { reason: String(why) });
      state.rejectTxId = null;
      await loadTransactions();
      state.notice = `Giao dịch #${txId} đã bị từ chối.`;
    }, txId);
  });
  card.append(form);
  return card;
}

async function createPreview(txId, deviceId) {
  const challenge = await api.challenge(txId, { device_id: Number(deviceId) });
  let content;
  try {
    content = JSON.parse(challenge.signing_string);
  } catch {
    throw new Error("Máy chủ trả signing_string không phải JSON hợp lệ; chưa ký giao dịch.");
  }
  if (!content || typeof content !== "object" || Array.isArray(content)) {
    throw new Error("Định dạng signing_string không phải đối tượng giao dịch hợp lệ.");
  }
  state.preview = {
    txId,
    deviceId: Number(deviceId),
    nonce: challenge.nonce,
    expiresAt: challenge.expires_at,
    level: challenge.level,
    signingString: challenge.signing_string,
    content,
    digest: await sha256Hex(challenge.signing_string),
    confirmRead: false,
    tamper: false,
  };
}

function renderPreview(preview) {
  const card = el("section", { className: "card", attributes: { "aria-labelledby": "preview-title" } });
  card.append(
    el("div", { className: "toolbar-spread" }, [
      el("div", {}, [
        el("p", { className: "eyebrow", text: "What You See Is What You Sign" }),
        el("h2", { id: "preview-title", text: `Xem trước trước khi ký · giao dịch #${preview.txId}` }),
      ]),
      button("Hủy xem trước", "preview-close", "button secondary"),
    ]),
  );
  const content = preview.tamper ? JSON.parse(preview.tamperedSigningString) : preview.content;
  const signingText = preview.tamper ? preview.tamperedSigningString : preview.signingString;
  const digest = preview.tamper ? preview.tamperedDigest : preview.digest;
  if (preview.tamper) card.append(el("div", { className: "notice error", text: "Demo TC-06b: nội dung hiển thị đã được chỉnh lệch 1 VND; backend phải từ chối chữ ký." }));
  card.append(el("div", { className: "preview-grid" }, [
    valueCell("Số tiền", formatAmount(content.amount, content.currency)),
    valueCell("Người nhận", content.recipient_name),
    valueCell("Số tài khoản", content.recipient_account),
    valueCell("Mã giao dịch / cấp", `#${content.tx_id} · cấp ${content.level}`),
    valueCell("Người duyệt", content.approver_id),
    valueCell("Thiết bị", `#${content.device_id}`),
    valueCell("Nonce", preview.nonce),
    valueCell("Hành động / phiên bản", `${content.action} · v${content.v}`),
    valueCell("Hạn nonce", new Date(preview.expiresAt).toLocaleString("vi-VN")),
  ]));
  const timer = el("p", { className: "notice warning mono", id: "nonce-countdown" });
  card.append(timer);
  updateNonceCountdown(timer, preview.expiresAt);
  card.append(el("details", {}, [
    el("summary", { text: "Xem signing_string nguyên văn và SHA-256" }),
    el("p", { className: "help", text: `SHA-256 của chuỗi sẽ ký: ${digest}` }),
    el("pre", { className: "mono", text: signingText }),
  ]));
  card.append(el("p", { className: "help", text: "Ghi chú không nằm trong signing_string nên không được ký. Nếu có ghi chú, chỉ tham khảo ngoài nội dung ký." }));
  if (state.detail?.id === preview.txId && state.detail.note) {
    card.append(el("div", { className: "notice warning", text: `Ghi chú (không được ký): ${state.detail.note}` }));
  }
  const confirmation = el("label", { className: "check-row" });
  const check = el("input", { type: "checkbox", name: "confirm-read" });
  check.checked = preview.confirmRead;
  check.addEventListener("change", () => { preview.confirmRead = check.checked; });
  confirmation.append(check, el("span", { text: "Tôi đã đọc và xác nhận nội dung giao dịch sẽ ký." }));
  card.append(confirmation);
  if (DEMO_MODE) {
    const tamperLabel = el("label", { className: "check-row" });
    const tamperCheck = el("input", { type: "checkbox" });
    tamperCheck.checked = preview.tamper;
    tamperCheck.addEventListener("change", () => {
      preview.tamper = tamperCheck.checked;
      if (preview.tamper) {
        const changed = { ...preview.content, amount: Number(preview.content.amount) + 1 };
        preview.tamperedSigningString = JSON.stringify(Object.fromEntries(Object.keys(changed).sort().map((key) => [key, changed[key]])));
        sha256Hex(preview.tamperedSigningString).then((digestValue) => {
          preview.tamperedDigest = digestValue;
          render();
        }).catch((error) => {
          setError(error);
          render();
        });
      } else {
        preview.tamperedSigningString = "";
        preview.tamperedDigest = "";
        render();
      }
    });
    tamperLabel.append(tamperCheck, el("span", { text: "TC-06b · đổi số tiền hiển thị trước khi ký (kết quả mong đợi: SIGNATURE_INVALID)" }));
    card.append(tamperLabel);
  }
  card.append(el("div", { className: "toolbar" }, [
    button("Ký và gửi duyệt", "preview-approve", "button success"),
    button("Xin nonce mới", `preview-refresh:${preview.txId}`, "button secondary"),
  ]));
  return card;
}

function updateNonceCountdown(node, timestamp) {
  const update = () => {
    const left = Math.max(0, Math.ceil((Date.parse(timestamp) - Date.now()) / 1000));
    node.textContent = left
      ? `Nonce còn ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} · hết hạn ${new Date(timestamp).toLocaleTimeString("vi-VN")}`
      : "Nonce đã hết hạn. Hãy xin nonce mới trước khi ký.";
  };
  update();
  const timer = setInterval(() => {
    if (!node.isConnected) {
      clearInterval(timer);
      return;
    }
    update();
  }, 1000);
}

async function approvePreview() {
  const preview = state.preview;
  if (!preview) throw new Error("Không có nội dung xem trước để ký.");
  if (!preview.confirmRead) throw new Error("Bạn cần xác nhận đã đọc nội dung trước khi ký.");
  if (Date.parse(preview.expiresAt) <= Date.now()) throw new Error("Nonce đã hết hạn; hãy xin nonce mới.");
  const privateKey = await getPrivateKey(state.user.username, preview.deviceId);
  if (!privateKey) throw new Error("Không tìm thấy khóa riêng của thiết bị trong IndexedDB. Không thể ký; hãy đăng ký lại thiết bị.");
  const stringToSign = preview.tamper ? preview.tamperedSigningString : preview.signingString;
  const signature = await signUtf8(privateKey, stringToSign);
  const body = { device_id: preview.deviceId, nonce: preview.nonce, signature };
  let result;
  try {
    result = await api.approve(preview.txId, body);
  } catch (error) {
    state.preview = null;
    if (preview.tamper) {
      recordDemo("TC-06b · ký nội dung khác", "SIGNATURE_INVALID", error instanceof ApiError ? `${error.code} (HTTP ${error.status})` : error.message, error.message);
      setError(error, preview.txId, true);
    }
    throw error;
  }
  state.lastApproveRequest = { txId: preview.txId, body };
  if (preview.tamper) recordDemo("TC-06b · ký nội dung khác", "SIGNATURE_INVALID", "Thành công (không mong đợi)", "Backend chấp nhận chữ ký trên nội dung đã chỉnh.");
  state.preview = null;
  state.detail = null;
  await loadTransactions();
  state.notice = `Duyệt thành công giao dịch #${result.id}; trạng thái: ${STATUS_LABEL[result.status] || result.status}.`;
}

function renderDevices() {
  const grid = el("div", { className: "grid" });
  const card = el("section", { className: "card span-6" });
  card.append(
    el("h2", { text: "Đăng ký thiết bị hiện tại" }),
    el("p", { className: "help", text: "Tạo khóa ECDSA P-256 không xuất được; khóa riêng chỉ lưu trong IndexedDB và được gắn với tài khoản + device_id." }),
  );
  const form = el("form", { className: "form-grid" });
  form.append(field("Tên gợi nhớ", input("label", "text", { attributes: { maxlength: 50, placeholder: "Ví dụ: Laptop quản lý" } }), true));
  form.append(el("div", { className: "field full" }, [el("button", { className: "button success", text: "Tạo khóa và đăng ký", type: "submit" })]));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const label = String(new FormData(form).get("label"));
    perform(async () => {
      const pair = await createDeviceKeyPair();
      if (pair.privateKey.extractable) throw new Error("WebCrypto tạo khóa riêng extractable; đã dừng đăng ký.");
      const publicKey = await exportPublicKey(pair.publicKey);
      const challenge = await api.deviceChallenge();
      const signature = await signUtf8(pair.privateKey, challenge.challenge);
      const registered = await api.registerDevice({ label, public_key: publicKey, challenge: challenge.challenge, signature });
      try {
        await savePrivateKey(state.user.username, registered.id, pair.privateKey);
      } catch (error) {
        throw new Error(`Thiết bị #${registered.id} đã đăng ký trên máy chủ nhưng không lưu được khóa vào IndexedDB (${error.message}). Hãy thu hồi thiết bị này và đăng ký lại.`);
      }
      await loadDevices();
      state.notice = `Đã đăng ký thiết bị #${registered.id}. Khóa riêng không thể xuất và không được lưu trong Web Storage.`;
    });
  });
  card.append(form);
  grid.append(el("div", { className: "span-6" }, [card]));
  const list = el("section", { className: "card span-6" });
  list.append(el("h2", { text: "Thiết bị của tôi" }));
  if (!state.devices.length) list.append(empty("Chưa có thiết bị đăng ký."));
  else {
    for (const device of state.devices) {
      const line = el("div", { className: "toolbar-spread" });
      const info = el("div");
      info.append(el("strong", { text: `${device.label} · #${device.id}` }), el("p", { className: "help", text: `${device.status === "active" ? "Đang hoạt động" : "Đã thu hồi"} · ${new Date(device.created_at).toLocaleString("vi-VN")}` }));
      line.append(info);
      if (device.status === "active") line.append(button("Thu hồi", `device-revoke:${device.id}`, "button danger small"));
      list.append(line, el("hr"));
    }
  }
  list.append(el("p", { className: "help", text: "Xóa dữ liệu trình duyệt sẽ làm mất khóa riêng; thiết bị cần được đăng ký lại." }));
  grid.append(el("div", { className: "span-6" }, [list]));
  return grid;
}

function formatAuditDataValue(key, value) {
  const knownValues = AUDIT_DATA_VALUE_LABELS[key];
  if (knownValues && Object.hasOwn(knownValues, value)) return knownValues[value];
  if (key === "role" && typeof value === "string") return roleName(value);
  if (key === "seeded" && typeof value === "boolean") return value ? "Có" : "Không";
  if (key === "amount" && Number.isFinite(Number(value))) return formatAmount(Number(value), "VND");
  if (key === "locked_until" && typeof value === "string" && Number.isFinite(Date.parse(value))) {
    return new Date(value).toLocaleString("vi-VN");
  }
  if (key === "error_code" && Object.hasOwn(ERROR_COPY, value)) return ERROR_COPY[value][0];
  if (value === null) return "Không có";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function renderAuditData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data) || Object.keys(data).length === 0) {
    return el("p", { className: "help audit-data-empty", text: "Không có thông tin bổ sung" });
  }

  const list = el("dl", { className: "audit-data-list" });
  for (const [key, value] of Object.entries(data)) {
    const label = Object.hasOwn(AUDIT_DATA_LABELS, key) ? AUDIT_DATA_LABELS[key] : key;
    list.append(el("div", {}, [
      el("dt", { text: label }),
      el("dd", { text: formatAuditDataValue(key, value) }),
    ]));
  }
  return list;
}

function renderAuditEvent(event) {
  const details = Object.hasOwn(AUDIT_EVENT_LABELS, event) ? AUDIT_EVENT_LABELS[event] : null;
  const badge = el("span", {
    className: `audit-event-badge audit-severity-${details?.level || "info"}`,
    text: details?.label || "Sự kiện hệ thống",
  });
  const content = el("div", { className: "audit-event" }, [
    badge,
    el("p", { className: "audit-event-description", text: details?.description || "Sự kiện chưa có mô tả tiếng Việt." }),
  ]);
  if (!details) content.append(el("code", { className: "audit-event-unknown", text: String(event) }));
  return content;
}

function renderAuditHashLine(label, value) {
  const copyStatus = el("span", {
    className: "audit-copy-status",
    attributes: { "aria-live": "polite" },
  });
  const copyButton = el("button", {
    className: "button small secondary audit-copy-button",
    text: "Sao chép",
    type: "button",
    attributes: { "aria-label": `Sao chép mã ${label}` },
  });
  copyButton.addEventListener("click", async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Trình duyệt không hỗ trợ sao chép.");
      await navigator.clipboard.writeText(String(value));
      copyStatus.textContent = `Đã sao chép mã ${label}.`;
    } catch (error) {
      const reason = error instanceof Error ? error.message : "Lỗi không xác định.";
      copyStatus.textContent = `Không thể sao chép mã ${label}: ${reason} Hãy chọn và sao chép thủ công.`;
    }
  });
  return el("div", { className: "audit-hash-line" }, [
    el("strong", { text: label }),
    el("code", { className: "hash audit-hash-value", text: String(value) }),
    copyButton,
    copyStatus,
  ]);
}

function renderAuditTechnicalDetails(entry) {
  return el("details", { className: "audit-technical" }, [
    el("summary", { text: "Chi tiết kỹ thuật" }),
    el("div", { className: "audit-technical-content" }, [
      el("p", {}, [
        el("strong", { text: "Mã sự kiện gốc: " }),
        el("code", { text: String(entry.event) }),
      ]),
      el("p", { text: "Dữ liệu gốc:" }),
      el("pre", { className: "mono audit-raw-data", text: JSON.stringify(entry.data ?? {}, null, 2) }),
      renderAuditHashLine("prev_hash", entry.prev_hash),
      renderAuditHashLine("hash", entry.hash),
    ]),
  ]);
}

function auditActorLabel(actorId) {
  if (actorId === null || actorId === undefined) return "Không xác định";
  const numericId = Number(actorId);
  if (numericId === 0) return "Hệ thống";

  const createdUser = state.auditEntries.find((entry) =>
    entry.event === "USER_CREATED"
    && Number(entry.data?.user_id) === numericId
    && typeof entry.data?.role === "string"
  );
  const role = Number(state.user?.id) === numericId
    ? state.user.role
    : createdUser?.data.role || SEEDED_ACTOR_ROLES[numericId];
  return role
    ? `${roleName(role)} · #${numericId}`
    : `Chưa xác định vai trò · #${actorId}`;
}

function renderAudit() {
  const card = el("section", { className: "card" });
  const eventControl = select("audit-event", [
    { value: "", label: "Tất cả sự kiện" },
    ...EVENT_OPTIONS.map((event) => ({
      value: event,
      label: Object.hasOwn(AUDIT_EVENT_LABELS, event) ? AUDIT_EVENT_LABELS[event].label : event,
    })),
  ], state.auditEvent);
  eventControl.className = "filter-control";
  eventControl.addEventListener("change", () => perform(async () => {
    state.auditEvent = eventControl.value;
    state.auditOffset = 0;
    await loadAudit();
  }));
  card.append(el("div", { className: "toolbar-spread" }, [
    el("div", {}, [el("h2", { text: "Nhật ký sự kiện" }), el("p", { className: "help", text: `${state.auditTotal} dòng · mới nhất trước` })]),
    el("div", { className: "toolbar" }, [
      eventControl,
      button("Kiểm tra toàn vẹn", "audit-verify", "button success"),
      button("Tải lại", "audit-refresh", "button secondary"),
    ]),
  ]));
  if (state.auditVerification) {
    const verification = state.auditVerification;
    const notice = el("div", { className: `notice ${verification.valid ? "success" : "error"}` });
    notice.append(el("strong", { text: verification.valid ? "Hash chain hợp lệ" : `Hash chain bị gián đoạn · ${verification.reason || "không rõ nguyên nhân"}` }));
    notice.append(el("p", { text: `Đã kiểm tra ${verification.checked} dòng${verification.broken_at ? ` · dòng lỗi #${verification.broken_at}` : ""}.` }));
    if (!verification.valid) notice.append(el("p", { text: verification.reason === "HASH_MISMATCH" ? "Nội dung/hash của dòng này bị sửa." : "Liên kết prev_hash bị đứt; có thể dòng đã bị xóa hoặc chèn." }));
    card.append(notice);
  }
  if (!state.auditEntries.length) card.append(empty("Chưa có sự kiện audit phù hợp."));
  else {
    const table = el("table");
    table.className = "audit-table";
    table.append(el("thead", {}, [el("tr", {}, [
      el("th", { text: "ID / Thời điểm" }), el("th", { text: "Sự kiện" }), el("th", { text: "Người thực hiện" }),
      el("th", { text: "Thông tin chi tiết" }), el("th", { text: "Mã kiểm chứng" }),
    ])]));
    const rows = el("tbody");
    const brokenAt = state.auditVerification?.broken_at;
    for (const entry of state.auditEntries) {
      const hashes = el("details", { className: "audit-hashes" }, [
        el("summary", { text: "Xem mã kiểm chứng" }),
        renderAuditHashLine("prev_hash", entry.prev_hash),
        renderAuditHashLine("hash", entry.hash),
      ]);
      rows.append(el("tr", { className: entry.id === brokenAt ? "broken-row" : "" }, [
        el("td", { attributes: { "data-label": "ID / Thời điểm" } }, [el("strong", { text: `#${entry.id}` }), el("br"), el("span", { text: new Date(entry.created_at).toLocaleString("vi-VN") })]),
        el("td", { attributes: { "data-label": "Sự kiện" } }, [renderAuditEvent(entry.event)]),
        el("td", { text: auditActorLabel(entry.actor_id), attributes: { "data-label": "Người thực hiện" } }),
        el("td", { attributes: { "data-label": "Thông tin chi tiết" } }, [renderAuditData(entry.data)]),
        el("td", { attributes: { "data-label": "Mã kiểm chứng" } }, [hashes, renderAuditTechnicalDetails(entry)]),
      ]));
    }
    table.append(rows);
    card.append(el("div", {
      className: "table-wrap",
      attributes: { role: "region", tabindex: "0", "aria-label": "Nhật ký sự kiện, có thể cuộn ngang để xem thêm cột" },
    }, [table]));
  }
  card.append(el("div", { className: "pagination" }, [
    button("← Mới hơn", "audit-newer", "button secondary small"),
    el("span", { text: `${state.auditOffset + 1}–${Math.min(state.auditOffset + 50, state.auditTotal)} / ${state.auditTotal}` }),
    button("Cũ hơn →", "audit-older", "button secondary small"),
  ]));
  return card;
}

async function loadAudit() {
  const params = new URLSearchParams({ limit: "50", offset: String(state.auditOffset), order: "desc" });
  if (state.auditEvent) params.set("event", state.auditEvent);
  const result = await api.audit(`?${params.toString()}`);
  state.auditEntries = result.entries;
  state.auditTotal = result.total;
}

function renderDemoPanel() {
  const panel = el("div", { className: "grid" });
  const info = el("section", { className: "card demo-panel span-12" });
  info.append(
    el("h2", { text: "Demo mode đang bật" }),
    el("p", { className: "help", text: "Chỉ bật trong môi trường demo bằng cách đổi DEMO_MODE trong public/js/config.js. Nút dưới đây gửi yêu cầu thật tới backend, không tự sửa dữ liệu cơ sở dữ liệu." }),
  );
  panel.append(info);
  if (state.preview) panel.append(el("div", { className: "span-12" }, [renderPreview(state.preview)]));

  const txOptions = [{ value: "", label: "Chọn giao dịch đang chờ" }];
  for (const tx of state.transactions.filter((item) => ["PENDING_L1", "PENDING_L2"].includes(item.status))) {
    txOptions.push({ value: String(tx.id), label: `#${tx.id} · ${tx.status} · ${formatAmount(tx.amount)}` });
  }
  const deviceOptions = [{ value: "", label: "Chọn thiết bị đang hoạt động" }];
  for (const device of state.devices.filter((item) => item.status === "active")) {
    deviceOptions.push({ value: String(device.id), label: `#${device.id} · ${device.label}` });
  }
  const form = el("section", { className: "card demo-panel span-6" });
  form.append(el("h2", { text: "Kịch bản chữ ký / nonce" }));
  const txSelect = select("demo-tx", txOptions);
  txSelect.value = state.demoTxId;
  txSelect.addEventListener("change", () => { state.demoTxId = txSelect.value; });
  const deviceSelect = select("demo-device", deviceOptions);
  deviceSelect.value = state.demoDeviceId;
  deviceSelect.addEventListener("change", () => { state.demoDeviceId = deviceSelect.value; });
  const formWrap = el("div", { className: "form-grid" }, [
    field("Giao dịch đang chờ", txSelect, true),
    field("Thiết bị người duyệt", deviceSelect, true),
  ]);
  form.append(formWrap);
  form.append(
    demoActionRow("TC-06b · ký nội dung khác", "SIGNATURE_INVALID", button("Chạy TC-06b", "demo-tamper", "button danger small")),
    demoActionRow("TC-07 · replay request đã duyệt thành công", "NONCE_USED", button("Chạy TC-07", "demo-replay", "button danger small")),
    demoActionRow("TC-09/13 · chữ ký rỗng", "SIGNATURE_INVALID", button("Chạy TC-09/13", "demo-empty-signature", "button danger small")),
    demoActionRow("TC-10 · device_id không tồn tại", "DEVICE_NOT_REGISTERED", button("Chạy TC-10", "demo-unknown-device", "button danger small")),
  );
  panel.append(el("div", { className: "span-6" }, [form]));

  const other = el("section", { className: "card demo-panel span-6" });
  other.append(
    el("h2", { text: "Xác thực / audit" }),
    demoActionRow("TC-12 · mã TOTP sai", "MFA_INVALID", button("Đăng xuất để thử TOTP sai", "demo-totp", "button danger small")),
    el("div", { className: "field" }, [
      el("label", { text: "Tài khoản thử khóa", attributes: { for: "demo-target-user" } }),
      input("demo-target-user", "text", { value: state.demoTargetUser, attributes: { autocomplete: "off" } }),
      el("p", { className: "help", text: "Năm lần sai sẽ khóa tài khoản; không chọn admin. Sau đó cần chờ rate limit hoặc reset DB demo." }),
    ]),
    demoActionRow("TC-17 · 5 lần sai + yêu cầu thứ 6", "AUTH_INVALID_CREDENTIALS / RATE_LIMITED; ACCOUNT_LOCKED sau rate limit", button("Chạy TC-17", "demo-bruteforce", "button danger small")),
    demoActionRow("TC-18 · sửa audit bằng script TV4", "valid: false", button("Kiểm tra toàn vẹn", "audit-verify", "button success small")),
    el("p", { className: "help", text: "TC-06a cần TV4 sửa DB sau challenge; TC-08 cần chờ nonce quá 5 phút. Hai tình huống này không được giả lập trong giao diện." }),
  );
  panel.append(el("div", { className: "span-6" }, [other]));

  const results = el("section", { className: "card span-12" });
  results.append(el("h2", { text: "Kết quả thực tế từ backend" }));
  if (!state.demoResults.length) results.append(empty("Chưa chạy kịch bản nào."));
  for (const result of state.demoResults) {
    const line = el("div", { className: "demo-result" });
    line.append(el("strong", { text: `${result.label} · mong đợi: ${result.expected}` }), el("br"));
    line.append(el("span", { text: `Thực tế: ${result.actual}` }));
    if (result.message) line.append(el("p", { text: result.message }));
    results.append(line);
  }
  panel.append(results);
  return panel;
}

function demoActionRow(label, expected, actionButton) {
  const row = el("div", { className: "toolbar-spread" });
  row.append(el("div", {}, [el("strong", { text: label }), el("p", { className: "help", text: `Mong đợi: ${expected}` })]), actionButton);
  return el("div", { className: "notice" }, [row]);
}

function recordDemo(label, expected, actual, message = "") {
  state.demoResults.unshift({ label, expected, actual, message });
  state.demoResults = state.demoResults.slice(0, 12);
}

async function runDemoCall(label, expected, action, txId = null, audit = false) {
  try {
    const result = await action();
    const actual = result?.error?.code || result?.status || (result?.valid === false ? "valid: false" : "Thành công");
    recordDemo(label, expected, actual, result?.message || "");
    if (result?.entries) {
      state.auditEntries = result.entries;
      state.auditTotal = result.total;
    }
    return result;
  } catch (error) {
    const actual = error instanceof ApiError ? `${error.code} (HTTP ${error.status})` : error.message;
    recordDemo(label, expected, actual, error.message || "");
    if (error instanceof ApiError) setError(error, txId, audit);
    throw error;
  }
}

async function demoTamper() {
  const { txId, deviceId } = demoFormValues();
  await createPreview(txId, deviceId);
  state.preview.tamper = true;
  const changed = { ...state.preview.content, amount: Number(state.preview.content.amount) + 1 };
  state.preview.tamperedSigningString = JSON.stringify(Object.fromEntries(Object.keys(changed).sort().map((name) => [name, changed[name]])));
  state.preview.tamperedDigest = await sha256Hex(state.preview.tamperedSigningString);
}

function demoFormValues() {
  const txId = Number(state.demoTxId);
  const deviceId = Number(state.demoDeviceId);
  if (!Number.isInteger(txId) || txId <= 0) throw new Error("Chọn một giao dịch đang chờ.");
  if (!Number.isInteger(deviceId) || deviceId <= 0) throw new Error("Chọn một thiết bị đang hoạt động.");
  return { txId, deviceId };
}

async function demoReplay() {
  if (!state.lastApproveRequest) throw new Error("Chưa có request duyệt thành công trong phiên trình duyệt này để replay.");
  const { txId, body } = state.lastApproveRequest;
  try {
    await runDemoCall("TC-07 · replay", "NONCE_USED", () => api.approve(txId, body), txId, true);
  } catch {
    return;
  }
}

async function demoEmptySignature() {
  const { txId, deviceId } = demoFormValues();
  const challenge = await api.challenge(txId, { device_id: deviceId });
  try {
    await runDemoCall("TC-09/13 · chữ ký rỗng", "SIGNATURE_INVALID", () => api.approve(txId, {
      device_id: deviceId, nonce: challenge.nonce, signature: "",
    }), txId, true);
  } catch {
    return;
  }
}

async function demoUnknownDevice() {
  const txId = Number(state.demoTxId);
  if (!Number.isInteger(txId) || txId <= 0) throw new Error("Chọn một giao dịch đang chờ.");
  try {
    await runDemoCall("TC-10 · thiết bị lạ", "DEVICE_NOT_REGISTERED", () => api.challenge(txId, { device_id: 2147483647 }), txId);
  } catch {
    return;
  }
}

async function verifyAudit() {
  const verification = await api.verifyAudit();
  state.auditVerification = verification;
  if (state.view === "audit" && verification.broken_at) {
    const params = new URLSearchParams({ limit: "50", offset: "0", order: "desc" });
    const result = await api.audit(`?${params.toString()}`);
    state.auditEntries = result.entries;
    state.auditTotal = result.total;
    state.auditOffset = 0;
  }
  if (state.view === "demo") recordDemo("TC-18 · kiểm tra hash chain", "valid: false", verification.valid ? "valid: true" : `valid: false · ${verification.reason} · dòng #${verification.broken_at}`);
  state.notice = verification.valid ? `Hash chain hợp lệ · đã kiểm tra ${verification.checked} dòng.` : `Hash chain không hợp lệ · ${verification.reason} tại dòng #${verification.broken_at}.`;
}

async function handleClick(event) {
  const target = event.target.closest("[data-action]");
  if (!target || state.busy) return;
  const action = target.dataset.action;
  if (action.startsWith("nav:")) {
    if (
      state.view === "create"
      && target.dataset.confirmLeave !== "true"
      && createTransactionHasChanges()
    ) {
      state.createTransactionDraft = Object.fromEntries(
        new FormData(root.querySelector(".transaction-form")).entries(),
      );
      state.createLeaveDestination = action;
      state.showCreateLeaveConfirmation = true;
      render();
      root.querySelector('[data-action="stay-create"]')?.focus();
      return;
    }
    state.showCreateLeaveConfirmation = false;
    state.createLeaveDestination = "";
    if (state.view === "create") {
      state.createTransactionDraft = null;
    }
    state.view = action.slice(4);
    state.error = null;
    state.notice = null;
    state.detail = null;
    state.preview = null;
    state.rejectTxId = null;
    await perform(async () => {
      if (state.view === "transactions") await loadTransactions();
      if (state.view === "devices") await loadDevices();
      if (state.view === "audit") await loadAudit();
      if (state.view === "demo") {
        await loadTransactions();
        await loadDevices();
      }
    });
    return;
  }
  if (action === "logout") {
    await perform(async () => {
      await api.logout();
      state.user = null;
      state.authStep = "login";
      state.pendingUsername = "";
      state.pendingEmailHint = "";
      state.preview = null;
      state.lastApproveRequest = null;
    });
    return;
  }
  if (action === "retry-companies") {
    const request = loadCompanies(true);
    render();
    await request;
    render();
    return;
  }
  if (action === "resend-mfa") {
    await perform(async () => {
      const result = await api.resendMfa();
      state.pendingEmailHint = result.email_hint || state.pendingEmailHint;
      state.notice = `Mã OTP mới đã được gửi tới ${state.pendingEmailHint || "email của bạn"}.`;
    });
    return;
  }
  if (action === "new-transaction") {
    state.showCreateLeaveConfirmation = false;
    state.createLeaveDestination = "";
    state.createTransactionDraft = null;
    state.view = "create";
    render();
    return;
  }
  if (action === "stay-create") {
    state.showCreateLeaveConfirmation = false;
    state.createLeaveDestination = "";
    render();
    root.querySelector(".back-button")?.focus();
    return;
  }
  if (action === "detail-close") { state.detail = null; render(); return; }
  if (action === "preview-close" || action === "reject-close") {
    state.preview = null;
    state.rejectTxId = null;
    render();
    return;
  }
  if (action.startsWith("tx-detail:")) {
    const txId = Number(action.split(":")[1]);
    await perform(async () => { state.detail = await api.transaction(txId); }, txId);
    return;
  }
  if (action.startsWith("tx-cancel:")) {
    const txId = Number(action.split(":")[1]);
    if (!window.confirm(`Hủy giao dịch #${txId}?`)) return;
    await perform(async () => {
      await api.cancelTransaction(txId);
      await loadTransactions();
      state.notice = `Đã hủy giao dịch #${txId}.`;
    }, txId);
    return;
  }
  if (action.startsWith("tx-reject:")) {
    state.rejectTxId = Number(action.split(":")[1]);
    render();
    return;
  }
  if (action.startsWith("tx-approve:")) {
    const txId = Number(action.split(":")[1]);
    await perform(async () => {
      await loadDevices();
      const device = state.devices.find((item) => item.status === "active");
      if (!device) throw new Error("Chưa có thiết bị đang hoạt động. Đăng ký thiết bị trước khi duyệt.");
      await createPreview(txId, device.id);
      state.detail = await api.transaction(txId);
    }, txId);
    return;
  }
  if (action.startsWith("preview-refresh:")) {
    const txId = Number(action.split(":")[1]);
    await perform(async () => {
      await loadDevices();
      const activeId = state.preview?.deviceId || state.devices.find((item) => item.status === "active")?.id;
      if (!activeId) throw new Error("Chưa có thiết bị đang hoạt động.");
      await createPreview(txId, activeId);
    }, txId);
    return;
  }
  if (action === "preview-approve") {
    const txId = state.preview?.txId;
    await perform(approvePreview, txId, true);
    return;
  }
  if (action.startsWith("device-revoke:")) {
    const id = Number(action.split(":")[1]);
    if (!window.confirm(`Thu hồi thiết bị #${id}? Khóa này sẽ không thể dùng để duyệt.`)) return;
    await perform(async () => {
      await api.revokeDevice(id);
      await deletePrivateKey(state.user.username, id);
      await loadDevices();
      state.notice = `Đã thu hồi thiết bị #${id} và xóa bản khóa IndexedDB tương ứng.`;
    });
    return;
  }
  if (action === "audit-verify") {
    await perform(verifyAudit);
    return;
  }
  if (action === "audit-refresh") {
    await perform(async () => { await loadAudit(); state.notice = "Audit log đã được tải lại."; });
    return;
  }
  if (action === "audit-older") {
    if (state.auditOffset + 50 < state.auditTotal) {
      state.auditOffset += 50;
      await perform(loadAudit);
    }
    return;
  }
  if (action === "audit-newer") {
    if (state.auditOffset > 0) {
      state.auditOffset = Math.max(0, state.auditOffset - 50);
      await perform(loadAudit);
    }
    return;
  }
  if (action === "demo-tamper") {
    await perform(demoTamper);
    return;
  }
  if (action === "demo-replay") {
    await perform(demoReplay);
    return;
  }
  if (action === "demo-empty-signature") {
    await perform(demoEmptySignature);
    return;
  }
  if (action === "demo-unknown-device") {
    await perform(demoUnknownDevice);
    return;
  }
  if (action === "demo-totp") {
    await perform(async () => {
      await api.logout();
      state.user = null;
      state.authStep = "login";
      state.notice = "Đăng nhập lại bằng đúng mật khẩu, sau đó nhập TOTP sai để quan sát MFA_INVALID.";
    });
    return;
  }
  if (action === "demo-bruteforce") {
    const target = document.querySelector("#demo-target-user")?.value.trim() || state.demoTargetUser;
    state.demoTargetUser = target;
    if (target === "admin01" || target.toLowerCase() === "admin") {
      state.error = null;
      state.notice = "TC-17 không được chạy với admin: admin không bị khóa theo số lần sai.";
      render();
      return;
    }
    if (!window.confirm(`Gửi 6 lần đăng nhập sai cho ${target}? Tài khoản có thể bị khóa 15 phút.`)) return;
    await perform(async () => {
      const results = [];
      for (let attempt = 1; attempt <= 6; attempt += 1) {
        try {
          await api.login({ username: target, password: `demo-invalid-${crypto.randomUUID()}` });
          results.push(`lần ${attempt}: không mong đợi thành công`);
        } catch (error) {
          const code = error instanceof ApiError ? `${error.code} (HTTP ${error.status})` : error.message;
          results.push(`lần ${attempt}: ${code}`);
        }
      }
      recordDemo("TC-17 · dò mật khẩu", "AUTH_INVALID_CREDENTIALS rồi RATE_LIMITED; tiếp theo ACCOUNT_LOCKED", results.join(" | "));
      state.notice = "TC-17 đã gửi 6 lần thử sai. Lần thứ 6 thường bị RATE_LIMITED; chờ cửa sổ giới hạn kết thúc rồi thử đăng nhập để quan sát ACCOUNT_LOCKED.";
    });
  }
}

root.addEventListener("click", (event) => { void handleClick(event); });
sessionArea.addEventListener("click", (event) => { void handleClick(event); });

async function initialize() {
  try {
    state.user = await api.me();
    state.view = state.user.role === "admin" ? "audit" : "transactions";
    if (state.view === "audit") await loadAudit();
    else await loadTransactions();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      state.user = null;
    } else {
      setError(error);
    }
  }
  render();
}

void initialize();
