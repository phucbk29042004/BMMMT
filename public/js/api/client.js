export class ApiError extends Error {
  constructor(status, payload) {
    const error = payload?.error ?? {};
    super(error.message || `Yêu cầu thất bại (HTTP ${status}).`);
    this.name = "ApiError";
    this.status = status;
    this.code = error.code || "UNKNOWN_ERROR";
    this.details = error.details || {};
  }
}

export async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  let response;
  try {
    response = await fetch(`/api${path}`, {
      ...options,
      headers,
      credentials: "same-origin",
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch (error) {
    throw new Error(`Không kết nối được máy chủ TrustSign: ${error.message}`);
  }

  if (response.status === 204) return null;
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`Máy chủ trả dữ liệu không phải JSON (HTTP ${response.status}).`);
    }
  }
  if (!response.ok) throw new ApiError(response.status, payload);
  return payload;
}

export const api = {
  login: (body) => request("/auth/login", { method: "POST", body }),
  mfa: (body) => request("/auth/mfa", { method: "POST", body }),
  resendMfa: () => request("/auth/mfa/resend", { method: "POST" }),
  me: () => request("/auth/me"),
  logout: () => request("/auth/logout", { method: "POST" }),
  devices: () => request("/devices"),
  deviceChallenge: () => request("/devices/challenge", { method: "POST" }),
  registerDevice: (body) => request("/devices/register", { method: "POST", body }),
  revokeDevice: (id) => request(`/devices/${encodeURIComponent(id)}/revoke`, { method: "POST" }),
  transactions: (query = "") => request(`/transactions${query}`),
  transaction: (id) => request(`/transactions/${encodeURIComponent(id)}`),
  createTransaction: (body) => request("/transactions", { method: "POST", body }),
  cancelTransaction: (id) => request(`/transactions/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  challenge: (id, body) => request(`/transactions/${encodeURIComponent(id)}/challenge`, { method: "POST", body }),
  approve: (id, body) => request(`/transactions/${encodeURIComponent(id)}/approve`, { method: "POST", body }),
  reject: (id, body) => request(`/transactions/${encodeURIComponent(id)}/reject`, { method: "POST", body }),
  audit: (query) => request(`/audit${query}`),
  verifyAudit: () => request("/audit/verify"),
};
