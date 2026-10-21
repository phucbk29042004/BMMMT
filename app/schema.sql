-- TrustSign - schema SQLite (TV1 sở hữu file này; muốn đổi thì báo cả nhóm)

CREATE TABLE IF NOT EXISTS users (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  username        TEXT    NOT NULL UNIQUE,
  password_hash   TEXT    NOT NULL,
  role            TEXT    NOT NULL CHECK (role IN ('accountant','manager','director','admin')),
  email           TEXT,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    TEXT,                              -- ISO 8601 UTC, NULL = không khóa
  created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (                -- phiên lưu phía server, đăng xuất là hủy thật
  id         TEXT PRIMARY KEY,                       -- SHA-256 của token trong cookie
  data_json  TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  public_key TEXT    NOT NULL UNIQUE,                -- SPKI base64
  label      TEXT    NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_at TEXT    NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS transactions (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  creator_id        INTEGER NOT NULL REFERENCES users(id),
  amount            INTEGER NOT NULL CHECK (amount > 0),   -- đồng (VND)
  currency          TEXT    NOT NULL DEFAULT 'VND',
  recipient_account TEXT    NOT NULL,
  recipient_name    TEXT    NOT NULL,
  note              TEXT,
  status            TEXT    NOT NULL CHECK (status IN
                      ('PENDING_L1','PENDING_L2','APPROVED','REJECTED','CANCELLED','EXPIRED')),
  required_levels   INTEGER NOT NULL CHECK (required_levels IN (1,2)),
  reject_reason     TEXT,
  rejected_by       INTEGER REFERENCES users(id),
  created_at        TEXT    NOT NULL,
  expires_at        TEXT    NOT NULL
);

-- Dùng chung cho challenge đăng ký thiết bị (TV1) và nonce duyệt giao dịch (TV2)
CREATE TABLE IF NOT EXISTS nonces (
  nonce          TEXT PRIMARY KEY,                   -- PRIMARY KEY => chống trùng/replay
  purpose        TEXT NOT NULL CHECK (purpose IN ('DEVICE_REG','TX_APPROVE')),
  user_id        INTEGER NOT NULL REFERENCES users(id),
  tx_id          INTEGER REFERENCES transactions(id),
  level          INTEGER,
  device_id      INTEGER REFERENCES devices(id),
  signing_string TEXT,                               -- chuỗi server đã phát hành cho TX_APPROVE
  created_at     TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  used_at        TEXT                                -- NULL = chưa dùng
);

CREATE TABLE IF NOT EXISTS approvals (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id INTEGER NOT NULL REFERENCES transactions(id),
  level          INTEGER NOT NULL CHECK (level IN (1,2)),
  approver_id    INTEGER NOT NULL REFERENCES users(id),
  device_id      INTEGER NOT NULL REFERENCES devices(id),
  nonce          TEXT    NOT NULL REFERENCES nonces(nonce),
  signature      TEXT    NOT NULL,
  signing_string TEXT    NOT NULL,
  created_at     TEXT    NOT NULL,
  UNIQUE (transaction_id, level)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event      TEXT    NOT NULL,
  actor_id   INTEGER NOT NULL DEFAULT 0,
  data_json  TEXT    NOT NULL,                       -- canonical JSON
  prev_hash  TEXT    NOT NULL,
  hash       TEXT    NOT NULL,
  created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_tx_status    ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_nonces_tx    ON nonces(tx_id);
