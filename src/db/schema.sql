-- RZero Mail D1 SQLite Schema (Serverless Disposable Email & OTP Extraction)

CREATE TABLE IF NOT EXISTS inboxes (
  address TEXT PRIMARY KEY,
  is_locked INTEGER NOT NULL DEFAULT 0,
  lock_pin_hash TEXT DEFAULT NULL,
  owner_session_id TEXT DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  locked_at TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_inboxes_locked ON inboxes(is_locked);
CREATE INDEX IF NOT EXISTS idx_inboxes_owner ON inboxes(owner_session_id);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  inbox_address TEXT NOT NULL,
  from_address TEXT NOT NULL,
  subject TEXT DEFAULT '(no subject)',
  body TEXT DEFAULT '',
  body_html TEXT DEFAULT '',
  otp_code TEXT DEFAULT NULL,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (inbox_address) REFERENCES inboxes(address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(inbox_address);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(inbox_address, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_otp ON messages(otp_code);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_inboxes (
  session_id TEXT NOT NULL,
  inbox_address TEXT NOT NULL,
  PRIMARY KEY (session_id, inbox_address),
  FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (inbox_address) REFERENCES inboxes(address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_inboxes_session ON session_inboxes(session_id);

-- Dynamic Managed Domains
CREATE TABLE IF NOT EXISTS domains (
  domain TEXT PRIMARY KEY,
  is_active INTEGER NOT NULL DEFAULT 1,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Traffic & Security Logs (Live Monitor)
CREATE TABLE IF NOT EXISTS traffic_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  user_agent TEXT DEFAULT '',
  duration_ms INTEGER DEFAULT 0,
  timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_ip ON traffic_logs(ip);

-- PIN Attempt Rate Limiting & Lockout Protection
CREATE TABLE IF NOT EXISTS pin_attempts (
  address TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_pin_attempts_address ON pin_attempts(address);

-- Ads & Sponsorship Slots (Manual or Adsterra/Script)
CREATE TABLE IF NOT EXISTS ads (
  slot_name TEXT PRIMARY KEY,
  is_active INTEGER NOT NULL DEFAULT 1,
  ad_type TEXT NOT NULL DEFAULT 'manual', -- 'manual' | 'script'
  title TEXT DEFAULT '',
  description TEXT DEFAULT '',
  banner_url TEXT DEFAULT '',
  target_url TEXT DEFAULT '',
  script_code TEXT DEFAULT '',
  cta_text TEXT DEFAULT 'Lihat Promo',
  views INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed default slots if not exist
INSERT OR IGNORE INTO ads (slot_name, is_active, ad_type, title, description, banner_url, target_url, cta_text)
VALUES 
  ('slot_main', 1, 'manual', 'Sewa Slot Iklan Ini (Open Sponsor)', 'Pasang banner produk, bot, atau jasa kamu di sini.', '', 'https://instagram.com/rskl411_', 'Pasang Iklan'),
  ('slot_bottom', 0, 'manual', 'Partner Terpercaya', 'Slot iklan sekunder di bawah kotak pesan masuk.', '', 'https://instagram.com/rskl411_', 'Hubungi');
