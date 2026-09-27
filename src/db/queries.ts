import type { D1Database } from '@cloudflare/workers-types';
import { hashPin } from '../utils/crypto';

export interface Inbox {
  address: string;
  is_locked: number; // 0 = false, 1 = true
  lock_pin_hash: string | null;
  owner_session_id: string | null;
  created_at: string;
  locked_at: string | null;
}

export interface Message {
  id: string;
  inbox_address: string;
  from_address: string;
  subject: string;
  body: string;
  body_html: string;
  otp_code: string | null;
  received_at: string;
}

export interface Session {
  id: string;
  created_at: string;
}

export interface DomainItem {
  domain: string;
  is_active: number;
  is_default: number;
  created_at: string;
}

export interface TrafficLog {
  id: number;
  ip: string;
  method: string;
  path: string;
  status: number;
  user_agent: string;
  duration_ms: number;
  timestamp: string;
}

export interface TrafficStats {
  totalEmailsAllTime: number;
  totalEmailsToday: number;
  totalInboxesAllTime: number;
  totalInboxesLocked: number;
  activeDomainsCount: number;
}

// ==========================================
// 1. INBOXES & LOCKING
// ==========================================

export async function getInbox(db: D1Database, address: string): Promise<Inbox | null> {
  return db
    .prepare('SELECT * FROM inboxes WHERE address = ?')
    .bind(address)
    .first<Inbox>();
}

export async function createInbox(
  db: D1Database,
  address: string,
  ownerSessionId?: string
): Promise<void> {
  await db
    .prepare(
      `INSERT OR IGNORE INTO inboxes (address, is_locked, lock_pin_hash, owner_session_id)
       VALUES (?, 0, NULL, ?)`
    )
    .bind(address, ownerSessionId || null)
    .run();
}

export async function lockInbox(
  db: D1Database,
  address: string,
  pin: string,
  sessionId: string
): Promise<boolean> {
  const pinHash = await hashPin(pin);
  const res = await db
    .prepare(
      `UPDATE inboxes
       SET is_locked = 1, lock_pin_hash = ?, owner_session_id = ?, locked_at = datetime('now')
       WHERE address = ? AND (is_locked = 0 OR owner_session_id = ?)`
    )
    .bind(pinHash, sessionId, address, sessionId)
    .run();
  return (res.meta.changes || 0) > 0;
}

export async function unlockInbox(
  db: D1Database,
  address: string,
  pin: string
): Promise<boolean> {
  const pinHash = await hashPin(pin);
  const res = await db
    .prepare(
      `UPDATE inboxes
       SET is_locked = 0, lock_pin_hash = NULL, locked_at = NULL
       WHERE address = ? AND lock_pin_hash = ?`
    )
    .bind(address, pinHash)
    .run();
  return (res.meta.changes || 0) > 0;
}

export async function verifyInboxPinWithLockout(
  db: D1Database,
  address: string,
  candidatePin: string
): Promise<{ success: boolean; locked: boolean; remainingMinutes?: number }> {
  // 1. Cek apakah alamat sedang dalam masa hukuman lockout
  const attemptRow = await db
    .prepare('SELECT failed_count, locked_until FROM pin_attempts WHERE address = ?')
    .bind(address)
    .first<{ failed_count: number; locked_until: string | null }>()
    .catch(() => null);

  if (attemptRow && attemptRow.locked_until) {
    const lockExpiry = new Date(attemptRow.locked_until).getTime();
    const now = Date.now();
    if (now < lockExpiry) {
      const remainingMinutes = Math.ceil((lockExpiry - now) / 60000);
      return { success: false, locked: true, remainingMinutes };
    }
  }

  // 2. Evaluasi kecocokan PIN
  const pinHash = await hashPin(candidatePin);
  const inbox = await db
    .prepare('SELECT 1 FROM inboxes WHERE address = ? AND lock_pin_hash = ?')
    .bind(address, pinHash)
    .first();

  if (inbox) {
    // Sukses: Reset riwayat percobaan
    await db.prepare('DELETE FROM pin_attempts WHERE address = ?').bind(address).run().catch(() => {});
    return { success: true, locked: false };
  } else {
    // Gagal: Tingkatkan counter dan tentukan lockout jika >= 5 percobaan
    const currentFailed = (attemptRow?.failed_count || 0) + 1;
    const isLockout = currentFailed >= 5;
    await db
      .prepare(`
        INSERT INTO pin_attempts (address, failed_count, locked_until)
        VALUES (?, 1, NULL)
        ON CONFLICT(address) DO UPDATE SET
          failed_count = failed_count + 1,
          locked_until = CASE WHEN pin_attempts.failed_count + 1 >= 5 THEN datetime('now', '+15 minutes') ELSE NULL END
      `)
      .bind(address)
      .run()
      .catch(() => {});

    return { success: false, locked: isLockout, remainingMinutes: isLockout ? 15 : undefined };
  }
}

export async function verifyInboxPin(
  db: D1Database,
  address: string,
  pin: string
): Promise<boolean> {
  const result = await verifyInboxPinWithLockout(db, address, pin);
  return result.success;
}

export async function inboxExists(db: D1Database, address: string): Promise<boolean> {
  const row = await db.prepare('SELECT 1 FROM inboxes WHERE address = ? LIMIT 1').bind(address).first();
  return !!row;
}

export async function getSessionInboxes(db: D1Database, sessionId: string): Promise<Inbox[]> {
  return db
    .prepare(
      `SELECT i.* FROM inboxes i
       INNER JOIN session_inboxes si ON si.inbox_address = i.address
       WHERE si.session_id = ?
       ORDER BY i.created_at DESC`
    )
    .bind(sessionId)
    .all<Inbox>()
    .then((r) => r.results);
}

// ==========================================
// 2. MESSAGES & OTP
// ==========================================

export async function getMessages(db: D1Database, inboxAddress: string): Promise<Message[]> {
  return db
    .prepare(
      `SELECT id, inbox_address, from_address, subject, body, body_html, otp_code, received_at
       FROM messages
       WHERE inbox_address = ?
       ORDER BY received_at DESC`
    )
    .bind(inboxAddress)
    .all<Message>()
    .then((r) => r.results);
}

export async function getMessageById(
  db: D1Database,
  inboxAddress: string,
  messageId: string
): Promise<Message | null> {
  return db
    .prepare(
      `SELECT id, inbox_address, from_address, subject, body, body_html, otp_code, received_at
       FROM messages
       WHERE inbox_address = ? AND id = ?
       LIMIT 1`
    )
    .bind(inboxAddress, messageId)
    .first<Message>();
}

export async function insertMessage(
  db: D1Database,
  msg: {
    id: string;
    inbox_address: string;
    from_address: string;
    subject: string;
    body: string;
    body_html?: string;
    otp_code?: string | null;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO messages (id, inbox_address, from_address, subject, body, body_html, otp_code)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      msg.id,
      msg.inbox_address,
      msg.from_address,
      msg.subject,
      msg.body,
      msg.body_html || '',
      msg.otp_code || null
    )
    .run();
}

export async function deleteMessage(db: D1Database, id: string): Promise<boolean> {
  const res = await db.prepare('DELETE FROM messages WHERE id = ?').bind(id).run();
  return (res.meta.changes || 0) > 0;
}

// ==========================================
// 3. SESSIONS & LINKS
// ==========================================

export async function ensureSession(db: D1Database, sessionId: string): Promise<void> {
  await db.prepare('INSERT OR IGNORE INTO sessions (id) VALUES (?)').bind(sessionId).run();
}

export async function linkInboxToSession(
  db: D1Database,
  sessionId: string,
  address: string
): Promise<void> {
  await db
    .prepare(
      'INSERT OR IGNORE INTO session_inboxes (session_id, inbox_address) VALUES (?, ?)'
    )
    .bind(sessionId, address)
    .run();
}

export async function unlinkInboxFromSession(
  db: D1Database,
  sessionId: string,
  address: string
): Promise<void> {
  await db
    .prepare('DELETE FROM session_inboxes WHERE session_id = ? AND inbox_address = ?')
    .bind(sessionId, address)
    .run();
}

export async function isInboxInSession(
  db: D1Database,
  sessionId: string,
  address: string
): Promise<boolean> {
  const row = await db
    .prepare('SELECT 1 FROM session_inboxes WHERE session_id = ? AND inbox_address = ? LIMIT 1')
    .bind(sessionId, address)
    .first();
  return !!row;
}

// ==========================================
// 4. DYNAMIC DOMAINS (ADMIN)
// ==========================================

export async function getActiveDomains(db: D1Database): Promise<string[]> {
  const rows = await db
    .prepare('SELECT domain FROM domains WHERE is_active = 1 ORDER BY is_default DESC, domain ASC')
    .all<{ domain: string }>();
  return rows.results.map((r) => r.domain);
}

export async function getAllDomains(db: D1Database): Promise<DomainItem[]> {
  const rows = await db
    .prepare('SELECT * FROM domains ORDER BY is_default DESC, domain ASC')
    .all<DomainItem>();
  return rows.results;
}

export async function addDomain(
  db: D1Database,
  domain: string,
  isDefault: boolean = false
): Promise<void> {
  const cleanDomain = domain.trim().toLowerCase();
  if (isDefault) {
    await db.prepare('UPDATE domains SET is_default = 0').run();
  }
  await db
    .prepare(
      `INSERT INTO domains (domain, is_active, is_default)
       VALUES (?, 1, ?)
       ON CONFLICT(domain) DO UPDATE SET is_active = 1, is_default = ?`
    )
    .bind(cleanDomain, isDefault ? 1 : 0, isDefault ? 1 : 0)
    .run();
}

export async function deleteDomain(db: D1Database, domain: string): Promise<boolean> {
  const res = await db
    .prepare('DELETE FROM domains WHERE domain = ?')
    .bind(domain.trim().toLowerCase())
    .run();
  return (res.meta.changes || 0) > 0;
}

export async function toggleDomainStatus(
  db: D1Database,
  domain: string,
  isActive: boolean
): Promise<boolean> {
  const res = await db
    .prepare('UPDATE domains SET is_active = ? WHERE domain = ?')
    .bind(isActive ? 1 : 0, domain.trim().toLowerCase())
    .run();
  return (res.meta.changes || 0) > 0;
}

// ==========================================
// 5. LIVE STATS & TRAFFIC LOGS (ADMIN)
// ==========================================

export async function getTrafficLogs(db: D1Database, limit: number = 50): Promise<TrafficLog[]> {
  const rows = await db
    .prepare(
      `SELECT id, ip, method, path, status, user_agent, duration_ms, timestamp as created_at, timestamp
       FROM traffic_logs
       ORDER BY id DESC
       LIMIT ?`
    )
    .bind(limit)
    .all<TrafficLog>();
  return rows.results;
}

export async function getTrafficStats(db: D1Database): Promise<TrafficStats> {
  const [totalEmails, totalEmailsToday, totalInboxes, lockedInboxes, activeDomains] =
    await Promise.all([
      db.prepare('SELECT COUNT(*) as c FROM messages').first<{ c: number }>(),
      db
        .prepare(
          "SELECT COUNT(*) as c FROM messages WHERE date(received_at) = date('now')"
        )
        .first<{ c: number }>(),
      db.prepare('SELECT COUNT(*) as c FROM inboxes').first<{ c: number }>(),
      db.prepare('SELECT COUNT(*) as c FROM inboxes WHERE is_locked = 1').first<{ c: number }>(),
      db.prepare('SELECT COUNT(*) as c FROM domains WHERE is_active = 1').first<{ c: number }>(),
    ]);

  return {
    totalEmailsAllTime: totalEmails?.c || 0,
    totalEmailsToday: totalEmailsToday?.c || 0,
    totalInboxesAllTime: totalInboxes?.c || 0,
    totalInboxesLocked: lockedInboxes?.c || 0,
    activeDomainsCount: activeDomains?.c || 0,
  };
}

export interface SenderStatItem {
  from_address: string;
  count: number;
}

export async function getSenderStats(db: D1Database): Promise<SenderStatItem[]> {
  try {
    const res = await db
      .prepare(
        `SELECT from_address, COUNT(*) as count
         FROM messages
         WHERE from_address IS NOT NULL AND from_address != ''
         GROUP BY from_address
         ORDER BY count DESC`
      )
      .all<SenderStatItem>();
    return res.results || [];
  } catch {
    return [];
  }
}

// ==========================================
// 6. ADS & SPONSORSHIP (MONETIZATION)
// ==========================================

export interface AdItem {
  slot_name: string;
  is_active: number;
  ad_type: string; // 'manual' | 'script'
  title: string;
  description: string;
  banner_url: string;
  target_url: string;
  script_code: string;
  cta_text: string;
  views: number;
  clicks: number;
  updated_at?: string;
}

export async function getAllAds(db: D1Database): Promise<AdItem[]> {
  try {
    const rows = await db.prepare('SELECT * FROM ads ORDER BY slot_name ASC').all<AdItem>();
    return rows.results;
  } catch {
    return [];
  }
}

export async function getPublicAds(db: D1Database): Promise<AdItem[]> {
  try {
    const rows = await db
      .prepare('SELECT slot_name, is_active, ad_type, title, description, banner_url, target_url, script_code, cta_text FROM ads WHERE is_active = 1')
      .all<AdItem>();
    if (rows.results.length > 0) {
      db.prepare('UPDATE ads SET views = views + 1 WHERE is_active = 1').run().catch(() => {});
    }
    return rows.results;
  } catch {
    return [];
  }
}

export async function saveAd(db: D1Database, ad: Partial<AdItem> & { slot_name: string }): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ads (slot_name, is_active, ad_type, title, description, banner_url, target_url, script_code, cta_text, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(slot_name) DO UPDATE SET
         is_active = excluded.is_active,
         ad_type = excluded.ad_type,
         title = excluded.title,
         description = excluded.description,
         banner_url = excluded.banner_url,
         target_url = excluded.target_url,
         script_code = excluded.script_code,
         cta_text = excluded.cta_text,
         updated_at = datetime('now')`
    )
    .bind(
      ad.slot_name,
      ad.is_active !== undefined ? (ad.is_active ? 1 : 0) : 1,
      ad.ad_type || 'manual',
      ad.title || '',
      ad.description || '',
      ad.banner_url || '',
      ad.target_url || '',
      ad.script_code || '',
      ad.cta_text || 'Lihat Promo'
    )
    .run();
}

export async function recordAdClick(db: D1Database, slotName: string): Promise<string | null> {
  try {
    const ad = await db.prepare('SELECT target_url FROM ads WHERE slot_name = ?').bind(slotName).first<{ target_url: string }>();
    if (ad) {
      await db.prepare('UPDATE ads SET clicks = clicks + 1 WHERE slot_name = ?').bind(slotName).run();
      return ad.target_url;
    }
  } catch {}
  return null;
}

// ==========================================
// 7. AUTO-SCHEMA INITIALIZATION
// ==========================================
let schemaInitDone = false;

export async function ensureDatabaseSchema(db: D1Database): Promise<void> {
  if (schemaInitDone || !db) return;
  try {
    // Check if inboxes has correct schema
    const tableInfo = await db.prepare("PRAGMA table_info(inboxes)").all<{ name: string }>().catch(() => ({ results: [] as { name: string }[] }));
    const cols = (tableInfo.results || []).map((r: any) => r.name);
    if (cols.length > 0 && (!cols.includes('address') || !cols.includes('lock_pin_hash'))) {
      // Incompatible old schema detected! Drop obsolete tables to migrate cleanly
      await db.batch([
        db.prepare('DROP TABLE IF EXISTS session_inboxes'),
        db.prepare('DROP TABLE IF EXISTS messages'),
        db.prepare('DROP TABLE IF EXISTS inboxes'),
      ]);
    }

    const siInfo = await db.prepare("PRAGMA table_info(session_inboxes)").all<{ name: string }>().catch(() => ({ results: [] as { name: string }[] }));
    const siCols = (siInfo.results || []).map((r: any) => r.name);
    if (siCols.length > 0 && !siCols.includes('inbox_address')) {
      await db.prepare('DROP TABLE IF EXISTS session_inboxes').run();
    }

    const msgInfo = await db.prepare("PRAGMA table_info(messages)").all<{ name: string }>().catch(() => ({ results: [] as { name: string }[] }));
    const msgCols = (msgInfo.results || []).map((r: any) => r.name);
    if (msgCols.length > 0 && !msgCols.includes('inbox_address')) {
      await db.prepare('DROP TABLE IF EXISTS messages').run();
    }

    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS inboxes (
        address TEXT PRIMARY KEY,
        is_locked INTEGER NOT NULL DEFAULT 0,
        lock_pin_hash TEXT DEFAULT NULL,
        owner_session_id TEXT DEFAULT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        locked_at TEXT DEFAULT NULL
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        inbox_address TEXT NOT NULL,
        from_address TEXT NOT NULL,
        subject TEXT DEFAULT '(no subject)',
        body TEXT DEFAULT '',
        body_html TEXT DEFAULT '',
        otp_code TEXT DEFAULT NULL,
        received_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (inbox_address) REFERENCES inboxes(address) ON DELETE CASCADE
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS session_inboxes (
        session_id TEXT NOT NULL,
        inbox_address TEXT NOT NULL,
        PRIMARY KEY (session_id, inbox_address),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
        FOREIGN KEY (inbox_address) REFERENCES inboxes(address) ON DELETE CASCADE
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS domains (
        domain TEXT PRIMARY KEY,
        is_active INTEGER NOT NULL DEFAULT 1,
        is_default INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status INTEGER NOT NULL,
        user_agent TEXT DEFAULT '',
        duration_ms INTEGER DEFAULT 0,
        timestamp TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS ads (
        slot_name TEXT PRIMARY KEY,
        is_active INTEGER NOT NULL DEFAULT 1,
        ad_type TEXT NOT NULL DEFAULT 'manual',
        title TEXT DEFAULT '',
        description TEXT DEFAULT '',
        banner_url TEXT DEFAULT '',
        target_url TEXT DEFAULT '',
        script_code TEXT DEFAULT '',
        cta_text TEXT DEFAULT 'Lihat Promo',
        views INTEGER NOT NULL DEFAULT 0,
        clicks INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS pin_attempts (
        address TEXT PRIMARY KEY,
        failed_count INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT DEFAULT NULL
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_messages_inbox_received ON messages (inbox_address, received_at DESC)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_inboxes_owner ON inboxes (owner_session_id)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_session_inboxes_lookup ON session_inboxes (session_id, inbox_address)`),
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_pin_attempts_address ON pin_attempts (address)`),
      db.prepare(`INSERT OR IGNORE INTO ads (slot_name, is_active, ad_type, title, description, banner_url, target_url, cta_text)
        VALUES ('slot_main', 1, 'manual', 'Sewa Slot Iklan Ini (Open Sponsor)', 'Pasang banner produk, bot, atau jasa kamu di sini.', '', 'https://instagram.com/rskl411_', 'Pasang Iklan')`)
    ]);
    schemaInitDone = true;
  } catch (err) {
    console.error('ensureDatabaseSchema error', err);
  }
}
