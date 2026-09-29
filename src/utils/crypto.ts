/**
 * Cryptographic & Extraction Utilities for RZero Mail
 */

// ─────────────────────────────────────────────────────────────────────────────
// PIN HASHING
//
// A security PIN is only 4-6 digits, so hashing it with a single SHA-256 round
// and a shared constant salt made every stored hash reversible: one precomputed
// table of 10^4..10^6 entries cracks every inbox in the database at once, and
// identical PINs produce identical hashes across inboxes.
//
// PINs are now stretched with PBKDF2-HMAC-SHA256 and a unique random salt per
// inbox, stored as:  pbkdf2$<iterations>$<saltB64>$<hashB64>
//
// Hashes written by the previous scheme are still accepted on read and are
// transparently re-hashed on the next successful unlock, so existing locked
// inboxes keep working.
// ─────────────────────────────────────────────────────────────────────────────

// PBKDF2 cost is CPU the Worker pays on EVERY PIN check, so it cannot be picked
// for security in isolation. Measured in V8: ~2.5 ms at 10k, ~6 ms at 25k,
// ~24 ms at 100k, ~36 ms at 150k. Cloudflare's Free plan allows roughly 10 ms of
// CPU per request, so a value in the 150k range would not just be slow — it would
// make PIN verification fail outright on that plan.
//
// 20k keeps the default inside the Free budget with headroom while still being
// ~20,000x the work of the single SHA-256 round it replaced. On a paid plan you
// can raise this constant, and hashes already stored keep verifying: the
// iteration count is embedded in the hash format.
//
// Worth being honest about the ceiling: even at 150k, an offline crack of a
// 4-digit PIN costs about a second of GPU time, and a 6-digit one a couple of
// minutes. The KDF is the backstop for a leaked database; the online lockout in
// verifyInboxPinWithLockout() is what actually protects a live inbox.
const PBKDF2_ITERATIONS = 20_000;
const PBKDF2_PREFIX = 'pbkdf2';
const LEGACY_SALT = 'rzero_salt_v1';

function bytesToB64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return btoa(out);
}

function b64ToBytes(b64: string): Uint8Array {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function toHex(buffer: ArrayBuffer): string {
  const view = new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < view.length; i++) out += view[i].toString(16).padStart(2, '0');
  return out;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  return crypto.subtle.deriveBits(
    // Cast keeps this portable across the DOM and Workers lib typings, which
    // disagree about which buffer types satisfy `BufferSource`.
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as unknown as BufferSource, iterations },
    key,
    256
  );
}

/**
 * Constant-time string comparison. Length mismatch is folded into the result
 * instead of short-circuiting, so timing does not reveal how many leading
 * characters matched. Used for PIN digests and shared secrets.
 */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  const len = Math.max(ab.length, bb.length);
  let diff = ab.length ^ bb.length;
  for (let i = 0; i < len; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

/** Hash a PIN with PBKDF2-HMAC-SHA256 and a fresh random salt. */
export async function hashPin(pin: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(pin.trim(), salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_PREFIX}$${PBKDF2_ITERATIONS}$${bytesToB64(salt)}$${bytesToB64(new Uint8Array(bits))}`;
}

/** Previous scheme. Retained only to verify PINs stored before the upgrade. */
async function hashPinLegacy(pin: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${LEGACY_SALT}:${pin.trim()}`);
  return toHex(await crypto.subtle.digest('SHA-256', data));
}

/** True when `stored` was produced by the old single-round SHA-256 scheme. */
export function isLegacyPinHash(stored: string | null | undefined): boolean {
  return !!stored && !stored.startsWith(`${PBKDF2_PREFIX}$`);
}

/**
 * Verify a candidate PIN against a stored hash. Accepts both the current
 * PBKDF2 format and the legacy SHA-256 format.
 */
export async function verifyPinHash(
  pin: string,
  stored: string | null | undefined
): Promise<boolean> {
  if (!stored) return false;
  const candidate = pin.trim();

  if (stored.startsWith(`${PBKDF2_PREFIX}$`)) {
    const parts = stored.split('$');
    if (parts.length !== 4) return false;
    const iterations = Number(parts[1]);
    if (!Number.isFinite(iterations) || iterations <= 0) return false;
    try {
      const salt = b64ToBytes(parts[2]);
      const bits = await pbkdf2(candidate, salt, iterations);
      return timingSafeEqualStr(bytesToB64(new Uint8Array(bits)), parts[3]);
    } catch {
      return false;
    }
  }

  return timingSafeEqualStr(await hashPinLegacy(candidate), stored);
}

export function parseCookies(cookieHeader: string | null): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const [k, ...v] = part.trim().split('=');
    if (k) {
      cookies[k] = decodeURIComponent(v.join('='));
    }
  }
  return cookies;
}

/**
 * Admin session lifetime.
 *
 * Was 30 days with no way to revoke, so a leaked cookie stayed valid for a
 * month. The epoch check in the admin session gate now makes revocation
 * possible; this shortens the window that revocation has to save you from.
 */
export const ADMIN_SESSION_TTL_MS = 7 * 24 * 3600 * 1000;

/**
 * Sign an admin session token using HMAC-SHA256 (Web Crypto API)
 *
 * `kind` is embedded in the payload so a short-lived login challenge can never
 * be mistaken for a full session: verification checks the expected kind.
 *
 * `epoch` is the deployment's session generation. Bumping it in the database
 * invalidates every token signed with the previous value, which is what makes
 * "log out everywhere" possible without server-side session storage.
 */
export async function signAdminToken(
  user: string,
  secret: string,
  ttlMs: number = ADMIN_SESSION_TTL_MS,
  kind: 'session' | 'challenge' = 'session',
  epoch: number = 0
): Promise<string> {
  const exp = Date.now() + ttlMs;
  const payloadStr = JSON.stringify({ user, exp, kind, epoch });
  const payloadB64 = btoa(payloadStr);

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64));
  const sigHex = Array.from(new Uint8Array(sigBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `${payloadB64}.${sigHex}`;
}

/**
 * Verify signed admin session token
 */
export async function verifyAdminToken(
  token: string,
  secret: string
): Promise<{ valid: boolean; user?: string; kind?: string; epoch?: number }> {
  if (!token || !token.includes('.')) return { valid: false };
  const [payloadB64, sigHex] = token.split('.');

  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const sigBytes = new Uint8Array(
      (sigHex.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
    );

    const isValid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payloadB64));
    if (!isValid) return { valid: false };

    const payload = JSON.parse(atob(payloadB64));
    if (payload.exp < Date.now()) {
      return { valid: false };
    }

    // Tokens minted before the `kind` field existed were all full sessions.
    const kind = typeof payload.kind === 'string' ? payload.kind : 'session';
    // Tokens minted before the epoch existed belong to generation 0.
    const epoch = Number.isFinite(payload.epoch) ? Number(payload.epoch) : 0;

    return { valid: true, user: payload.user, kind, epoch };
  } catch {
    return { valid: false };
  }
}

function stripHtmlTags(html: string): string {
  if (!html) return '';
  let out = '';
  let i = 0;
  const len = Math.min(html.length, 100000);
  while (i < len) {
    const lt = html.indexOf('<', i);
    if (lt === -1) { out += html.slice(i, len); break; }
    out += html.slice(i, lt);
    const gt = html.indexOf('>', lt);
    if (gt === -1) break;
    out += ' ';
    i = gt + 1;
  }
  return out;
}

export function extractOtpCode(subject: string, text: string, html: string = ''): string | null {
  // Strip HTML tags and entities without catastrophic backtracking
  const cleanHtml = stripHtmlTags(html || '')
    .replace(/&[a-z0-9#]+;/gi, ' ');

  const content = `${subject}\n${text}\n${cleanHtml}`
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, ' ');

  // Priority 1: Direct keyword association (OTP, verification code, pin, etc.)
  const labeledPatterns = [
    /(?:verification\s*code|kode\s*(?:verifikasi|otp)|one-time\s*(?:password|passcode)|security\s*code|confirm(?:ation)?\s*code|login\s*code|auth(?:entication)?\s*code|otp(?:\s*code)?|pin(?:\s*code)?)\s*[:=—–-]?\s*(?:is\s*|adalah\s*)?(\d{4,8})\b/i,
    /\b(\d{4,8})\b\s*(?:is\s*your\s*(?:verification|login|otp|security)\s*code|adalah\s*kode\s*(?:verifikasi|otp))/i,
    /(?:code|kode|otp)\s+is\s+(\d{4,8})\b/i,
    /(?:enter|masukkan|input)\s+(?:the\s+)?(?:code|kode|pin|otp)?\s*[:=—–-]?\s*(\d{4,8})\b/i,
  ];

  for (const pattern of labeledPatterns) {
    const match = content.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  // Priority 2: Standalone ONLY if verification context exists in text or subject
  const hasAuthContext = /(?:verification|verifikasi|one-time|otp|security|confirm\b|authenticate|otentikasi|login code)/i.test(
    subject + ' ' + text
  );

  if (hasAuthContext) {
    // Look for isolated 6-digit or 4-digit number
    const matches = content.match(/\b(?<![#$€£¥\/\-@.])(\d{4,8})\b(?![#$€£¥\/\-@.])/g);
    if (matches) {
      for (const candidate of matches) {
        const num = parseInt(candidate, 10);
        // Exclude years
        if (num >= 1990 && num <= 2035) continue;
        // Exclude common round dimensions, addresses, or numbers
        if ([1000, 1200, 1400, 1600, 1920, 2000, 5000].includes(num)) continue;
        return candidate;
      }
    }
  }

  return null;
}
