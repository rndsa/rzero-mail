/**
 * Cryptographic & Extraction Utilities for RZero Mail
 */

export async function hashPin(pin: string, salt: string = 'rzero_salt_v1'): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${salt}:${pin.trim()}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
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
 * Sign an admin session token using HMAC-SHA256 (Web Crypto API)
 */
export async function signAdminToken(
  user: string,
  secret: string,
  ttlMs: number = 30 * 24 * 3600 * 1000
): Promise<string> {
  const exp = Date.now() + ttlMs;
  const payloadStr = JSON.stringify({ user, exp });
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
): Promise<{ valid: boolean; user?: string }> {
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

    return { valid: true, user: payload.user };
  } catch {
    return { valid: false };
  }
}

export function extractOtpCode(subject: string, text: string, html: string = ''): string | null {
  // Strip HTML tags and entities
  const cleanHtml = (html || '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
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
