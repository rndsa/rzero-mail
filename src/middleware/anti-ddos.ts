import type { Context, Next } from 'hono';
import type { D1Database } from '@cloudflare/workers-types';
import { timingSafeEqualStr } from '../utils/crypto';

interface RateRecord {
  count: number;
  resetAt: number;
}

// In-memory sliding window cache per Cloudflare Worker edge POP
const ipRateMap = new Map<string, RateRecord>();
const blockedIps = new Map<string, number>(); // ip -> unblockTimestamp

function cleanupStaleEntries(now: number) {
  if (ipRateMap.size > 2000) {
    for (const [key, val] of ipRateMap.entries()) {
      if (val.resetAt <= now) {
        ipRateMap.delete(key);
      }
    }
  }
  if (blockedIps.size > 500) {
    for (const [ip, unblockTime] of blockedIps.entries()) {
      if (unblockTime <= now) {
        blockedIps.delete(ip);
      }
    }
  }
}

export function getClientIp(c: Context): string {
  return (
    c.req.header('cf-connecting-ip') ||
    c.req.header('x-forwarded-for')?.split(',')[0].trim() ||
    '127.0.0.1'
  );
}

/**
 * Does this request create an inbox?
 *
 * Exported so the classification can be unit-tested. It must NOT be keyed off
 * the HTTP verb: the same handler is reachable over documented GET aliases
 * (/create, /custom, /new, /inboxes/create, /inboxes/new), so a method-based
 * check let the 15/min creation budget be spent at the 120/min read budget.
 */
export function isCreateRequest(method: string, path: string): boolean {
  const normalized = path.startsWith('/api/') ? path.slice(4) : path;
  const suffixes = ['/create', '/custom', '/new', '/inboxes/create', '/inboxes/new'];
  const isWrite = method === 'POST' || method === 'DELETE';
  return (
    suffixes.some((p) => normalized === p || normalized.startsWith(`${p}/`)) ||
    (isWrite && normalized === '/inboxes')
  );
}

/**
 * Silent Anti-DDoS Middleware:
 * - Edge sliding-window rate limiter (strict on creation, relaxed on reads)
 * - Temporary auto-cooldown for abusive IPs
 * - Invisible honeypot trap against automated scrapers
 * - D1 asynchronous analytics logging without slowing down user response
 */
export async function antiDdosMiddleware(c: Context, next: Next): Promise<Response | void> {
  // Trusted server-to-server callers (e.g. the VPS SMTP receiver) skip the
  // limiter. The credential must match the configured secret exactly.
  //
  // This previously accepted a hardcoded string that is published in this
  // repository, via a substring match — anyone could lift the whole rate limit
  // with one crafted header. Now: configured secret only, exact match only,
  // and no bypass at all when the secret is unset.
  const configuredSecret = String(c.env?.ADMIN_SECRET || '').trim();
  if (configuredSecret) {
    const presented = (
      c.req.header('authorization') ||
      c.req.header('x-inbound-secret') ||
      ''
    )
      .replace(/^Bearer\s+/i, '')
      .trim();
    if (presented && timingSafeEqualStr(presented, configuredSecret)) {
      return next();
    }
  }

  const ip = getClientIp(c);
  const now = Date.now();
  cleanupStaleEntries(now);
  const path = c.req.path;
  const method = c.req.method;

  // 1. Check if IP is in temporary cooldown / blocked list
  const blockedUntil = blockedIps.get(ip);
  if (blockedUntil && blockedUntil > now) {
    const retryAfter = Math.ceil((blockedUntil - now) / 1000);
    return c.json(
      {
        error: 'Too Many Requests',
        message: 'IP dalam cooldown sementara karena aktivitas mencurigakan. Coba lagi nanti.',
        retryAfter,
      },
      429,
      { 'Retry-After': String(retryAfter) }
    );
  }

  // 2. Sliding window rate limit
  const isWrite = method === 'POST' || method === 'DELETE';
  const isCreateInbox = isCreateRequest(method, path);

  // Rate limit thresholds:
  // - Inbox creation: max 15 / min per IP
  // - Other writes (PIN, delete): max 30 / min per IP
  // - Reads / polling: max 120 / min per IP
  const limit = isCreateInbox ? 15 : isWrite ? 30 : 120;
  const windowMs = 60000;

  const key = `${ip}:${isCreateInbox ? 'create' : isWrite ? 'w' : 'r'}`;
  const record = ipRateMap.get(key) || { count: 0, resetAt: now + windowMs };

  if (record.resetAt <= now) {
    record.count = 1;
    record.resetAt = now + windowMs;
  } else {
    record.count += 1;
  }
  ipRateMap.set(key, record);

  // If rate limit exceeded:
  if (record.count > limit) {
    // If spamming heavily (2x limit), put in temporary 5-minute jail
    if (record.count > limit * 2) {
      blockedIps.set(ip, now + 300000); // 5 minutes cooldown
    }

    const retryAfter = Math.ceil((record.resetAt - now) / 1000);
    return c.json(
      {
        error: 'Too Many Requests',
        message: 'Batas request tercapai. Harap tunggu beberapa detik.',
        retryAfter,
      },
      429,
      { 'Retry-After': String(retryAfter) }
    );
  }

  // 3. Invisible honeypot trap for automated bots
  if (isWrite && c.req.header('content-type')?.includes('application/json')) {
    try {
      const cloned = c.req.raw.clone();
      const body: any = await cloned.json();
      if (body && typeof body === 'object') {
        if (body._hp || body.honeypot || body.hp_check || body.website_url) {
          // Trap triggered: ban bot IP for 30 minutes
          blockedIps.set(ip, now + 1800000);
          return c.json({ error: 'Validation failed' }, 400);
        }
      }
    } catch {
      // Ignore JSON parse errors here; route handler will process
    }
  }

  const startTime = Date.now();
  await next();
  const duration = Date.now() - startTime;

  // 4. Asynchronously record traffic log into D1
  const db = (c.env as any)?.DB as D1Database | undefined;
  if (db && !path.startsWith('/admin/traffic')) {
    const status = c.res.status || 200;
    const ua = (c.req.header('user-agent') || '').slice(0, 150);
    // The method is echoed in the admin traffic log. HTTP methods are an open
    // token set, so constrain what we store to the standard verb shape and
    // label anything else — a crafted method cannot carry markup into that view.
    const safeMethod = /^[A-Z]{3,10}$/.test(method) ? method : 'OTHER';
    let logPath = path;
    try {
      logPath = decodeURIComponent(path);
    } catch {}

    const logPromise = db
      .prepare(
        `INSERT INTO traffic_logs (ip, method, path, status, user_agent, duration_ms)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(ip, safeMethod, logPath, status, ua, duration)
      .run()
      .catch(() => {});

    try {
      c.executionCtx.waitUntil(logPromise);
    } catch {
      // fallback
    }
  }
}
