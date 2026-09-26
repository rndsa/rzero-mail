import { Hono } from 'hono';
import type { D1Database } from '@cloudflare/workers-types';
import {
  getInbox,
  createInbox,
  inboxExists,
  lockInbox,
  unlockInbox,
  verifyInboxPin,
  getSessionInboxes,
  getMessages,
  getMessageById,
  deleteMessage,
  ensureSession,
  linkInboxToSession,
  unlinkInboxFromSession,
  isInboxInSession,
  getActiveDomains,
  getAllDomains,
  addDomain,
  deleteDomain,
  toggleDomainStatus,
  getTrafficLogs,
  getTrafficStats,
  getPublicAds,
  recordAdClick,
} from '../db/queries';
import { generateUniqueAddress } from '../utils/random-address';

import { antiDdosMiddleware } from '../middleware/anti-ddos';

export interface ApiEnv {
  DB: D1Database;
  APP_NAME?: string;
  MAIL_DOMAIN?: string;
  WEB_HOST?: string;
  ADMIN_TOKEN?: string;
}

function getEnvDomains(env: ApiEnv): string[] {
  return (env.MAIL_DOMAIN || 'rzero.me')
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

function getSessionId(c: any): string | null {
  const headerSid = (c.req.header('x-session-id') || c.req.query('session_id') || '').trim();
  if (headerSid) return headerSid;
  const cookieHeader = c.req.header('cookie') || '';
  const match = cookieHeader.match(/rzero_user_session=([^;]+)/);
  if (match && match[1]) {
    return decodeURIComponent(match[1]).trim();
  }
  return null;
}

function requireSession(c: any): string {
  let sid = getSessionId(c);
  if (!sid) {
    sid = crypto.randomUUID();
    c.header(
      'Set-Cookie',
      `rzero_user_session=${encodeURIComponent(sid)}; Path=/; SameSite=Lax; Max-Age=31536000`
    );
  }
  return sid;
}

const api = new Hono<{ Bindings: ApiEnv }>();

// Silent Anti-DDoS & Traffic Logger Middleware
api.use('*', antiDdosMiddleware);

// ==========================================
// PUBLIC API (NO API KEY REQUIRED)
// ==========================================

// ---- GET /api/config ----
api.get('/config', async (c) => {
  let domains: string[] = [];
  try {
    domains = await getActiveDomains(c.env.DB);
  } catch {}

  if (domains.length === 0) {
    domains = getEnvDomains(c.env);
  }

  return c.json({
    appName: c.env.APP_NAME || 'RZero Mail',
    mailDomain: domains[0] || 'rzero.me',
    mailDomains: domains,
    webHost: c.env.WEB_HOST || 'mail.rzero.me',
  });
});

// ---- GET /api/session ----
api.get('/session', async (c) => {
  let sid = getSessionId(c);
  if (!sid) {
    sid = crypto.randomUUID();
  }
  await ensureSession(c.env.DB, sid);
  c.header(
    'Set-Cookie',
    `rzero_user_session=${encodeURIComponent(sid)}; Path=/; SameSite=Lax; Max-Age=31536000`
  );
  return c.json({ sessionId: sid });
});

// ---- GET /api/domains (Public Active Domains) ----
api.get('/domains', async (c) => {
  let domains: string[] = [];
  try {
    domains = await getActiveDomains(c.env.DB);
  } catch {}

  if (domains.length === 0) {
    domains = getEnvDomains(c.env);
  }
  return c.json({ domains });
});

// ---- GET /api/ads (Public Active Ads) ----
api.get('/ads', async (c) => {
  try {
    const ads = await getPublicAds(c.env.DB);
    return c.json({ ads });
  } catch {
    return c.json({ ads: [] });
  }
});

// ---- GET /api/ads/click/:slot (Track Click & Redirect) ----
api.get('/ads/click/:slot', async (c) => {
  const slot = c.req.param('slot');
  try {
    const targetUrl = await recordAdClick(c.env.DB, slot);
    if (targetUrl && (targetUrl.startsWith('http://') || targetUrl.startsWith('https://'))) {
      return c.redirect(targetUrl, 302);
    }
  } catch {}
  return c.redirect('/', 302);
});

// ---- GET /api/inboxes ----
const getInboxesHandler = async (c: any) => {
  try {
    const sid = requireSession(c);
    if (!sid) return c.json({ error: 'Missing x-session-id header' }, 400);

    const inboxes = await getSessionInboxes(c.env.DB, sid);
    return c.json({
      inboxes: inboxes.map((i) => ({
        address: i.address,
        isLocked: Boolean(i.is_locked),
        isOwner: i.owner_session_id === sid,
        createdAt: i.created_at,
        lockedAt: i.locked_at,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'INBOXES_ERROR', detail: String(err?.message || err) }, 500);
  }
};

api.get('/inboxes', getInboxesHandler);
api.get('/session/inboxes', getInboxesHandler);

// ---- Helper: Unified Create Inbox (Supports POST JSON & GET Query) ----
const createInboxHandler = async (c: any) => {
  try {
    const sid = requireSession(c);
    if (!sid) return c.json({ error: 'Missing x-session-id header' }, 400);

    await ensureSession(c.env.DB, sid);

    let body: any = {};
    if (c.req.method === 'POST') {
      try {
        body = await c.req.json();
      } catch {}
    }

    const pathAddress = c.req.param('address') ? decodeURIComponent(c.req.param('address')).trim().toLowerCase() : '';
    const queryDomain = c.req.query('domain');
    const queryName = c.req.query('name') || c.req.query('user');
    const queryAddress = c.req.query('address') || c.req.query('email');
    const queryPin = c.req.query('pin');

    let domains: string[] = [];
    try {
      domains = await getActiveDomains(c.env.DB);
    } catch {}
    if (domains.length === 0) {
      domains = getEnvDomains(c.env);
    }

    let address: string;
    const requestedDomain = (body.domain || queryDomain || '').trim().toLowerCase();
    const defaultDomain = domains.includes(c.env.MAIL_DOMAIN || 'rzmail.my.id')
      ? (c.env.MAIL_DOMAIN || 'rzmail.my.id')
      : (domains.includes('rzmail.my.id') ? 'rzmail.my.id' : domains[0]);
    const targetDomain = domains.includes(requestedDomain) ? requestedDomain : defaultDomain;

    const requestedName = (body.name || queryName || '').trim();
    const fullCustomAddress = (pathAddress || body.address || queryAddress || '').trim().toLowerCase();

    if (fullCustomAddress && fullCustomAddress.includes('@')) {
      const parts = fullCustomAddress.split('@');
      const customDomain = parts[1];
      if (domains.includes(customDomain)) {
        address = fullCustomAddress;
      } else {
        address = `${parts[0]}@${targetDomain}`;
      }
    } else if (fullCustomAddress && !fullCustomAddress.includes('@')) {
      const rawName = fullCustomAddress.toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 40);
      if (!rawName) return c.json({ error: 'Invalid inbox name' }, 400);
      address = `${rawName}@${targetDomain}`;
    } else if (requestedName) {
      const rawName = requestedName.toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 40);
      if (!rawName) return c.json({ error: 'Invalid inbox name' }, 400);
      address = `${rawName}@${targetDomain}`;
    } else {
      address = await generateUniqueAddress((addr) => inboxExists(c.env.DB, addr), targetDomain);
    }

    const existing = await getInbox(c.env.DB, address);
    if (existing) {
      // If inbox exists and is locked with PIN
      if (existing.is_locked) {
        // If current session is already the owner:
        if (existing.owner_session_id === sid) {
          await linkInboxToSession(c.env.DB, sid, address);
          return c.json({
            success: true,
            inbox: {
              address,
              isLocked: true,
              isOwner: true,
              created: false,
            },
            address,
            isLocked: true,
            isOwner: true,
            created: false,
          });
        }

        // If a PIN is supplied in the request, verify it!
        const providedPin = (body.pin || queryPin) ? String(body.pin || queryPin).trim() : '';
        if (providedPin) {
          const isValid = await verifyInboxPin(c.env.DB, address, providedPin);
          if (isValid) {
            await linkInboxToSession(c.env.DB, sid, address);
            return c.json({
              success: true,
              inbox: {
                address,
                isLocked: true,
                isOwner: false,
                created: false,
              },
              address,
              isLocked: true,
              isOwner: false,
              created: false,
              message: 'PIN benar! Email berhasil dibuka.',
            });
          } else {
            return c.json(
              {
                success: false,
                error: 'INVALID_PIN',
                requiresPin: true,
                address,
                message: 'PIN keamanan yang dimasukkan salah!',
              },
              401
            );
          }
        }

        return c.json(
          {
            success: false,
            error: 'PIN_REQUIRED',
            requiresPin: true,
            address,
            message: 'Email ini dilindungi PIN keamanan.',
          },
          403
        );
      }

      // If existing is not locked: link directly to session
      await linkInboxToSession(c.env.DB, sid, address);
      return c.json({
        success: true,
        inbox: {
          address,
          isLocked: false,
          isOwner: existing.owner_session_id === sid,
          created: false,
        },
        address,
        isLocked: false,
        isOwner: existing.owner_session_id === sid,
        created: false,
      });
    }

    // Create new inbox
    await createInbox(c.env.DB, address, sid);
    await linkInboxToSession(c.env.DB, sid, address);

    // If user requested immediate PIN lock
    const initialPin = body.pin || queryPin;
    if (initialPin && typeof initialPin === 'string' && initialPin.trim().length >= 4) {
      await lockInbox(c.env.DB, address, initialPin.trim(), sid);
    }

    const created = await getInbox(c.env.DB, address);
    return c.json(
      {
        success: true,
        inbox: {
          address,
          isLocked: Boolean(created?.is_locked),
          isOwner: true,
          created: true,
        },
        address,
        isLocked: Boolean(created?.is_locked),
        isOwner: true,
        created: true,
      },
      201
    );
  } catch (err: any) {
    return c.json({ success: false, error: 'CREATE_INBOX_ERROR', detail: String(err?.message || err) }, 500);
  }
};

// Mount Create & Custom Inbox Handlers (Both POST and GET!)
api.post('/inboxes', createInboxHandler);
api.get('/inboxes/create', createInboxHandler);
api.get('/inboxes/new', createInboxHandler);
api.get('/create', createInboxHandler);
api.get('/create/:address', createInboxHandler);
api.get('/new', createInboxHandler);
api.get('/custom', createInboxHandler);
api.get('/custom/:address', createInboxHandler);
api.post('/custom', createInboxHandler);

// ---- DELETE /api/inboxes/:address (DELETE and GET /delete) ----
const deleteInboxHandler = async (c: any) => {
  const sid = requireSession(c);
  if (!sid) return c.json({ error: 'Missing x-session-id header' }, 400);

  const address = decodeURIComponent(c.req.param('address') || c.req.query('address') || '').toLowerCase();
  if (!address) return c.json({ error: 'Address is required' }, 400);

  await unlinkInboxFromSession(c.env.DB, sid, address);
  return c.json({ success: true, message: 'Inbox unlinked from session' });
};
api.delete('/inboxes/:address', deleteInboxHandler);
api.get('/inboxes/:address/delete', deleteInboxHandler);

// ---- POST & GET /api/inboxes/:address/lock (Lock email with PIN) ----
const lockInboxHandler = async (c: any) => {
  const sid = requireSession(c);
  if (!sid) return c.json({ error: 'Missing x-session-id header' }, 400);

  const address = decodeURIComponent(c.req.param('address') || c.req.query('address') || '').toLowerCase();
  let body: any = {};
  if (c.req.method === 'POST') {
    try { body = await c.req.json(); } catch {}
  }
  const pin = (body.pin || c.req.query('pin') || '').trim();

  if (!pin || pin.length < 4) {
    return c.json({ error: 'PIN must be at least 4 characters/digits' }, 400);
  }

  const inbox = await getInbox(c.env.DB, address);
  if (!inbox) {
    return c.json({ error: 'Inbox not found' }, 404);
  }

  if (inbox.is_locked && inbox.owner_session_id && inbox.owner_session_id !== sid) {
    return c.json({ error: 'This inbox is already locked by another owner' }, 403);
  }

  const success = await lockInbox(c.env.DB, address, pin, sid);
  if (!success) {
    return c.json({ error: 'Failed to lock inbox' }, 500);
  }

  return c.json({ success: true, message: 'Inbox successfully locked with PIN' });
};
api.post('/inboxes/:address/lock', lockInboxHandler);
api.get('/inboxes/:address/lock', lockInboxHandler);

// ---- POST & GET /api/inboxes/:address/unlock (Unlock email with PIN) ----
const unlockInboxHandler = async (c: any) => {
  const address = decodeURIComponent(c.req.param('address') || c.req.query('address') || '').toLowerCase();
  let body: any = {};
  if (c.req.method === 'POST') {
    try { body = await c.req.json(); } catch {}
  }
  const pin = (body.pin || c.req.query('pin') || '').trim();

  if (!pin) {
    return c.json({ error: 'PIN is required to unlock' }, 400);
  }

  const success = await unlockInbox(c.env.DB, address, pin);
  if (!success) {
    return c.json({ error: 'Invalid PIN or inbox is not locked' }, 401);
  }

  return c.json({ success: true, message: 'Inbox successfully unlocked' });
};
api.post('/inboxes/:address/unlock', unlockInboxHandler);
api.get('/inboxes/:address/unlock', unlockInboxHandler);

// ---- POST & GET /api/inboxes/:address/verify-pin (Verify PIN & link session) ----
const verifyPinHandler = async (c: any) => {
  const sid = requireSession(c);
  const address = decodeURIComponent(c.req.param('address') || c.req.query('address') || '').toLowerCase();
  let body: any = {};
  if (c.req.method === 'POST') {
    try { body = await c.req.json(); } catch {}
  }
  const pin = (body.pin || c.req.query('pin') || '').trim();

  const valid = await verifyInboxPin(c.env.DB, address, pin);
  if (!valid) {
    return c.json({ error: 'INVALID_PIN', message: 'PIN yang dimasukkan salah!' }, 401);
  }

  if (sid) {
    await linkInboxToSession(c.env.DB, sid, address);
  }

  return c.json({ success: true, message: 'PIN berhasil diverifikasi!' });
};
api.post('/inboxes/:address/verify-pin', verifyPinHandler);
api.get('/inboxes/:address/verify-pin', verifyPinHandler);

// ---- GET /api/inboxes/:address/messages (Read Messages + Lock Guard) ----
api.get('/inboxes/:address/messages', async (c) => {
  const sid = getSessionId(c);
  const address = decodeURIComponent(c.req.param('address')).toLowerCase();
  const inbox = await getInbox(c.env.DB, address);

  if (!inbox) {
    return c.json({ messages: [] });
  }

  // Check Lock Guard
  if (inbox.is_locked) {
    const isOwner = sid && inbox.owner_session_id === sid;
    const isLinked = sid ? await isInboxInSession(c.env.DB, sid, address) : false;
    const providedPin = c.req.header('x-inbox-pin') || c.req.query('pin');

    let pinVerified = false;
    if (providedPin) {
      pinVerified = await verifyInboxPin(c.env.DB, address, String(providedPin).trim());
    }

    if (!isOwner && !isLinked && !pinVerified) {
      return c.json(
        {
          error: 'INBOX_LOCKED',
          isLocked: true,
          requiresPin: true,
          message: 'Inbox ini dilindungi PIN. Masukkan PIN untuk membaca pesan.',
        },
        403
      );
    }
  }

  const messages = await getMessages(c.env.DB, address);
  return c.json({
    address,
    isLocked: Boolean(inbox.is_locked),
    messages: messages.map((m) => ({
      id: m.id,
      from: m.from_address,
      from_address: m.from_address,
      subject: m.subject,
      body: m.body,
      body_text: m.body,
      bodyHtml: m.body_html,
      body_html: m.body_html,
      otpCode: m.otp_code,
      otp_code: m.otp_code,
      receivedAt: m.received_at,
      created_at: m.received_at,
    })),
  });
});

// ---- GET /api/inboxes/:address/messages/:id (Single Message Detail) ----
api.get('/inboxes/:address/messages/:id', async (c) => {
  const sid = getSessionId(c);
  const address = decodeURIComponent(c.req.param('address')).toLowerCase();
  const id = c.req.param('id');
  const inbox = await getInbox(c.env.DB, address);

  if (!inbox) {
    return c.json({ error: 'INBOX_NOT_FOUND', message: 'Inbox tidak ditemukan.' }, 404);
  }

  // Check Lock Guard
  if (inbox.is_locked) {
    const isOwner = sid && inbox.owner_session_id === sid;
    const isLinked = sid ? await isInboxInSession(c.env.DB, sid, address) : false;
    const providedPin = c.req.header('x-inbox-pin') || c.req.query('pin');

    let pinVerified = false;
    if (providedPin) {
      pinVerified = await verifyInboxPin(c.env.DB, address, String(providedPin).trim());
    }

    if (!isOwner && !isLinked && !pinVerified) {
      return c.json(
        {
          error: 'INBOX_LOCKED',
          isLocked: true,
          requiresPin: true,
          message: 'Inbox ini dilindungi PIN. Masukkan PIN untuk membaca pesan.',
        },
        403
      );
    }
  }

  const msg = await getMessageById(c.env.DB, address, id);
  if (!msg) {
    return c.json({ error: 'MESSAGE_NOT_FOUND', message: 'Pesan tidak ditemukan.' }, 404);
  }

  return c.json({
    message: {
      id: msg.id,
      from_address: msg.from_address,
      subject: msg.subject,
      body_text: msg.body,
      body_html: msg.body_html,
      otp_code: msg.otp_code,
      created_at: msg.received_at,
    },
  });
});

// ---- GET /api/messages (Shorthand GET for retrieving messages) ----
api.get('/messages/:address', async (c) => {
  const address = decodeURIComponent(c.req.param('address')).toLowerCase();
  const sid = getSessionId(c);
  const inbox = await getInbox(c.env.DB, address);
  if (!inbox) return c.json({ address, messages: [] });

  if (inbox.is_locked) {
    const isOwner = sid && inbox.owner_session_id === sid;
    const isLinked = sid ? await isInboxInSession(c.env.DB, sid, address) : false;
    const providedPin = c.req.header('x-inbox-pin') || c.req.query('pin');
    let pinVerified = false;
    if (providedPin) {
      pinVerified = await verifyInboxPin(c.env.DB, address, String(providedPin).trim());
    }
    if (!isOwner && !isLinked && !pinVerified) {
      return c.json({ error: 'INBOX_LOCKED', isLocked: true, requiresPin: true, message: 'Inbox ini dilindungi PIN.' }, 403);
    }
  }

  const messages = await getMessages(c.env.DB, address);
  return c.json({
    success: true,
    address,
    isLocked: Boolean(inbox.is_locked),
    count: messages.length,
    messages: messages.map((m) => ({
      id: m.id,
      from_address: m.from_address,
      subject: m.subject,
      snippet: m.body ? m.body.slice(0, 100) : '',
      otp_code: m.otp_code,
      received_at: m.received_at,
    })),
  });
});

api.get('/messages', async (c) => {
  const address = (c.req.query('address') || c.req.query('email') || c.req.query('inbox') || '').trim().toLowerCase();
  if (!address) {
    return c.json({ error: 'Missing address query (?address=user@zallpyx.xyz)' }, 400);
  }
  const sid = getSessionId(c);
  const inbox = await getInbox(c.env.DB, address);
  if (!inbox) return c.json({ address, messages: [] });

  const messages = await getMessages(c.env.DB, address);
  return c.json({
    success: true,
    address,
    isLocked: Boolean(inbox.is_locked),
    count: messages.length,
    messages: messages.map((m) => ({
      id: m.id,
      from_address: m.from_address,
      subject: m.subject,
      snippet: m.body ? m.body.slice(0, 100) : '',
      otp_code: m.otp_code,
      received_at: m.received_at,
    })),
  });
});

// ---- DELETE & GET /api/inboxes/:address/messages/:id/delete ----
const deleteMessageHandler = async (c: any) => {
  const id = c.req.param('id');
  const success = await deleteMessage(c.env.DB, id);
  return c.json({ success });
};
api.delete('/inboxes/:address/messages/:id', deleteMessageHandler);
api.get('/inboxes/:address/messages/:id/delete', deleteMessageHandler);

// ---- GET /api/otp/:address (Instant Bot OTP Extractor - Clean & Lightweight) ----
const getOtpHandler = async (c: any) => {
  const address = decodeURIComponent(c.req.param('address') || c.req.query('address') || c.req.query('email') || '').toLowerCase().trim();
  if (!address) {
    return c.json({ success: false, error: 'Address is required (?address=user@zallpyx.xyz)' }, 400);
  }

  const inbox = await getInbox(c.env.DB, address);
  if (!inbox) {
    return c.json({ success: false, address, has_otp: false, otp: null, message: 'Inbox belum terdaftar' }, 404);
  }

  // Check PIN if locked
  if (inbox.is_locked) {
    const sid = getSessionId(c);
    const isOwner = sid && inbox.owner_session_id === sid;
    const isLinked = sid ? await isInboxInSession(c.env.DB, sid, address) : false;
    const providedPin = c.req.header('x-inbox-pin') || c.req.query('pin');
    let pinVerified = false;
    if (providedPin) {
      pinVerified = await verifyInboxPin(c.env.DB, address, String(providedPin).trim());
    }
    if (!isOwner && !isLinked && !pinVerified) {
      return c.json({ success: false, error: 'INBOX_LOCKED', requiresPin: true, message: 'Inbox dilindungi PIN.' }, 403);
    }
  }

  const messages = await getMessages(c.env.DB, address);
  if (messages.length === 0) {
    return c.json({
      success: true,
      address,
      has_otp: false,
      otp: null,
      message: 'Belum ada email yang masuk',
    });
  }

  const msgWithOtp = messages.find((m) => m.otp_code) || messages[0];
  const otp = msgWithOtp.otp_code || null;

  if (c.req.query('raw') === '1' || c.req.query('format') === 'text') {
    return new Response(otp || '', {
      headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
    });
  }

  return c.json({
    success: true,
    address,
    has_otp: Boolean(otp),
    otp: otp,
    from: msgWithOtp.from_address,
    subject: msgWithOtp.subject,
    received_at: msgWithOtp.received_at,
  });
};

api.get('/otp/:address', getOtpHandler);
api.get('/otp', getOtpHandler);

export default api;
