import PostalMime from 'postal-mime';
import type { D1Database, ForwardableEmailMessage } from '@cloudflare/workers-types';
import { createInbox, inboxExists, insertMessage } from './db/queries';
import { extractOtpCode } from './utils/crypto';

export interface EmailHandlerEnv {
  DB: D1Database;
  MAIL_DOMAIN?: string;
}

/**
 * Characters we accept in an inbound recipient.
 *
 * The local part is fully attacker-controlled: Cloudflare Email Routing accepts
 * mail for any local part on the domain, so whatever arrives here becomes an
 * inbox address. That address is rendered by the web client, which means an
 * exotic local part could carry markup into a page that does not escape it.
 * The inbox creation API already sanitises its input — this path had no check
 * at all, so the same class of address could be planted by sending an email.
 *
 * Anything outside this set is dropped and logged rather than stored, so a
 * mailbox is never created under an address the rest of the app does not
 * expect. The charset covers ordinary addresses, including `+` tagging.
 */
const INBOUND_ADDRESS_PATTERN = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/;

/**
 * Handles inbound email via Cloudflare Email Worker for RZero Mail.
 * Called for every email received at any supported domain address.
 */
export async function handleEmail(
  message: ForwardableEmailMessage,
  env: EmailHandlerEnv
): Promise<void> {
  const to = message.to.toLowerCase();
  const from = message.from.toLowerCase();

  if (!INBOUND_ADDRESS_PATTERN.test(to)) {
    console.warn(
      `[RZero Mail] Dropped mail to unsupported address: ${to.slice(0, 80)}`
    );
    return;
  }

  console.log(`[RZero Mail] Inbound email from=${from} to=${to}`);

  try {
    const rawStream = message.raw;
    const parser = new PostalMime();
    const parsed = await parser.parse(rawStream);

    const subject = parsed.subject || '(no subject)';
    // Defense against unbounded email body ingestion (DoS / storage exhaustion)
    const MAX_BODY_CHARS = 250000;
    const textBody = (parsed.text?.trim() || '').slice(0, MAX_BODY_CHARS);
    const htmlBody = (parsed.html?.trim() || '').slice(0, MAX_BODY_CHARS);
    const plainFallback = (textBody || htmlBody.replace(/<[^>]+>/g, ' ').trim() || '').slice(0, MAX_BODY_CHARS);

    // Automatically detect and extract 4-8 digit OTP code
    const otpCode = extractOtpCode(subject, textBody, htmlBody);
    if (otpCode) {
      console.log(`[RZero Mail] Detected OTP code: ${otpCode} for ${to}`);
    }

    const db = env.DB;

    // Auto-create inbox if it does not exist yet
    if (!(await inboxExists(db, to))) {
      await createInbox(db, to);
      console.log(`[RZero Mail] Created new inbox: ${to}`);
    }

    // Store the message with rich HTML and extracted OTP
    const msgId = `msg_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
    await insertMessage(db, {
      id: msgId,
      inbox_address: to,
      from_address: from,
      subject,
      body: plainFallback,
      body_html: htmlBody,
      otp_code: otpCode,
    });

    // Record inbound traffic event
    await db
      .prepare(
        `INSERT INTO traffic_logs (ip, method, path, status, user_agent, duration_ms)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(from.slice(0, 45), 'EMAIL', `/inbox/${to}`, 200, 'Cloudflare-Email-Worker', 0)
      .run()
      .catch(() => {});

    console.log(`[RZero Mail] Stored message ${msgId} for ${to}`);
  } catch (err) {
    console.error(`[RZero Mail] Failed to process email for ${to}:`, err);
  }
}
