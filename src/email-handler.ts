import PostalMime from 'postal-mime';
import type { D1Database, ForwardableEmailMessage } from '@cloudflare/workers-types';
import { createInbox, inboxExists, insertMessage } from './db/queries';
import { extractOtpCode } from './utils/crypto';

export interface EmailHandlerEnv {
  DB: D1Database;
  MAIL_DOMAIN?: string;
}

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

  console.log(`[RZero Mail] Inbound email from=${from} to=${to}`);

  try {
    const rawStream = message.raw;
    const parser = new PostalMime();
    const parsed = await parser.parse(rawStream);

    const subject = parsed.subject || '(no subject)';
    const textBody = parsed.text?.trim() || '';
    const htmlBody = parsed.html?.trim() || '';
    const plainFallback = textBody || htmlBody.replace(/<[^>]+>/g, ' ').trim() || '';

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
