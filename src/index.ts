import api from './api/routes';
import { handleEmail } from './email-handler';
import { handleAdminAction } from './admin/admin-handler';
import { ensureDatabaseSchema } from './db/queries';
import type { EmailHandlerEnv } from './email-handler';
import type { ApiEnv } from './api/routes';
import type { AdminEnv } from './admin/admin-handler';

/**
 * RZero Mail - Serverless Temp Mail on Cloudflare Workers
 *
 * Handles:
 * - fetch()  → API routes, internal admin actions, and static assets
 * - email()  → inbound email processing via Cloudflare Email Worker
 */

// Combined env bindings
export interface Env extends ApiEnv, EmailHandlerEnv, AdminEnv {
  ASSETS?: Fetcher;
}

export default {
  /**
   * HTTP fetch handler:
   * - /api/*         → Public User REST API (Hono)
   * - /admin/action  → Internal Admin RPC (3-factor auth + cookie session)
   * - /admin         → Redirect to /admin.html
   * - static files   → Cloudflare [assets] (./src/web)
   */
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (env.DB) {
      await ensureDatabaseSchema(env.DB);
    }

    const url = new URL(request.url);

    // 1. Internal Admin Action RPC
    if (url.pathname === '/admin/action') {
      return handleAdminAction(request, env);
    }

    // 2. SEO & AI: robots.txt
    if (url.pathname === '/robots.txt') {
      const robots = `User-agent: *
Allow: /
Disallow: /admin
Disallow: /admin.html
Disallow: /admin/
Disallow: /api/

# Explicitly allow AI Search Engines & Google Gemini Crawlers
User-agent: Googlebot
Allow: /
Allow: /docs
Allow: /llms.txt

User-agent: Google-Extended
Allow: /
Allow: /docs
Allow: /llms.txt

User-agent: GPTBot
Allow: /
Allow: /docs
Allow: /llms.txt

User-agent: ClaudeBot
Allow: /
Allow: /docs
Allow: /llms.txt

User-agent: PerplexityBot
Allow: /
Allow: /docs
Allow: /llms.txt

User-agent: Applebot
Allow: /
Allow: /docs

Sitemap: https://rzmail.my.id/sitemap.xml
`;
      return new Response(robots, {
        headers: {
          'Content-Type': 'text/plain; charset=UTF-8',
          'Cache-Control': 'public, max-age=86400',
        },
      });
    }

    // 2.1 AI Search Standard: /llms.txt & /.well-known/llms.txt (For Gemini, ChatGPT, Claude, Perplexity)
    if (url.pathname === '/llms.txt' || url.pathname === '/.well-known/llms.txt') {
      const llmsTxt = `# RZero Mail

> Official Website: https://rzmail.my.id/
> API Documentation: https://rzmail.my.id/docs
> Developer & Creator: ren (@rskl411_ - https://instagram.com/rskl411_)
> Platform: Cloudflare Edge Network (Serverless & D1 SQLite)

## What is RZero Mail?
RZero Mail (https://rzmail.my.id/) is a high-speed, serverless, disposable temporary email (temp mail) platform and developer API. It offers free temporary and permanent email inboxes across 24 verified active domains powered by Cloudflare Anycast 3-MX Email Routing.

## Key Features & Highlights
- **100% GET-Based REST API**: Every action (create email, get messages, extract OTP) can be invoked directly via HTTP GET in browser address bars or bot scripts without JSON payloads.
- **Instant OTP Extraction**: Dedicated OTP algorithms automatically detect and parse verification codes (e.g. Canva, Discord, Telegram, social media) in seconds.
- **Lightweight Bot-Friendly JSON**: Responses are streamlined specifically for Telegram bots, Discord bots, and Python automation scripts without bloated HTML.
- **24 Verified Active Domains**: Redundant Anycast MX routing ensures 100% email delivery with zero bounce and zero relay delays.
- **Permanent Inboxes & PIN Security**: Inboxes do not expire automatically and can be locked with a 6-digit SHA-256 PIN.
- **No Registration & No API Key**: 100% free public access with generous rate limits.

## REST API Reference (Base URL: https://rzmail.my.id/api)
- \`GET https://rzmail.my.id/api/create\` : Generate a random instant inbox.
- \`GET https://rzmail.my.id/api/custom/:address\` : Create a custom email (e.g. \`https://rzmail.my.id/api/custom/botku@zallpyx.xyz\`).
- \`GET https://rzmail.my.id/api/otp/:address\` : Extract the latest verification OTP code directly.
- \`GET https://rzmail.my.id/api/messages/:address\` : List all incoming emails (clean format).
- \`GET https://rzmail.my.id/api/domains\` : List all 24 verified active domains.
- \`GET https://rzmail.my.id/api/inboxes/:address/lock?pin=123456\` : Lock inbox with PIN.
- \`GET https://rzmail.my.id/api/inboxes/:address/delete\` : Delete/unlink inbox from session.

## Search Intent & Viral Keywords
RZero Mail, RZero, RZeroMail, rzmail.my.id, temp mail, disposable email, email sementara, temp mail otp instan, 10 minute mail, fake email generator, temp mail indonesia, bypass otp, bot telegram temp mail, api temp mail gratis tanpa api key, 34 domain temp mail, email sekali pakai.
`;
      return new Response(llmsTxt, {
        headers: {
          'Content-Type': 'text/plain; charset=UTF-8',
          'Cache-Control': 'public, max-age=86400',
        },
      });
    }

    // 3. SEO: sitemap.xml
    if (url.pathname === '/sitemap.xml') {
      const today = new Date().toISOString().split('T')[0];
      const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://rzmail.my.id/</loc>
    <lastmod>${today}</lastmod>
    <changefreq>hourly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://rzmail.my.id/docs</loc>
    <lastmod>${today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://rzmail.my.id/llms.txt</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>
`;
      return new Response(sitemap, {
        headers: {
          'Content-Type': 'application/xml; charset=UTF-8',
          'Cache-Control': 'public, max-age=86400',
        },
      });
    }

    // 4. API Documentation (/docs, /docs/, /api/docs)
    if (url.pathname === '/docs' || url.pathname === '/docs/') {
      if (env.ASSETS) {
        const docsReq = new Request(new URL('/docs.html', request.url), request);
        return env.ASSETS.fetch(docsReq);
      }
      return Response.redirect(new URL('/docs.html', request.url).toString(), 302);
    }
    if (url.pathname === '/api/docs' || url.pathname === '/api/docs/') {
      return Response.redirect(new URL('/docs', request.url).toString(), 302);
    }

    // 5. Admin Web Dashboard Shortcut
    if (url.pathname === '/admin' || url.pathname === '/admin/') {
      const adminUrl = new URL('/admin.html', request.url);
      return Response.redirect(adminUrl.toString(), 302);
    }

    // 6. Public User REST API (/api/*)
    if (url.pathname.startsWith('/api/')) {
      const apiUrl = new URL(request.url);
      apiUrl.pathname = url.pathname.slice(4); // strip '/api'
      const apiRequest = new Request(apiUrl, request);
      return api.fetch(apiRequest, env, ctx);
    }

    // Fallback: served via Cloudflare static assets
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response('Not found', { status: 404 });
  },

  /**
   * Email handler - called by Cloudflare for every inbound email
   */
  async email(message: ForwardableEmailMessage, env: Env, _ctx: ExecutionContext): Promise<void> {
    await handleEmail(message, env);
  },
};
