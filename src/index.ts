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

// Baseline security headers applied to every response.
//
// The CSP is REPORT-ONLY on purpose: the frontend relies on inline styles and
// an inline script block, and frames email bodies via `srcdoc`. Enforcing a
// policy before validating those cases in a real browser would risk breaking
// the email viewer, so this ships as a starting point to observe violations
// first. Enforce it once the reports come back clean.
const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy-Report-Only': [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data: https:",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    "script-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
  ].join('; '),
};

function withSecurityHeaders(res: Response): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(k)) headers.set(k, v);
  }
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
}

const worker = {
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
RZero Mail (https://rzmail.my.id/) is a high-speed, serverless, disposable temporary email (temp mail) platform and developer API. It offers free temporary and permanent email inboxes across its verified active domains (see the domains endpoint for the current list) powered by Cloudflare Anycast 3-MX Email Routing.

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
- \`GET https://rzmail.my.id/api/domains\` : List every verified active domain.
- \`POST https://rzmail.my.id/api/inboxes/:address/lock\` : Lock inbox with PIN (JSON body \`{"pin":"123456"}\` + \`x-session-id\` header).
- \`DELETE https://rzmail.my.id/api/inboxes/:address\` : Delete/unlink inbox from session (\`x-session-id\` header).

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

    // 3. Homepage (/)
    if (url.pathname === '/') {
      if (env.ASSETS) {
        const homeReq = new Request(new URL('/index.html', request.url), request);
        const homeRes = await env.ASSETS.fetch(homeReq);
        const headers = new Headers(homeRes.headers);
        headers.set('Content-Type', 'text/html; charset=UTF-8');
        return new Response(homeRes.body, {
          status: 200,
          headers,
        });
      }
    }

    // 4. API Documentation (/docs, /docs/, /api/docs, /docs.html)
    if (url.pathname === '/docs' || url.pathname === '/docs/' || url.pathname === '/docs.html') {
      if (env.ASSETS) {
        const docsReq = new Request(new URL('/docs.html', request.url), request);
        const docsRes = await env.ASSETS.fetch(docsReq);
        const headers = new Headers(docsRes.headers);
        headers.set('Content-Type', 'text/html; charset=UTF-8');
        return new Response(docsRes.body, {
          status: 200,
          headers,
        });
      }
      return Response.redirect(new URL('/docs.html', request.url).toString(), 302);
    }
    if (url.pathname === '/api/docs' || url.pathname === '/api/docs/') {
      return Response.redirect(new URL('/docs', request.url).toString(), 302);
    }

    // 5. Admin Web Dashboard (Strict No-Cache, zero-redirect direct serve)
    if (url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin.html') {
      if (env.ASSETS) {
        const adminReq = new Request(new URL('/admin.html', request.url), request);
        const assetRes = await env.ASSETS.fetch(adminReq);
        const headers = new Headers(assetRes.headers);
        headers.set('Content-Type', 'text/html; charset=UTF-8');
        headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
        headers.set('Pragma', 'no-cache');
        headers.set('Expires', '0');
        headers.set('CDN-Cache-Control', 'no-store');
        headers.set('Cloudflare-CDN-Cache-Control', 'no-store');
        return new Response(assetRes.body, {
          status: 200,
          headers,
        });
      }
      return Response.redirect(new URL('/admin.html', request.url).toString(), 302);
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

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return withSecurityHeaders(await worker.fetch(request, env, ctx));
  },
  email: worker.email,
};
