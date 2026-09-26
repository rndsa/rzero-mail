import type { D1Database } from '@cloudflare/workers-types';
import {
  getAllDomains,
  addDomain,
  deleteDomain,
  toggleDomainStatus,
  getTrafficLogs,
  getTrafficStats,
  getAllAds,
  saveAd,
} from '../db/queries';
import {
  parseCookies,
  signAdminToken,
  verifyAdminToken,
} from '../utils/crypto';

export interface AdminEnv {
  DB: D1Database;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  ADMIN_V2L_KEY?: string;
  ADMIN_SECRET?: string;
}

const COOKIE_NAME = 'rzero_admin_session';

export async function handleAdminAction(request: Request, env: AdminEnv): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method Not Allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const action = body.action;
  const adminSecret = env.ADMIN_SECRET || 'rzero_hmac_ren_secret_salt_2026_x77';
  const expectedUser = env.ADMIN_USERNAME || 'ren';
  const expectedPass = env.ADMIN_PASSWORD || 'a3fd356ca1';
  const expectedV2l = env.ADMIN_V2L_KEY || 'gdnOMK029#$$$93';

  // ========================================================
  // STEP-BY-STEP AUTHENTICATION:
  // Step 1: User + Pass  -> Returns temp challenge token
  // Step 2: 3DS / V2L Key -> Issues persistent session cookie
  // ========================================================

  if (action === 'login_step1') {
    const user = (body.username || '').trim();
    const pass = (body.password || '').trim();

    if (user !== expectedUser || pass !== expectedPass) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Username atau password salah',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Generate short-lived temp token (valid 5 minutes) for step 2
    const tempChallenge = await signAdminToken(`challenge:${user}`, adminSecret, 5 * 60 * 1000);
    return new Response(
      JSON.stringify({
        success: true,
        step: 2,
        user,
        temp_token: tempChallenge,
        challenge_token: tempChallenge,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  if (action === 'login_step2') {
    const tempToken = (body.temp_token || body.challenge_token || '').trim();
    const v2l = (body.v2l || body.v2l_key || body.key || body['3ds'] || '').trim();

    const check = await verifyAdminToken(tempToken, adminSecret);
    if (!check.valid || !check.user?.startsWith('challenge:')) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Authentication session expired. Please re-enter username & password.',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    if (v2l !== expectedV2l) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Invalid 3DS / Secondary Security Key',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    const realUser = check.user.replace('challenge:', '');
    const sessionToken = await signAdminToken(realUser, adminSecret);
    const cookieHeader = `${COOKIE_NAME}=${encodeURIComponent(sessionToken)}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=2592000`;

    return new Response(
      JSON.stringify({
        success: true,
        user: realUser,
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': cookieHeader,
        },
      }
    );
  }

  // LOGOUT
  if (action === 'logout') {
    const clearCookie = `${COOKIE_NAME}=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
    return new Response(JSON.stringify({ success: true, message: 'Logged out' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': clearCookie,
      },
    });
  }

  // ALL OTHER ACTIONS REQUIRE VALID COOKIE AUTH
  const cookieHeader = request.headers.get('Cookie');
  const cookies = parseCookies(cookieHeader);
  const sessionToken = cookies[COOKIE_NAME];

  const authCheck = await verifyAdminToken(sessionToken, adminSecret);
  if (!authCheck.valid) {
    return new Response(
      JSON.stringify({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Admin session expired or invalid cookie',
      }),
      {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  // CHECK AUTH
  if (action === 'check_auth') {
    return new Response(JSON.stringify({ success: true, user: authCheck.user }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // GET DASHBOARD (ALL-IN-ONE FOR ADMIN CONSOLE)
  if (action === 'get_dashboard') {
    const [stats, domains, logs] = await Promise.all([
      getTrafficStats(env.DB),
      getAllDomains(env.DB),
      getTrafficLogs(env.DB, 50),
    ]);

    return new Response(
      JSON.stringify({
        success: true,
        metrics: {
          active_domains: stats.activeDomainsCount,
          total_messages: stats.totalEmailsAllTime,
          total_inboxes: stats.totalInboxesAllTime,
          locked_inboxes: stats.totalInboxesLocked,
        },
        stats,
        domains,
        logs,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  // GET STATS
  if (action === 'get_stats') {
    const stats = await getTrafficStats(env.DB);
    return new Response(JSON.stringify({ success: true, stats }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // GET ADS (MONETIZATION)
  if (action === 'get_ads') {
    const ads = await getAllAds(env.DB);
    return new Response(JSON.stringify({ success: true, ads }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // SAVE AD (MONETIZATION)
  if (action === 'save_ad') {
    const adData = body.ad;
    if (!adData || !adData.slot_name) {
      return new Response(JSON.stringify({ success: false, error: 'Data iklan tidak lengkap' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    await saveAd(env.DB, adData);
    return new Response(JSON.stringify({ success: true, message: `Iklan ${adData.slot_name} berhasil disimpan!` }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // GET TRAFFIC LOGS
  if (action === 'get_traffic') {
    const limit = Math.min(parseInt(body.limit || '50', 10), 100);
    const logs = await getTrafficLogs(env.DB, limit);
    return new Response(JSON.stringify({ success: true, logs }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // LIST DOMAINS
  if (action === 'list_domains') {
    const domains = await getAllDomains(env.DB);
    return new Response(JSON.stringify({ success: true, domains }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // ADD DOMAIN
  if (action === 'add_domain') {
    const domain = (body.domain || '').trim().toLowerCase();
    const isDefault = Boolean(body.is_default);

    if (!domain || !domain.includes('.')) {
      return new Response(JSON.stringify({ success: false, error: 'Format domain tidak valid' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check MX immediately via DoH
    let isMxLive = false;
    let mxRecords: string[] = [];
    try {
      const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`;
      const res = await fetch(dohUrl, { headers: { Accept: 'application/dns-json' } });
      if (res.ok) {
        const data: any = await res.json();
        mxRecords = (data.Answer || []).map((ans: any) => ans.data);
        isMxLive = mxRecords.length > 0;
      }
    } catch {}

    // Add with is_active = 1 if MX detected, else 0 (pending)
    await addDomain(env.DB, domain, isDefault);
    if (!isMxLive) {
      await toggleDomainStatus(env.DB, domain, false).catch(() => {});
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: `Domain ${domain} berhasil ditambahkan!`,
        domain,
        is_active: isMxLive,
        mxRecords,
        setupGuide: {
          type: 'MX',
          host: '@',
          target: 'route1.mx.cloudflare.net',
          priority: 10,
        },
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  // DELETE DOMAIN
  if (action === 'delete_domain') {
    const domain = (body.domain || '').trim().toLowerCase();
    const ok = await deleteDomain(env.DB, domain);
    return new Response(JSON.stringify({ success: ok, message: `Domain ${domain} dihapus` }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // TOGGLE DOMAIN
  if (action === 'toggle_domain') {
    const domain = (body.domain || '').trim().toLowerCase();
    const isActive = Boolean(body.is_active);
    const ok = await toggleDomainStatus(env.DB, domain, isActive);
    return new Response(JSON.stringify({ success: ok, isActive }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // CHECK DOMAIN LIVE / MX (DoH MX Resolution + Auto-Activate if MX exists)
  if (action === 'check_domain_live' || action === 'check_domain_mx') {
    const domain = (body.domain || '').trim().toLowerCase();
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`;

    const start = Date.now();
    try {
      const res = await fetch(dohUrl, {
        headers: { Accept: 'application/dns-json' },
      });
      const latency = Date.now() - start;

      if (!res.ok) {
        return new Response(
          JSON.stringify({ success: false, error: `DNS query failed (${res.status})` }),
          { status: 502, headers: { 'Content-Type': 'application/json' } }
        );
      }

      const data: any = await res.json();
      const records = (data.Answer || []).map((ans: any) => ans.data);
      const cfMxRecords = records.filter((r: string) => /route[1-3]\.mx\.cloudflare\.net/i.test(r));
      const hasCfMx = cfMxRecords.length > 0;
      const cfMxCount = cfMxRecords.length;

      // Strict validation: Only auto-activate if MX explicitly points to Cloudflare Email Routing!
      // Unverified non-CF MX or external unconfigured zones will NOT be auto-activated.
      if (hasCfMx) {
        // Double check against known unverified list to avoid activating unrouted third-party domains
        const unroutedDomains = ['apkprem.v6.rocks', 'emailprem.v6.army', 'inboxfree.dns.army', 'inboxvip.dns.navy', 'mailprem.v6.navy', 'rzeromail.dynv6.net'];
        if (!unroutedDomains.includes(domain)) {
          await toggleDomainStatus(env.DB, domain, true).catch(() => {});
        }
      }

      const speedRating = cfMxCount >= 3 ? 'turbo' : (cfMxCount >= 1 ? 'normal' : 'none');
      const speedLabel = cfMxCount >= 3
        ? '⚡ Turbo (3/3 MX Aktif — Kecepatan & Redundansi Maksimal)'
        : (cfMxCount >= 1
          ? `✅ Aktif (${cfMxCount}/3 MX — Pasang MX 2 & 3 opsional biar makin kenceng)`
          : '❌ Belum Terpasang (Email tidak akan masuk)');

      return new Response(
        JSON.stringify({
          success: true,
          domain,
          live: hasCfMx,
          cfMxCount,
          cfMxRecords,
          speedRating,
          speedLabel,
          records,
          latencyMs: latency,
          autoActivated: hasCfMx && !['apkprem.v6.rocks', 'emailprem.v6.army', 'inboxfree.dns.army', 'inboxvip.dns.navy', 'mailprem.v6.navy', 'rzeromail.dynv6.net'].includes(domain),
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    } catch (err: any) {
      return new Response(
        JSON.stringify({ success: false, error: err.message || 'DNS resolution failed' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }

  return new Response(JSON.stringify({ error: 'Unknown action' }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' },
  });
}
