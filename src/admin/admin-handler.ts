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
  getSenderStats,
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

interface ProviderRule {
  name: string;
  category: string;
  patterns: (string | RegExp)[];
}

const KNOWN_PROVIDERS: ProviderRule[] = [
  {
    name: 'Alight Motion',
    category: 'Creative / Video',
    patterns: [/alight/i, /alight-creative/i, /alightcreative/i, /alightmotion/i],
  },
  {
    name: 'Canva',
    category: 'Design & Media',
    patterns: [/canva\.com/i],
  },
  {
    name: 'Discord',
    category: 'Community & Gaming',
    patterns: [/discord/i],
  },
  {
    name: 'Google / Gmail',
    category: 'Tech & OAuth',
    patterns: [/google\.com/i, /gmail\.com/i],
  },
  {
    name: 'Shopee',
    category: 'E-Commerce',
    patterns: [/shopee/i],
  },
  {
    name: 'TikTok',
    category: 'Social Media',
    patterns: [/tiktok/i, /bytedance/i],
  },
  {
    name: 'Telegram',
    category: 'Messaging',
    patterns: [/telegram/i],
  },
  {
    name: 'Instagram / Meta',
    category: 'Social Media',
    patterns: [/instagram\.com/i, /facebookmail\.com/i, /meta\.com/i, /facebook\.com/i],
  },
  {
    name: 'X / Twitter',
    category: 'Social Media',
    patterns: [/twitter\.com/i, /x\.com/i],
  },
  {
    name: 'Steam / Valve',
    category: 'Gaming',
    patterns: [/steampowered\.com/i, /valvesoftware\.com/i],
  },
  {
    name: 'Netflix',
    category: 'Streaming',
    patterns: [/netflix\.com/i],
  },
  {
    name: 'Spotify',
    category: 'Music',
    patterns: [/spotify\.com/i],
  },
  {
    name: 'GitHub',
    category: 'Developer Platform',
    patterns: [/github\.com/i],
  },
  {
    name: 'Microsoft / Outlook',
    category: 'Office & Email',
    patterns: [/microsoft\.com/i, /outlook\.com/i, /live\.com/i, /hotmail\.com/i],
  },
  {
    name: 'Amazon / AWS',
    category: 'Cloud & Commerce',
    patterns: [/amazon\.com/i, /amazonses\.com/i],
  },
  {
    name: 'OpenAI / ChatGPT',
    category: 'Artificial Intelligence',
    patterns: [/openai\.com/i, /chatgpt\.com/i],
  },
  {
    name: 'Apple / iCloud',
    category: 'Tech & ID',
    patterns: [/apple\.com/i, /icloud\.com/i],
  },
  {
    name: 'Roblox',
    category: 'Gaming',
    patterns: [/roblox\.com/i],
  },
  {
    name: 'Moonton / MLBB',
    category: 'Gaming',
    patterns: [/moonton\.com/i, /mobilelegends\.com/i],
  },
  {
    name: 'Tokopedia',
    category: 'E-Commerce',
    patterns: [/tokopedia\.com/i],
  },
  {
    name: 'Gojek / GoTo',
    category: 'Fintech & Ride',
    patterns: [/gojek\.com/i, /goto\.com/i],
  },
  {
    name: 'DANA',
    category: 'Fintech & Wallet',
    patterns: [/dana\.id/i],
  },
  {
    name: 'Grab',
    category: 'Superapp',
    patterns: [/grab\.com/i],
  },
  {
    name: 'PayPal',
    category: 'Fintech / Payment',
    patterns: [/paypal\.com/i],
  },
  {
    name: 'deSEC DNS',
    category: 'DNS / Infra',
    patterns: [/desec\.io/i],
  },
  {
    name: 'ClouDNS',
    category: 'DNS / Infra',
    patterns: [/cloudns\.net/i],
  },
  {
    name: 'YDNS',
    category: 'DNS / Infra',
    patterns: [/ydns\.io/i],
  },
  {
    name: 'FreeDNS / Afraid',
    category: 'DNS / Infra',
    patterns: [/afraid\.org/i],
  },
  {
    name: 'Cloudflare',
    category: 'Cloud / Edge',
    patterns: [/cloudflare\.com/i],
  },
  {
    name: 'Pinterest',
    category: 'Social Media',
    patterns: [/pinterest\.com/i],
  },
  {
    name: 'Reddit',
    category: 'Social Community',
    patterns: [/reddit\.com/i],
  },
  {
    name: 'Twitch',
    category: 'Livestreaming',
    patterns: [/twitch\.tv/i],
  },
  {
    name: 'Epic Games',
    category: 'Gaming',
    patterns: [/epicgames\.com/i],
  },
  {
    name: 'Riot Games',
    category: 'Gaming',
    patterns: [/riotgames\.com/i],
  },
  {
    name: 'Yahoo',
    category: 'Email & Portal',
    patterns: [/yahoo\.com/i],
  },
];

export function buildProviderLeaderboard(rawSenders: { from_address: string; count: number }[]) {
  let totalEmails = 0;
  const providerMap = new Map<string, {
    name: string;
    category: string;
    count: number;
    senders: { address: string; count: number }[];
  }>();

  const otherSendersMap = new Map<string, { address: string; domain: string; count: number }>();
  let otherCount = 0;

  for (const item of rawSenders) {
    const rawAddr = (item.from_address || '').trim();
    if (!rawAddr) continue;
    const count = Number(item.count) || 0;
    totalEmails += count;

    // Clean address (remove display name <email@domain.com>)
    const match = rawAddr.match(/<([^>]+)>/);
    const cleanAddr = (match ? match[1] : rawAddr).trim().toLowerCase();
    const parts = cleanAddr.split('@');
    const domain = parts.length > 1 ? parts[parts.length - 1] : cleanAddr;

    let matched = false;
    for (const prov of KNOWN_PROVIDERS) {
      const isMatch = prov.patterns.some((pat) =>
        typeof pat === 'string' ? cleanAddr.includes(pat) : pat.test(cleanAddr)
      );
      if (isMatch) {
        if (!providerMap.has(prov.name)) {
          providerMap.set(prov.name, {
            name: prov.name,
            category: prov.category,
            count: 0,
            senders: [],
          });
        }
        const p = providerMap.get(prov.name)!;
        p.count += count;
        p.senders.push({ address: cleanAddr, count });
        matched = true;
        break;
      }
    }

    if (!matched) {
      otherCount += count;
      if (otherSendersMap.has(cleanAddr)) {
        otherSendersMap.get(cleanAddr)!.count += count;
      } else {
        otherSendersMap.set(cleanAddr, { address: cleanAddr, domain, count });
      }
    }
  }

  // Format providers sorted descending by count
  const providers = Array.from(providerMap.values())
    .map((p) => ({
      name: p.name,
      category: p.category,
      count: p.count,
      percentage: totalEmails > 0 ? Number(((p.count / totalEmails) * 100).toFixed(1)) : 0,
      senders: p.senders.sort((a, b) => b.count - a.count),
    }))
    .sort((a, b) => b.count - a.count);

  // Format other senders sorted descending by count
  const otherSenders = Array.from(otherSendersMap.values())
    .map((s) => ({
      address: s.address,
      domain: s.domain,
      count: s.count,
      percentage: totalEmails > 0 ? Number(((s.count / totalEmails) * 100).toFixed(1)) : 0,
    }))
    .sort((a, b) => b.count - a.count);

  const totalKnown = totalEmails - otherCount;

  return {
    total_emails: totalEmails,
    total_known: totalKnown,
    total_other: otherCount,
    providers,
    other: {
      name: 'Other',
      count: otherCount,
      percentage: totalEmails > 0 ? Number(((otherCount / totalEmails) * 100).toFixed(1)) : 0,
      senders: otherSenders,
    },
  };
}

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
  const adminSecret = env.ADMIN_SECRET || 'default_jwt_secret_salt_please_change';
  const expectedUser = env.ADMIN_USERNAME || 'ren';
  const expectedPass = env.ADMIN_PASSWORD || 'change_this_admin_password';
  const expectedV2l = env.ADMIN_V2L_KEY || 'change_this_secondary_key';

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
    const [stats, domains, logs, rawSenders] = await Promise.all([
      getTrafficStats(env.DB),
      getAllDomains(env.DB),
      getTrafficLogs(env.DB, 50),
      getSenderStats(env.DB),
    ]);

    const leaderboard = buildProviderLeaderboard(rawSenders);

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
        leaderboard,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  // GET LEADERBOARD (PROVIDER RANKINGS)
  if (action === 'get_leaderboard') {
    const rawSenders = await getSenderStats(env.DB);
    const leaderboard = buildProviderLeaderboard(rawSenders);
    return new Response(JSON.stringify({ success: true, leaderboard }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
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

  // HELPER: Dual-DoH MX Resolution (Cloudflare + Google fallback)
  async function resolveDomainMx(dom: string): Promise<{
    live: boolean;
    records: string[];
    cfMxRecords: string[];
    cfMxCount: number;
    speedRating: 'turbo' | 'normal' | 'none';
    speedLabel: string;
    latencyMs: number;
  }> {
    const start = Date.now();
    let records: string[] = [];

    // 1. Try Cloudflare DoH first
    try {
      const cfUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(dom)}&type=MX`;
      const res = await fetch(cfUrl, { headers: { Accept: 'application/dns-json' } });
      if (res.ok) {
        const data: any = await res.json();
        records = (data.Answer || []).map((ans: any) => String(ans.data || '').trim());
      }
    } catch {}

    // 2. Fallback to Google DoH if Cloudflare had no answers or timed out
    if (records.length === 0) {
      try {
        const googleUrl = `https://dns.google/resolve?name=${encodeURIComponent(dom)}&type=MX`;
        const res = await fetch(googleUrl, { headers: { Accept: 'application/dns-json' } });
        if (res.ok) {
          const data: any = await res.json();
          records = (data.Answer || []).map((ans: any) => String(ans.data || '').trim());
        }
      } catch {}
    }

    const latencyMs = Date.now() - start;
    const cfMxRecords = records.filter((r: string) => /route[1-3]\.mx\.cloudflare\.net/i.test(r));
    const hasCfMx = cfMxRecords.length > 0;
    const cfMxCount = cfMxRecords.length;

    const speedRating = cfMxCount >= 3 ? 'turbo' : (cfMxCount >= 1 ? 'normal' : 'none');
    const speedLabel = cfMxCount >= 3
      ? 'Turbo (3/3 MX Aktif — Kecepatan & Redundansi Maksimal)'
      : (cfMxCount >= 1
        ? `Aktif (${cfMxCount}/3 MX — Pasang MX 2 & 3 opsional biar makin kenceng)`
        : (records.length > 0
          ? `Terdeteksi ${records.length} MX non-Cloudflare (Arahkan ke route1/2/3.mx.cloudflare.net)`
          : 'Belum Terpasang (Email tidak akan masuk)'));

    return {
      live: hasCfMx,
      records,
      cfMxRecords,
      cfMxCount,
      speedRating,
      speedLabel,
      latencyMs,
    };
  }

  // ADD DOMAIN
  if (action === 'add_domain') {
    let domain = (body.domain || '').trim().toLowerCase();
    // Sanitize: strip http/https, leading @, slashes
    domain = domain.replace(/^https?:\/\//i, '').replace(/^@/, '').replace(/\/.*$/, '').trim();

    const isDefault = Boolean(body.is_default);

    if (!domain || !domain.includes('.') || domain.length < 3) {
      return new Response(JSON.stringify({ success: false, error: 'Format domain tidak valid' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Determine suggested host for DNS setup (root = @, subdomain = prefix)
    const parts = domain.split('.');
    const multiPartTlds = ['co.id', 'biz.id', 'web.id', 'my.id', 'ac.id', 'sch.id', 'go.id', 'or.id', 'v6.rocks', 'v6.army', 'v6.navy', 'dns.army', 'dns.navy'];
    const endsWithMultiPart = multiPartTlds.some(tld => domain.endsWith('.' + tld));
    const isSubdomain = endsWithMultiPart ? parts.length > 3 : parts.length > 2;
    const suggestedHost = isSubdomain ? parts[0] : '@';

    // Check MX immediately via Dual-DoH
    const mxResult = await resolveDomainMx(domain);

    // Add with is_active = 1 if CF MX detected, else 0 (pending)
    await addDomain(env.DB, domain, isDefault);
    if (!mxResult.live) {
      await toggleDomainStatus(env.DB, domain, false).catch(() => {});
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: mxResult.live
          ? `Domain ${domain} berhasil ditambahkan dan langsung AKTIF (MX terdeteksi)!`
          : `Domain ${domain} berhasil ditambahkan (Status PENDING). Silakan pasang 3 MX di bawah.`,
        domain,
        is_active: mxResult.live,
        is_subdomain: isSubdomain,
        suggested_host: suggestedHost,
        mxRecords: mxResult.records,
        cfMxRecords: mxResult.cfMxRecords,
        cfMxCount: mxResult.cfMxCount,
        speedLabel: mxResult.speedLabel,
        setupGuide: {
          type: 'MX',
          host: suggestedHost,
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
    let domain = (body.domain || '').trim().toLowerCase();
    domain = domain.replace(/^https?:\/\//i, '').replace(/^@/, '').replace(/\/.*$/, '').trim();
    const ok = await deleteDomain(env.DB, domain);
    return new Response(JSON.stringify({ success: ok, message: `Domain ${domain} dihapus` }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // TOGGLE DOMAIN (MANUAL OVERRIDE ADMIN)
  if (action === 'toggle_domain') {
    let domain = (body.domain || '').trim().toLowerCase();
    domain = domain.replace(/^https?:\/\//i, '').replace(/^@/, '').replace(/\/.*$/, '').trim();
    const isActive = Boolean(body.is_active);
    const ok = await toggleDomainStatus(env.DB, domain, isActive);
    return new Response(JSON.stringify({
      success: ok,
      domain,
      is_active: isActive,
      message: `Domain ${domain} berhasil di-${isActive ? 'aktifkan' : 'nonaktifkan'}!`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // CHECK DOMAIN LIVE / MX (Dual-DoH Resolution + Auto-Activate if MX exists)
  if (action === 'check_domain_live' || action === 'check_domain_mx') {
    let domain = (body.domain || '').trim().toLowerCase();
    domain = domain.replace(/^https?:\/\//i, '').replace(/^@/, '').replace(/\/.*$/, '').trim();

    try {
      const mxResult = await resolveDomainMx(domain);

      // Strict validation: Only auto-activate if MX explicitly points to Cloudflare Email Routing!
      if (mxResult.live) {
        const unroutedDomains = ['apkprem.v6.rocks', 'emailprem.v6.army', 'inboxfree.dns.army', 'inboxvip.dns.navy', 'mailprem.v6.navy', 'rzeromail.dynv6.net'];
        if (!unroutedDomains.includes(domain)) {
          await toggleDomainStatus(env.DB, domain, true).catch(() => {});
        }
      }

      return new Response(
        JSON.stringify({
          success: true,
          domain,
          live: mxResult.live,
          active: mxResult.live,
          cfMxCount: mxResult.cfMxCount,
          cfMxRecords: mxResult.cfMxRecords,
          speedRating: mxResult.speedRating,
          speedLabel: mxResult.speedLabel,
          records: mxResult.records,
          latencyMs: mxResult.latencyMs,
          autoActivated: mxResult.live,
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
