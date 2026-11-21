'use strict';

/**
 * SplitWire Browser — Background Service Worker (Manifest V3)
 *
 * Supports:
 * 1. In-Browser Zero-File Mode (`browser`): Automatically discovers & live-probes
 *    European SOCKS5 servers right inside Chrome using parallel PAC probes — NO local files!
 * 2. Custom Proxy / VPN Mode (`custom`): User's own HTTPS / SOCKS5 / HTTP proxy — NO local files!
 * 3. Optional Local Driverless DPI Engine (`splitwire`): 127.0.0.1:8080 (full line speed).
 * 4. Optional Local ByeDPI / Cloudflare WARP SOCKS5 (`byedpi`): 127.0.0.1:1080 or :40000.
 */

const PLATFORM_DOMAINS = {
  discord: [
    'discord.com',
    'discord.gg',
    'discordapp.com',
    'discordapp.net',
    'discord.media',
    'discordcdn.com',
    'discordstatus.com',
    'dis.gd',
    'discord.co',
  ],
  roblox: [
    'roblox.com',
    'rbxcdn.com',
    'rbxinfra.net',
    'rbxtrk.com',
    'arkoselabs.com',
    'rbx.com',
  ],
  wattpad: [
    'wattpad.com',
    'w.tt',
  ],
};

// 10 distinct fast HTTPS probe endpoints so we can test 10 candidate SOCKS5 servers in parallel
const PROBE_ENDPOINTS = [
  { host: '1.1.1.1', url: 'https://1.1.1.1/cdn-cgi/trace' },
  { host: '1.0.0.1', url: 'https://1.0.0.1/cdn-cgi/trace' },
  { host: 'cp.cloudflare.com', url: 'https://cp.cloudflare.com/generate_204' },
  { host: 'one.one.one.one', url: 'https://one.one.one.one/cdn-cgi/trace' },
  { host: 'cloudflare-dns.com', url: 'https://cloudflare-dns.com/cdn-cgi/trace' },
  { host: 'connectivitycheck.gstatic.com', url: 'https://connectivitycheck.gstatic.com/generate_204' },
  { host: 'www.gstatic.com', url: 'https://www.gstatic.com/generate_204' },
  { host: 'clients3.google.com', url: 'https://clients3.google.com/generate_204' },
  { host: 'www.google.com', url: 'https://www.google.com/generate_204' },
  { host: 'detectportal.firefox.com', url: 'https://detectportal.firefox.com/canonical.html' },
];

// Closest European countries to Turkey (typically 25-75ms RTT)
const NEAR_EU_COUNTRIES = new Set([
  'BG', 'RO', 'GR', 'AT', 'HU', 'DE', 'PL', 'CZ', 'SK', 'RS', 'HR', 'NL', 'CH', 'FR', 'IT',
]);

const EU_COUNTRIES = new Set([
  ...NEAR_EU_COUNTRIES,
  'GB', 'SE', 'FI', 'BE', 'DK', 'NO', 'ES', 'IE', 'LU', 'SI',
]);

const DEFAULT_STATE = {
  connected: false,
  connectedAt: null,
  tunnelMode: 'split', // 'split' | 'full'
  engineMode: 'browser', // 'browser' | 'custom' | 'splitwire' | 'byedpi'
  browserRegion: 'eu', // 'eu' | 'DE' | 'NL' | 'all'
  browserServers: [], // [{ ip, port, country, city, latencyMs, verifiedAt }]
  activeServerIndex: 0,
  splitwirePort: 8080,
  splitwireControlPort: 8081,
  localSocksPort: 1080,
  customProxy: {
    scheme: 'HTTPS', // 'PROXY' | 'HTTPS' | 'SOCKS5'
    host: '',
    port: 443,
  },
  preset: 'auto',
  dohProvider: 'cloudflare',
  webrtcProtection: true,
  adblockEnabled: true,
  trackerBlockEnabled: true,
  adblockAllowlist: [],
  blockedCount: 0,
  autoConnectEnabled: false,
  autoConnected: false,
  phishingShieldEnabled: true,
  phishingAllowlist: [],
  customBlocklist: [],
  communityFilterEnabled: true,
  lastFilterUpdate: null,
  communityStats: { ads: 0, phishing: 0 },
  theme: 'dark',
  lang: 'tr',
  platforms: {
    discord: true,
    roblox: true,
    wattpad: true,
  },
  customDomains: [],
  exclusions: [
    'turkiye.gov.tr',
    'ziraatbank.com.tr',
    'garantibbva.com.tr',
    'isbank.com.tr',
    'akbank.com',
    'yapikredi.com.tr',
    'enpara.com',
    'gib.gov.tr',
  ],
};

const HEALTH_ALARM = 'splitwire-health-check';
const COMMUNITY_ALARM = 'splitwire-community-filter';
const IS_FIREFOX =
  typeof browser !== 'undefined' && Boolean(browser.proxy && browser.proxy.onRequest);

let isProbing = false;
let isAutoConnecting = false;
let autoDisconnectTimer = null;
let firefoxCachedState = null;
let firefoxProbeMap = null; // Map<host, ProxyInfo> active only during parallel server probes
let firefoxBypassForFetch = false;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function isPrivateHostJs(host) {
  if (!host || !host.includes('.')) return true;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
  if (host.startsWith('127.') || host.startsWith('10.') || host.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (host.endsWith('.local') || host.endsWith('.localhost')) return true;
  return false;
}

function matchesAnyHostJs(host, list) {
  for (let i = 0; i < list.length; i++) {
    const d = list[i];
    if (host === d || host.endsWith('.' + d)) return true;
  }
  return false;
}

function buildFirefoxProxyInfo(state) {
  switch (state.engineMode) {
    case 'browser': {
      const list = state.browserServers || [];
      if (list.length === 0) return { type: 'direct' };
      const start = (state.activeServerIndex || 0) % list.length;
      const chain = [];
      for (let i = 0; i < Math.min(3, list.length); i++) {
        const srv = list[(start + i) % list.length];
        if (srv && srv.ip && srv.port) {
          chain.push({ type: 'socks', host: srv.ip, port: Number(srv.port), proxyDNS: true });
        }
      }
      return chain.length > 0 ? chain : { type: 'direct' };
    }
    case 'byedpi':
      return [
        { type: 'socks', host: '127.0.0.1', port: Number(state.localSocksPort) || 1080, proxyDNS: true },
        { type: 'direct' },
      ];
    case 'custom': {
      const host = (state.customProxy.host || '').trim();
      const port = parseInt(state.customProxy.port, 10) || 443;
      if (!host) return { type: 'direct' };
      const scheme = state.customProxy.scheme || 'HTTPS';
      if (scheme === 'SOCKS5') return { type: 'socks', host, port, proxyDNS: true };
      if (scheme === 'PROXY') return { type: 'http', host, port };
      return { type: 'https', host, port };
    }
    case 'splitwire':
    default:
      return { type: 'http', host: '127.0.0.1', port: Number(state.splitwirePort) || 8080 };
  }
}

function resolveFirefoxProxyForUrl(urlStr, state) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (_) {
    return { type: 'direct' };
  }

  const host = parsed.hostname.toLowerCase();
  const proto = parsed.protocol.toLowerCase();

  // 1. Parallel server probe override (never disturbs other tabs)
  if (firefoxProbeMap && firefoxProbeMap.has(host)) {
    return firefoxProbeMap.get(host);
  }

  if (firefoxBypassForFetch || !state || !state.connected) {
    return { type: 'direct' };
  }

  if (isPrivateHostJs(host)) {
    return { type: 'direct' };
  }

  // Public in-browser servers: strictly HTTPS / WSS only (never plaintext HTTP)
  if (state.engineMode === 'browser' && proto !== 'https:' && proto !== 'wss:') {
    return { type: 'direct' };
  }

  if (state.tunnelMode === 'full') {
    const exclusions = (state.exclusions || []).map((d) => d.toLowerCase().trim()).filter(Boolean);
    if (matchesAnyHostJs(host, exclusions)) {
      return { type: 'direct' };
    }
    return buildFirefoxProxyInfo(state);
  }

  const splitDomains = getActiveSplitDomains(state);
  if (matchesAnyHostJs(host, splitDomains)) {
    return buildFirefoxProxyInfo(state);
  }
  return { type: 'direct' };
}

if (IS_FIREFOX) {
  browser.proxy.onRequest.addListener(
    (details) => {
      if (firefoxCachedState) {
        return resolveFirefoxProxyForUrl(details.url, firefoxCachedState);
      }
      return getState().then((st) => {
        firefoxCachedState = st;
        return resolveFirefoxProxyForUrl(details.url, st);
      });
    },
    { urls: ['<all_urls>'] }
  );
}

async function getState() {
  const stored = await chrome.storage.local.get('splitwireState');
  const saved = stored.splitwireState || {};
  // Migrate older 'warp' engineMode cleanly into 'byedpi' with port 40000
  let engineMode = saved.engineMode || DEFAULT_STATE.engineMode;
  let localSocksPort = saved.localSocksPort || DEFAULT_STATE.localSocksPort;
  if (engineMode === 'warp') {
    engineMode = 'byedpi';
    localSocksPort = 40000;
  }

  return {
    ...DEFAULT_STATE,
    ...saved,
    engineMode,
    localSocksPort,
    platforms: { ...DEFAULT_STATE.platforms, ...(saved.platforms || {}) },
    customProxy: { ...DEFAULT_STATE.customProxy, ...(saved.customProxy || {}) },
    browserServers: Array.isArray(saved.browserServers) ? saved.browserServers : [],
    customDomains: Array.isArray(saved.customDomains) ? saved.customDomains : [],
    exclusions: Array.isArray(saved.exclusions) ? saved.exclusions : [...DEFAULT_STATE.exclusions],
    adblockAllowlist: Array.isArray(saved.adblockAllowlist) ? saved.adblockAllowlist : [],
    phishingAllowlist: Array.isArray(saved.phishingAllowlist) ? saved.phishingAllowlist : [],
    customBlocklist: Array.isArray(saved.customBlocklist) ? saved.customBlocklist : [],
    communityStats: {
      ...DEFAULT_STATE.communityStats,
      ...(saved.communityStats || {}),
    },
    blockedCount: typeof saved.blockedCount === 'number' ? saved.blockedCount : 0,
  };
}

async function saveState(state) {
  firefoxCachedState = state;
  await chrome.storage.local.set({ splitwireState: state });
}

function getActiveBrowserServer(state) {
  if (!state.browserServers || state.browserServers.length === 0) return null;
  const idx = state.activeServerIndex % state.browserServers.length;
  return state.browserServers[idx] || state.browserServers[0];
}

function getProxyDirective(state) {
  switch (state.engineMode) {
    case 'browser': {
      const list = state.browserServers || [];
      if (list.length === 0) return null;
      // Rotate list so activeServerIndex is primary, followed by up to 2 verified failover backups
      const start = state.activeServerIndex % list.length;
      const ordered = [];
      for (let i = 0; i < Math.min(3, list.length); i++) {
        const srv = list[(start + i) % list.length];
        if (srv && srv.ip && srv.port) {
          ordered.push(`SOCKS5 ${srv.ip}:${srv.port}`);
        }
      }
      return ordered.length > 0 ? ordered.join('; ') : null;
    }
    case 'byedpi':
      return `SOCKS5 127.0.0.1:${state.localSocksPort || 1080}; DIRECT`;
    case 'custom': {
      const host = (state.customProxy.host || '').trim();
      const port = parseInt(state.customProxy.port, 10) || 443;
      const scheme = ['PROXY', 'HTTPS', 'SOCKS5'].includes(state.customProxy.scheme)
        ? state.customProxy.scheme
        : 'HTTPS';
      if (!host) return null;
      return `${scheme} ${host}:${port}`;
    }
    case 'splitwire':
    default:
      return `PROXY 127.0.0.1:${state.splitwirePort || 8080}`;
  }
}

function getActiveSplitDomains(state) {
  const set = new Set();
  for (const [key, enabled] of Object.entries(state.platforms)) {
    if (enabled && PLATFORM_DOMAINS[key]) {
      for (const d of PLATFORM_DOMAINS[key]) set.add(d);
    }
  }
  for (const d of state.customDomains) {
    if (d && typeof d === 'string') set.add(d.toLowerCase().trim());
  }
  return Array.from(set);
}

/**
 * Generates a fast PAC script for Split Tunnel or Full Browser mode.
 * - Localhost & private RFC1918 LAN addresses ALWAYS remain DIRECT.
 * - In `browser` (public SOCKS5) mode, ONLY encrypted HTTPS / WSS URLs are proxied
 *   so plaintext HTTP can never be intercepted by a third-party server.
 */
function buildPacScript(state) {
  const proxyRule = getProxyDirective(state);
  if (!proxyRule) return null;

  const tunnelMode = state.tunnelMode;
  const httpsOnly = state.engineMode === 'browser';
  const splitDomains = getActiveSplitDomains(state);
  const exclusions = (state.exclusions || []).map((d) => d.toLowerCase().trim()).filter(Boolean);

  return `
function isPrivateHost(host) {
  if (isPlainHostName(host)) return true;
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return true;
  if (shExpMatch(host, "127.*") || shExpMatch(host, "10.*") || shExpMatch(host, "192.168.*")) return true;
  if (shExpMatch(host, "172.16.*") || shExpMatch(host, "172.17.*") || shExpMatch(host, "172.18.*") ||
      shExpMatch(host, "172.19.*") || shExpMatch(host, "172.2?.*") || shExpMatch(host, "172.30.*") ||
      shExpMatch(host, "172.31.*")) return true;
  if (dnsDomainIs(host, ".local") || dnsDomainIs(host, ".localhost")) return true;
  return false;
}

function matchesAny(host, list) {
  for (var i = 0; i < list.length; i++) {
    var d = list[i];
    if (host === d || dnsDomainIs(host, "." + d)) {
      return true;
    }
  }
  return false;
}

function FindProxyForURL(url, host) {
  var h = host.toLowerCase();
  if (isPrivateHost(h)) {
    return "DIRECT";
  }

  var httpsOnly = ${JSON.stringify(httpsOnly)};
  if (httpsOnly) {
    var u = url.toLowerCase();
    if (u.indexOf("https:") !== 0 && u.indexOf("wss:") !== 0) {
      return "DIRECT";
    }
  }

  var mode = ${JSON.stringify(tunnelMode)};
  var proxy = ${JSON.stringify(proxyRule)};

  if (mode === "full") {
    var exclusions = ${JSON.stringify(exclusions)};
    if (matchesAny(h, exclusions)) {
      return "DIRECT";
    }
    return proxy;
  }

  var splitDomains = ${JSON.stringify(splitDomains)};
  if (matchesAny(h, splitDomains)) {
    return proxy;
  }
  return "DIRECT";
}
`.trim();
}

/**
 * Fetches candidate SOCKS5 servers prioritized by lowest reported latency
 * and proximity to Turkey (excludes TR itself so ISP blocks are bypassed).
 */
async function fetchCandidateServers(region = 'eu') {
  const candidates = [];
  const seen = new Set();

  const matchesRegion = (cc) => {
    if (cc === 'TR') return false; // Never proxy through Turkey itself
    if (region === 'eu') return EU_COUNTRIES.has(cc);
    if (region === 'DE' || region === 'NL') return cc === region;
    return true;
  };

  const addCandidate = (ip, port, country, city, priorityScore) => {
    if (!ip || !port) return;
    const cc = (country || '').toUpperCase();
    if (!matchesRegion(cc)) return;
    const key = `${ip}:${port}`;
    if (seen.has(key)) return;
    seen.add(key);

    // Give a strong priority bonus to countries physically closest to Turkey
    const geoBonus = NEAR_EU_COUNTRIES.has(cc) ? 0 : 450;
    candidates.push({
      ip: String(ip).trim(),
      port: parseInt(port, 10),
      country: cc || 'EU',
      city: city && city !== 'Unknown' ? city : '',
      rank: (priorityScore || 1500) + geoBonus,
    });
  };

  // Query all 3 curated feeds in parallel for fast startup
  const [psResult, gnResult, pfResult] = await Promise.allSettled([
    // Source 1 (Fastest): ProxyScrape v4 live-verified low-timeout SOCKS5 list
    fetch(
      'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=protocolipport&format=json&timeout=2500',
      { cache: 'no-store', signal: AbortSignal.timeout(4500) }
    ).then((r) => (r.ok ? r.json() : null)),

    // Source 2: GeoNode sorted by lowest responseTime ascending
    fetch(
      'https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=responseTime&sort_type=asc&protocols=socks5',
      { cache: 'no-store', signal: AbortSignal.timeout(4500) }
    ).then((r) => (r.ok ? r.json() : null)),

    // Source 3: Proxifly large EU fallback pool
    fetch(
      'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.json',
      { cache: 'no-store', signal: AbortSignal.timeout(4500) }
    ).then((r) => (r.ok ? r.json() : null)),
  ]);

  if (psResult.status === 'fulfilled' && psResult.value && Array.isArray(psResult.value.proxies)) {
    for (const item of psResult.value.proxies) {
      const cc = item.ip_data && item.ip_data.countryCode;
      const city = item.ip_data && item.ip_data.city;
      const reportedMs = typeof item.average_timeout === 'number' ? item.average_timeout : 900;
      addCandidate(item.ip, item.port, cc, city, reportedMs * 0.6);
    }
  }

  if (gnResult.status === 'fulfilled' && gnResult.value && Array.isArray(gnResult.value.data)) {
    for (const row of gnResult.value.data) {
      const reportedMs = typeof row.responseTime === 'number' ? row.responseTime : 1200;
      addCandidate(row.ip, row.port, row.country, row.city, reportedMs * 0.8 + 150);
    }
  }

  if (pfResult.status === 'fulfilled' && Array.isArray(pfResult.value)) {
    // Take a light random sample of near-EU entries from the huge Proxifly pool as backup
    const pfFiltered = pfResult.value.filter((item) => {
      const cc = (item.geolocation && item.geolocation.country || '').toUpperCase();
      return matchesRegion(cc);
    });
    for (let i = pfFiltered.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [pfFiltered[i], pfFiltered[j]] = [pfFiltered[j], pfFiltered[i]];
    }
    for (const item of pfFiltered.slice(0, 60)) {
      addCandidate(
        item.ip,
        item.port,
        item.geolocation && item.geolocation.country,
        item.geolocation && item.geolocation.city,
        2200
      );
    }
  }

  // Sort strictly by lowest predicted latency (ProxyScrape near-EU first!)
  candidates.sort((a, b) => a.rank - b.rank);
  return candidates;
}

/**
 * Probes up to 10 candidate SOCKS5 servers IN PARALLEL using Chrome's own proxy engine.
 * Step 1: Warm-up TLS 1.3 handshake with strict timeout (rejects slow proxies immediately).
 * Step 2: Second tiny keep-alive request measures TRUE single-RTT ping in ms!
 */
async function probeServerBatch(batch, timeoutMs = 1350) {
  const slice = batch.slice(0, PROBE_ENDPOINTS.length);

  if (IS_FIREFOX) {
    const map = new Map();
    slice.forEach((srv, idx) => {
      map.set(PROBE_ENDPOINTS[idx].host.toLowerCase(), {
        type: 'socks',
        host: srv.ip,
        port: Number(srv.port),
        proxyDNS: true,
      });
    });
    firefoxProbeMap = map;
  } else {
    const mappingLines = slice
      .map((srv, idx) => `if (h === ${JSON.stringify(PROBE_ENDPOINTS[idx].host)}) return "SOCKS5 ${srv.ip}:${srv.port}";`)
      .join('\n  ');

    const probePac = `
function FindProxyForURL(url, host) {
  var h = host.toLowerCase();
  ${mappingLines}
  return "DIRECT";
}
`.trim();

    await chrome.proxy.settings.set({
      value: { mode: 'pac_script', pacScript: { data: probePac } },
      scope: 'regular',
    });
    await sleep(100);
  }

  try {
    const results = await Promise.all(
      slice.map(async (srv, idx) => {
        const endpoint = PROBE_ENDPOINTS[idx];
        const sep = endpoint.url.includes('?') ? '&' : '?';
        const coldStart = Date.now();
        try {
          // 1. Cold handshake + TLS 1.3 verification
          const res1 = await fetch(`${endpoint.url}${sep}_sw=${Date.now()}_${idx}`, {
            method: 'GET',
            cache: 'no-store',
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (!res1.ok && res1.status !== 204) return null;
          const coldMs = Date.now() - coldStart;

          // 2. Warm keep-alive ping (measures true single-RTT latency, not 4-RTT TLS setup)
          let rttMs = Math.round(coldMs / 3);
          try {
            const warmStart = Date.now();
            const res2 = await fetch(`${endpoint.url}${sep}_sw2=${Date.now()}_${idx}`, {
              method: 'GET',
              cache: 'no-store',
              signal: AbortSignal.timeout(1200),
            });
            if (res2.ok || res2.status === 204) {
              rttMs = Math.max(10, Date.now() - warmStart);
            }
          } catch (_) {}

          return {
            ip: srv.ip,
            port: srv.port,
            country: srv.country,
            city: srv.city,
            latencyMs: rttMs,
            coldMs,
            verifiedAt: Date.now(),
          };
        } catch (_) {
          return null;
        }
      })
    );

    return results.filter(Boolean);
  } finally {
    if (IS_FIREFOX) {
      firefoxProbeMap = null;
    }
  }
}

/**
 * Discovers the lowest-latency working SOCKS5 servers directly inside the browser.
 * Fast pass (1350ms cold / <250ms RTT target) runs first across 30 top candidates (3 batches of 10).
 * Falls back to a relaxed 2400ms pass only if no ultra-fast servers responded.
 */
async function discoverWorkingServers(state) {
  if (isProbing) return { ok: false, error: 'BUSY' };
  isProbing = true;

  try {
    if (IS_FIREFOX) {
      firefoxBypassForFetch = true;
    } else {
      await chrome.proxy.settings.clear({ scope: 'regular' });
      await sleep(60);
    }

    let candidates = await fetchCandidateServers(state.browserRegion || 'eu');
    if (candidates.length === 0 && state.browserRegion !== 'all') {
      candidates = await fetchCandidateServers('all');
    }

    const working = [];
    const batchSize = PROBE_ENDPOINTS.length; // 10 in parallel

    // Phase 1: Strict fast pass (1350ms max cold TLS handshake -> filters out laggy proxies)
    for (let b = 0; b < 3 && b * batchSize < candidates.length; b++) {
      const slice = candidates.slice(b * batchSize, (b + 1) * batchSize);
      const found = await probeServerBatch(slice, 1350);
      working.push(...found);
      // Stop early once we have at least 2 genuinely fast (<180ms RTT) servers
      const fastCount = working.filter((s) => s.latencyMs <= 180).length;
      if (fastCount >= 2 || working.length >= 4) break;
    }

    // Phase 2: Fallback relaxed pass only if Phase 1 found nothing
    if (working.length === 0 && candidates.length > 0) {
      const fallbackSlice = candidates.slice(0, batchSize);
      const found = await probeServerBatch(fallbackSlice, 2500);
      working.push(...found);
    }

    working.sort((a, b) => a.latencyMs - b.latencyMs);
    const topServers = working.slice(0, 6);

    if (topServers.length > 0) {
      state.browserServers = topServers;
      state.activeServerIndex = 0;
      await saveState(state);
      return { ok: true, servers: topServers, active: topServers[0] };
    }

    return { ok: false, error: 'NO_SERVERS' };
  } finally {
    isProbing = false;
    firefoxBypassForFetch = false;
    firefoxProbeMap = null;
    await applyProxyState(state);
  }
}

async function applyWebRtcSetting(state) {
  if (!chrome.privacy || !chrome.privacy.network || !chrome.privacy.network.webRTCIPHandlingPolicy) {
    return;
  }
  try {
    const value = state.connected && state.webrtcProtection ? 'disable_non_proxied_udp' : 'default';
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({ value });
  } catch (_) {}
}

async function checkLocalEngine(controlPort = 8081) {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1600);
  try {
    const res = await fetch(`http://127.0.0.1:${controlPort}/status`, {
      method: 'GET',
      cache: 'no-store',
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { online: false, latencyMs: null };
    const data = await res.json();
    return {
      online: Boolean(data && data.running),
      latencyMs: Date.now() - start,
      data,
    };
  } catch (_) {
    clearTimeout(timer);
    return { online: false, latencyMs: null };
  }
}

async function syncEngineConfig(state) {
  if (state.engineMode !== 'splitwire') return { ok: false };
  const controlPort = state.splitwireControlPort || 8081;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1600);
  try {
    const res = await fetch(`http://127.0.0.1:${controlPort}/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        preset: state.preset,
        dohProvider: state.dohProvider,
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { ok: false };
    return await res.json();
  } catch (_) {
    clearTimeout(timer);
    return { ok: false };
  }
}

async function updateBadgeAndIcon(state, engineOnline = null) {
  const actionApi = chrome.action || chrome.browserAction;
  if (!actionApi) return;

  const iconSet = state.connected
    ? {
        16: 'icons/icon-active-16.png',
        32: 'icons/icon-active-32.png',
        48: 'icons/icon-active-48.png',
        128: 'icons/icon-active-128.png',
      }
    : {
        16: 'icons/icon-16.png',
        32: 'icons/icon-32.png',
        48: 'icons/icon-48.png',
        128: 'icons/icon-128.png',
      };

  try {
    await actionApi.setIcon({ path: iconSet });
  } catch (_) {}

  if (!state.connected) {
    await actionApi.setBadgeText({ text: '' });
    return;
  }

  if (state.engineMode === 'splitwire' && engineOnline === false) {
    await actionApi.setBadgeText({ text: '!' });
    await actionApi.setBadgeBackgroundColor({ color: '#f59e0b' });
    try {
      if (actionApi.setBadgeTextColor) {
        await actionApi.setBadgeTextColor({ color: '#0b0f17' });
      }
    } catch (_) {}
    return;
  }

  await actionApi.setBadgeText({ text: 'ON' });
  await actionApi.setBadgeBackgroundColor({ color: '#10b981' });
  try {
    if (actionApi.setBadgeTextColor) {
      await actionApi.setBadgeTextColor({ color: '#ffffff' });
    }
  } catch (_) {}
}

async function applyProxyState(state) {
  firefoxCachedState = state;

  if (!state.connected) {
    if (!IS_FIREFOX) {
      await chrome.proxy.settings.clear({ scope: 'regular' });
    }
    await applyWebRtcSetting(state);
    await chrome.alarms.clear(HEALTH_ALARM);
    await updateBadgeAndIcon(state);
    return { ok: true };
  }

  const proxyRule = getProxyDirective(state);
  if (!proxyRule) {
    state.connected = false;
    state.connectedAt = null;
    await saveState(state);
    if (!IS_FIREFOX) {
      await chrome.proxy.settings.clear({ scope: 'regular' });
    }
    await updateBadgeAndIcon(state);
    return { ok: false, error: state.engineMode === 'custom' ? 'CUSTOM_PROXY_MISSING' : 'NO_SERVERS' };
  }

  if (!IS_FIREFOX) {
    const pacScript = buildPacScript(state);
    await chrome.proxy.settings.set({
      value: {
        mode: 'pac_script',
        pacScript: { data: pacScript },
      },
      scope: 'regular',
    });
  }

  await applyWebRtcSetting(state);

  let engineOnline = null;
  if (state.engineMode === 'splitwire') {
    const health = await checkLocalEngine(state.splitwireControlPort);
    engineOnline = health.online;
    if (engineOnline) syncEngineConfig(state);
    chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: 1 });
  } else {
    await chrome.alarms.clear(HEALTH_ALARM);
  }

  await updateBadgeAndIcon(state, engineOnline);
  return { ok: true, engineOnline };
}

function sanitizeDomain(input) {
  if (!input || typeof input !== 'string') return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  d = d.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  if (!d || d.length > 253 || !d.includes('.') || /\s/.test(d)) return null;
  if (!/^[a-z0-9.-]+$/.test(d)) return null;
  return d;
}

// ==================== Cross-Browser Ad, Phishing, Focus & Community Shield ====================
const ALLOWLIST_RULE_ID = 50001;
const CUSTOM_BLOCK_BASE_ID = 60000; // 60000..60999
const PHISHING_BASE_ID = 65000; // 65000..65499
const COMMUNITY_AD_BASE_ID = 70000; // 70000..70599

const SUBRESOURCE_TYPES = [
  'script',
  'image',
  'sub_frame',
  'xmlhttprequest',
  'ping',
  'media',
  'other',
  'stylesheet',
  'font',
  'websocket',
];

let pendingBlockedIncrement = 0;
let blockedFlushTimer = null;
let builtinPhishingCache = null;

function recordBlockedHit() {
  pendingBlockedIncrement++;
  if (firefoxCachedState) {
    firefoxCachedState.blockedCount = (firefoxCachedState.blockedCount || 0) + 1;
  }
  if (!blockedFlushTimer) {
    blockedFlushTimer = setTimeout(async () => {
      const delta = pendingBlockedIncrement;
      pendingBlockedIncrement = 0;
      blockedFlushTimer = null;
      if (delta <= 0) return;
      const st = await getState();
      st.blockedCount = (st.blockedCount || 0) + delta;
      await saveState(st);
    }, 1500);
  }
}

async function getBuiltinPhishingDomains() {
  if (builtinPhishingCache) return builtinPhishingCache;
  try {
    const url = (typeof browser !== 'undefined' ? browser.runtime : chrome.runtime).getURL(
      'rules/phishing.json'
    );
    const res = await fetch(url);
    const arr = await res.json();
    builtinPhishingCache = Array.isArray(arr)
      ? arr.map((d) => String(d).toLowerCase().trim()).filter(Boolean)
      : [];
  } catch (_) {
    builtinPhishingCache = [];
  }
  return builtinPhishingCache;
}

async function getCommunityStorage() {
  const res = await chrome.storage.local.get('splitwireCommunity');
  const data = res.splitwireCommunity || {};
  return {
    ads: Array.isArray(data.ads) ? data.ads : [],
    phishing: Array.isArray(data.phishing) ? data.phishing : [],
  };
}

function parseHostsDomains(text, maxCount = 500) {
  const out = [];
  const seen = new Set();
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('!')) continue;
    const parts = line.split(/\s+/);
    let candidate = parts.length >= 2 && /^(0\.0\.0\.0|127\.0\.0\.1)$/.test(parts[0]) ? parts[1] : parts[0];
    candidate = candidate.toLowerCase().replace(/^\.+|\.+$/g, '');
    if (
      !candidate ||
      candidate === 'localhost' ||
      candidate.endsWith('.local') ||
      !candidate.includes('.') ||
      candidate.length > 120 ||
      !/^[a-z0-9.-]+$/.test(candidate)
    ) {
      continue;
    }
    if (!seen.has(candidate)) {
      seen.add(candidate);
      out.push(candidate);
      if (out.length >= maxCount) break;
    }
  }
  return out;
}

/**
 * Fetches fresh open-source community ad & phishing blocklists
 * (AdAway + Peter Lowe + Discord-AntiScam) and applies them live.
 */
async function refreshCommunityFilters() {
  const state = await getState();

  const [adawayRes, plRes, scamRes] = await Promise.allSettled([
    fetch('https://cdn.jsdelivr.net/gh/AdAway/adaway.github.io@master/hosts.txt', {
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    }).then((r) => (r.ok ? r.text() : '')),
    fetch(
      'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext',
      {
        cache: 'no-store',
        signal: AbortSignal.timeout(6000),
      }
    ).then((r) => (r.ok ? r.text() : '')),
    fetch('https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.json', {
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    }).then((r) => (r.ok ? r.json() : [])),
  ]);

  // Deduplicate against static ads.json so community rules add strictly NEW coverage
  const staticAdSet = new Set();
  try {
    const url = (typeof browser !== 'undefined' ? browser.runtime : chrome.runtime).getURL(
      'rules/ads.json'
    );
    const staticRules = await (await fetch(url)).json();
    for (const r of staticRules) {
      const f = r?.condition?.urlFilter;
      if (f && f.startsWith('||')) staticAdSet.add(f.slice(2).replace(/\^$/, '').toLowerCase());
    }
  } catch (_) {}

  const adSet = new Set();
  const adSources = [
    adawayRes.status === 'fulfilled' ? adawayRes.value : '',
    plRes.status === 'fulfilled' ? plRes.value : '',
  ];
  for (const srcText of adSources) {
    for (const d of parseHostsDomains(srcText, 600)) {
      if (!staticAdSet.has(d)) adSet.add(d);
      if (adSet.size >= 500) break;
    }
    if (adSet.size >= 500) break;
  }

  const builtinPhish = new Set(await getBuiltinPhishingDomains());
  const phishSet = new Set();
  if (scamRes.status === 'fulfilled' && Array.isArray(scamRes.value)) {
    for (const item of scamRes.value) {
      const d = sanitizeDomain(String(item || ''));
      if (d && !builtinPhish.has(d)) {
        phishSet.add(d);
        if (phishSet.size >= 350) break;
      }
    }
  }

  const ads = Array.from(adSet);
  const phishing = Array.from(phishSet);

  if (ads.length === 0 && phishing.length === 0) {
    return { ok: false, error: 'FETCH_FAILED', state };
  }

  await chrome.storage.local.set({ splitwireCommunity: { ads, phishing } });
  state.lastFilterUpdate = Date.now();
  state.communityStats = { ads: ads.length, phishing: phishing.length };
  await saveState(state);
  await applyAdblockState(state);

  return {
    ok: true,
    total: ads.length + phishing.length,
    ads: ads.length,
    phishing: phishing.length,
    state,
  };
}

// Firefox MV2: Native webRequestBlocking matchers (Ads, Trackers, Community, Phishing, Custom Focus Block)
const ffAdMatcher = { domains: new Set(), paths: [] };
const ffTrackerMatcher = { domains: new Set(), paths: [] };
const ffCommunityAdSet = new Set();
const ffPhishingSet = new Set();
const ffCustomBlockSet = new Set();

function loadRulesIntoMatcher(rulesArray, target) {
  for (const rule of rulesArray) {
    const f = rule && rule.condition && rule.condition.urlFilter;
    if (!f || !f.startsWith('||')) continue;
    const raw = f.slice(2).replace(/\^$/, '').toLowerCase();
    if (raw.includes('/')) target.paths.push(raw);
    else target.domains.add(raw);
  }
}

function hostMatchesSet(host, domainSet) {
  if (domainSet.has(host)) return true;
  let dot = host.indexOf('.');
  while (dot !== -1) {
    const parent = host.slice(dot + 1);
    if (domainSet.has(parent)) return true;
    dot = host.indexOf('.', dot + 1);
  }
  return false;
}

function findMatchedDomainInSet(host, domainSet) {
  if (domainSet.has(host)) return host;
  let dot = host.indexOf('.');
  while (dot !== -1) {
    const parent = host.slice(dot + 1);
    if (domainSet.has(parent)) return parent;
    dot = host.indexOf('.', dot + 1);
  }
  return null;
}

/**
 * Unified Protection Rule Applicator (Chrome MV3 DNR + Firefox MV2 in-memory sets).
 * Manages:
 * - Static Ads & Trackers rulesets
 * - AdBlock per-site allowlist (50001)
 * - Personal Block / Focus List main_frame redirects to /blocked.html (60000+)
 * - Phishing & Malware Shield main_frame redirects to /blocked.html (65000+)
 * - Auto-Updating Community Ad Filter delta rules (70000+)
 */
async function applyAdblockState(state) {
  firefoxCachedState = state;

  const builtinPhishing = await getBuiltinPhishingDomains();
  const community = await getCommunityStorage();
  const phishingAllow = new Set(
    (state.phishingAllowlist || []).map((d) => d.toLowerCase().trim()).filter(Boolean)
  );
  const customBlocks = (state.customBlocklist || [])
    .map((d) => d.toLowerCase().trim().replace(/^www\./, ''))
    .filter(Boolean);

  // Combine built-in + community phishing domains (excluding any user-allowed overrides)
  const activePhishing = [];
  if (state.phishingShieldEnabled) {
    const seenP = new Set();
    const pool = state.communityFilterEnabled
      ? [...builtinPhishing, ...community.phishing]
      : [...builtinPhishing];
    for (const d of pool) {
      if (!phishingAllow.has(d) && !seenP.has(d)) {
        seenP.add(d);
        activePhishing.push(d);
        if (activePhishing.length >= 420) break;
      }
    }
  }

  const activeCommunityAds =
    state.adblockEnabled && state.communityFilterEnabled ? community.ads.slice(0, 500) : [];

  // Keep Firefox in-memory sets synced
  ffCustomBlockSet.clear();
  customBlocks.forEach((d) => ffCustomBlockSet.add(d));
  ffPhishingSet.clear();
  activePhishing.forEach((d) => ffPhishingSet.add(d));
  ffCommunityAdSet.clear();
  activeCommunityAds.forEach((d) => ffCommunityAdSet.add(d));

  // Schedule or clear 24-hour community filter alarm
  if (state.communityFilterEnabled) {
    chrome.alarms.create(COMMUNITY_ALARM, { periodInMinutes: 1440 });
  } else {
    chrome.alarms.clear(COMMUNITY_ALARM);
  }

  // Chrome MV3 declarativeNetRequest sync
  if (typeof chrome !== 'undefined' && chrome.declarativeNetRequest) {
    const enableRulesetIds = [];
    const disableRulesetIds = [];

    if (state.adblockEnabled) enableRulesetIds.push('ads_ruleset');
    else disableRulesetIds.push('ads_ruleset');

    if (state.adblockEnabled && state.trackerBlockEnabled) enableRulesetIds.push('trackers_ruleset');
    else disableRulesetIds.push('trackers_ruleset');

    try {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds,
        disableRulesetIds,
      });
    } catch (_) {}

    try {
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = existing.map((r) => r.id);
      const addRules = [];

      // 1. AdBlock per-site allowlist (only affects ad/tracker block rules, priority 100)
      const allowlist = (state.adblockAllowlist || [])
        .map((d) => d.toLowerCase().trim())
        .filter(Boolean);
      if (allowlist.length > 0) {
        addRules.push({
          id: ALLOWLIST_RULE_ID,
          priority: 100,
          action: { type: 'allow' },
          condition: {
            initiatorDomains: allowlist,
            resourceTypes: SUBRESOURCE_TYPES,
          },
        });
      }

      // 2. Personal Block / Focus List (main_frame -> animated blocked.html)
      customBlocks.slice(0, 500).forEach((domain, idx) => {
        addRules.push({
          id: CUSTOM_BLOCK_BASE_ID + idx,
          priority: 90,
          action: {
            type: 'redirect',
            redirect: {
              extensionPath: `/blocked.html?reason=custom&site=${encodeURIComponent(domain)}`,
            },
          },
          condition: {
            urlFilter: `||${domain}^`,
            resourceTypes: ['main_frame'],
          },
        });
      });

      // 3. Phishing & Malware Shield (main_frame -> animated blocked.html)
      activePhishing.forEach((domain, idx) => {
        addRules.push({
          id: PHISHING_BASE_ID + idx,
          priority: 85,
          action: {
            type: 'redirect',
            redirect: {
              extensionPath: `/blocked.html?reason=phishing&site=${encodeURIComponent(domain)}`,
            },
          },
          condition: {
            urlFilter: `||${domain}^`,
            resourceTypes: ['main_frame'],
          },
        });
      });

      // 4. Community Ad Filter delta (subresources only)
      activeCommunityAds.forEach((domain, idx) => {
        addRules.push({
          id: COMMUNITY_AD_BASE_ID + idx,
          priority: 1,
          action: { type: 'block' },
          condition: {
            urlFilter: `||${domain}^`,
            resourceTypes: SUBRESOURCE_TYPES,
          },
        });
      });

      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules,
      });
    } catch (err) {
      console.warn('[SplitWire] updateDynamicRules warning:', err);
    }
  }
}

// Chrome unpacked live blocked counter
if (
  typeof chrome !== 'undefined' &&
  chrome.declarativeNetRequest &&
  chrome.declarativeNetRequest.onRuleMatchedDebug
) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    if (info && info.rule && info.rule.ruleId !== ALLOWLIST_RULE_ID) {
      recordBlockedHit();
    }
  });
}

function checkFirefoxMainFrameBlock(urlStr, state) {
  if (!state) return null;
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (_) {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  const host = parsed.hostname.toLowerCase();

  // 1. Personal Block / Focus List
  const matchedCustom = findMatchedDomainInSet(host, ffCustomBlockSet);
  if (matchedCustom) {
    return { reason: 'custom', site: matchedCustom };
  }

  // 2. Phishing & Malware Shield
  if (state.phishingShieldEnabled) {
    const matchedPhish = findMatchedDomainInSet(host, ffPhishingSet);
    if (matchedPhish) {
      return { reason: 'phishing', site: matchedPhish };
    }
  }
  return null;
}

function shouldBlockFirefoxRequest(urlStr, initiatorUrl, reqType, state) {
  if (!state || !state.adblockEnabled || reqType === 'main_frame') return false;

  if (initiatorUrl && state.adblockAllowlist && state.adblockAllowlist.length > 0) {
    try {
      const initHost = new URL(initiatorUrl).hostname.toLowerCase();
      if (matchesAnyHostJs(initHost, state.adblockAllowlist)) return false;
    } catch (_) {}
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (_) {
    return false;
  }

  const host = parsed.hostname.toLowerCase();
  const hostAndPath = `${host}${parsed.pathname.toLowerCase()}`;

  if (hostMatchesSet(host, ffAdMatcher.domains)) return true;
  if (state.communityFilterEnabled && hostMatchesSet(host, ffCommunityAdSet)) return true;
  for (let i = 0; i < ffAdMatcher.paths.length; i++) {
    if (hostAndPath.includes(ffAdMatcher.paths[i])) return true;
  }

  if (state.trackerBlockEnabled) {
    if (hostMatchesSet(host, ffTrackerMatcher.domains)) return true;
    for (let i = 0; i < ffTrackerMatcher.paths.length; i++) {
      if (hostAndPath.includes(ffTrackerMatcher.paths[i])) return true;
    }
  }

  return false;
}

if (
  IS_FIREFOX &&
  typeof browser !== 'undefined' &&
  browser.webRequest &&
  browser.webRequest.onBeforeRequest
) {
  Promise.all([
    fetch(browser.runtime.getURL('rules/ads.json')).then((r) => r.json()).catch(() => []),
    fetch(browser.runtime.getURL('rules/trackers.json')).then((r) => r.json()).catch(() => []),
  ]).then(([ads, trackers]) => {
    loadRulesIntoMatcher(ads, ffAdMatcher);
    loadRulesIntoMatcher(trackers, ffTrackerMatcher);
  });

  browser.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (!firefoxCachedState) return {};
      if (details.type === 'main_frame') {
        const hit = checkFirefoxMainFrameBlock(details.url, firefoxCachedState);
        if (hit) {
          recordBlockedHit();
          return {
            redirectUrl: browser.runtime.getURL(
              `blocked.html?reason=${hit.reason}&site=${encodeURIComponent(hit.site)}`
            ),
          };
        }
        return {};
      }
      const initiator = details.documentUrl || details.originUrl || '';
      if (shouldBlockFirefoxRequest(details.url, initiator, details.type, firefoxCachedState)) {
        recordBlockedHit();
        return { cancel: true };
      }
      return {};
    },
    { urls: ['<all_urls>'] },
    ['blocking']
  );
}

// ==================== Smart Auto-Connect (Tab-Aware Split Tunnel) ====================
function urlMatchesSplitTunnel(urlStr, state) {
  if (!urlStr || !/^https?:\/\//i.test(urlStr)) return false;
  try {
    const host = new URL(urlStr).hostname.toLowerCase();
    const domains = getActiveSplitDomains(state);
    return matchesAnyHostJs(host, domains);
  } catch (_) {
    return false;
  }
}

async function evaluateAutoConnect() {
  if (isAutoConnecting || isProbing) return;
  const state = await getState();
  if (!state.autoConnectEnabled) return;

  let tabs = [];
  try {
    tabs = await chrome.tabs.query({});
  } catch (_) {
    return;
  }

  const hasMatchingTab = tabs.some((tab) => urlMatchesSplitTunnel(tab.url, state));

  if (hasMatchingTab) {
    clearTimeout(autoDisconnectTimer);
    autoDisconnectTimer = null;

    if (!state.connected) {
      if (state.engineMode === 'custom' && !(state.customProxy.host || '').trim()) return;
      isAutoConnecting = true;
      try {
        if (state.engineMode === 'browser') {
          const active = getActiveBrowserServer(state);
          const isStale = !active || Date.now() - (active.verifiedAt || 0) > 20 * 60_000;
          if (isStale) {
            const disc = await discoverWorkingServers(state);
            if (!disc.ok) return;
          }
        }
        const fresh = await getState();
        fresh.connected = true;
        fresh.autoConnected = true;
        fresh.connectedAt = Date.now();
        await saveState(fresh);
        await applyProxyState(fresh);
      } finally {
        isAutoConnecting = false;
      }
    }
  } else if (state.connected && state.autoConnected) {
    // Wait 4 seconds before disconnecting so refreshing/switching tabs doesn't flap
    if (!autoDisconnectTimer) {
      autoDisconnectTimer = setTimeout(async () => {
        autoDisconnectTimer = null;
        const latest = await getState();
        if (!latest.autoConnectEnabled || !latest.connected || !latest.autoConnected) return;
        const curTabs = await chrome.tabs.query({}).catch(() => []);
        if (!curTabs.some((t) => urlMatchesSplitTunnel(t.url, latest))) {
          latest.connected = false;
          latest.autoConnected = false;
          latest.connectedAt = null;
          await saveState(latest);
          await applyProxyState(latest);
        }
      }, 4000);
    }
  }
}

function findMainFrameBlockInState(urlStr, state, extraPhishingList = []) {
  if (!state || !urlStr || !/^https?:\/\//i.test(urlStr)) return null;
  let host;
  try {
    host = new URL(urlStr).hostname.toLowerCase();
  } catch (_) {
    return null;
  }

  // 1. Personal Block / Focus List
  const customList = (state.customBlocklist || [])
    .map((d) => d.toLowerCase().trim().replace(/^www\./, ''))
    .filter(Boolean);
  for (let i = 0; i < customList.length; i++) {
    const d = customList[i];
    if (host === d || host.endsWith('.' + d)) {
      return { reason: 'custom', site: d };
    }
  }

  // 2. Phishing & Malware Shield
  if (state.phishingShieldEnabled) {
    const allowSet = new Set(
      (state.phishingAllowlist || []).map((d) => d.toLowerCase().trim().replace(/^www\./, ''))
    );
    const matched = findMatchedDomainInSet(host, ffPhishingSet);
    if (matched && !allowSet.has(matched)) {
      return { reason: 'phishing', site: matched };
    }
    for (let i = 0; i < extraPhishingList.length; i++) {
      const d = extraPhishingList[i];
      if (!allowSet.has(d) && (host === d || host.endsWith('.' + d))) {
        return { reason: 'phishing', site: d };
      }
    }
  }
  return null;
}

async function enforceTabBlock(tabId, urlStr) {
  if (!tabId || !urlStr || !/^https?:\/\//i.test(urlStr)) return;
  const state = await getState();
  const builtinPhishing = state.phishingShieldEnabled ? await getBuiltinPhishingDomains() : [];
  const hit = findMainFrameBlockInState(urlStr, state, builtinPhishing);
  if (!hit) return;

  const blockedUrl = chrome.runtime.getURL(
    `blocked.html?reason=${hit.reason}&site=${encodeURIComponent(hit.site)}`
  );
  recordBlockedHit();
  try {
    await chrome.tabs.update(tabId, { url: blockedUrl });
  } catch (_) {}
}

if (typeof chrome !== 'undefined' && chrome.tabs) {
  if (chrome.tabs.onCreated) {
    chrome.tabs.onCreated.addListener((tab) => {
      const targetUrl = tab && (tab.pendingUrl || tab.url);
      if (tab && tab.id && targetUrl && /^https?:\/\//i.test(targetUrl)) {
        enforceTabBlock(tab.id, targetUrl);
      }
    });
  }
  if (chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      const targetUrl = (changeInfo && changeInfo.url) || (tab && tab.url);
      if (changeInfo && (changeInfo.url || changeInfo.status === 'loading') && targetUrl) {
        enforceTabBlock(tabId, targetUrl);
      }
      if (changeInfo && changeInfo.url) {
        evaluateAutoConnect();
      }
    });
  }
  if (chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener(() => {
      evaluateAutoConnect();
    });
  }
}

// Lifecycle listeners
chrome.runtime.onInstalled.addListener(async () => {
  const state = await getState();
  await saveState(state);
  await applyProxyState(state);
  await applyAdblockState(state);
  if (state.communityFilterEnabled && !state.lastFilterUpdate) {
    refreshCommunityFilters().catch(() => {});
  }
});

chrome.runtime.onStartup.addListener(async () => {
  const state = await getState();
  await applyProxyState(state);
  await applyAdblockState(state);
  if (
    state.communityFilterEnabled &&
    (!state.lastFilterUpdate || Date.now() - state.lastFilterUpdate > 24 * 3600_000)
  ) {
    refreshCommunityFilters().catch(() => {});
  }
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === COMMUNITY_ALARM) {
    const st = await getState();
    if (st.communityFilterEnabled) {
      refreshCommunityFilters().catch(() => {});
    }
    return;
  }
  if (alarm.name !== HEALTH_ALARM) return;
  const state = await getState();
  if (!state.connected || state.engineMode !== 'splitwire') {
    await chrome.alarms.clear(HEALTH_ALARM);
    return;
  }
  const health = await checkLocalEngine(state.splitwireControlPort);
  await updateBadgeAndIcon(state, health.online);
});

if (IS_FIREFOX) {
  getState().then((st) => {
    firefoxCachedState = st;
    applyAdblockState(st);
  });
}

// Message API for popup
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    const state = await getState();
    if (pendingBlockedIncrement > 0) {
      state.blockedCount = (state.blockedCount || 0) + pendingBlockedIncrement;
    }

    switch (message.type) {
      case 'GET_STATE': {
        const engine =
          state.engineMode === 'splitwire'
            ? await checkLocalEngine(state.splitwireControlPort)
            : { online: null, latencyMs: null };
        sendResponse({ state, engine, platformDomains: PLATFORM_DOMAINS });
        break;
      }

      case 'TOGGLE_CONNECT': {
        // Disconnect path
        if (state.connected) {
          clearTimeout(autoDisconnectTimer);
          autoDisconnectTimer = null;
          state.connected = false;
          state.autoConnected = false;
          state.connectedAt = null;
          await saveState(state);
          await applyProxyState(state);
          const engine =
            state.engineMode === 'splitwire'
              ? await checkLocalEngine(state.splitwireControlPort)
              : { online: null, latencyMs: null };
          sendResponse({ ok: true, state, engine });
          return;
        }

        // Connect path
        if (state.engineMode === 'custom' && !(state.customProxy.host || '').trim()) {
          sendResponse({ ok: false, error: 'CUSTOM_PROXY_MISSING', state });
          return;
        }

        // In-Browser Zero-File Mode: auto-discover fresh working servers if none cached or >20 min old
        if (state.engineMode === 'browser') {
          const active = getActiveBrowserServer(state);
          const isStale = !active || Date.now() - (active.verifiedAt || 0) > 20 * 60_000;
          if (isStale) {
            const disc = await discoverWorkingServers(state);
            if (!disc.ok) {
              sendResponse({ ok: false, error: disc.error || 'NO_SERVERS', state });
              return;
            }
          }
        }

        state.connected = true;
        state.autoConnected = false; // Manual connect overrides auto-disconnect
        state.connectedAt = Date.now();
        await saveState(state);
        const result = await applyProxyState(state);
        const engine =
          state.engineMode === 'splitwire'
            ? await checkLocalEngine(state.splitwireControlPort)
            : { online: null, latencyMs: null };
        sendResponse({ ...result, state, engine });
        break;
      }

      case 'DISCOVER_SERVERS': {
        const disc = await discoverWorkingServers(state);
        const freshState = await getState();
        sendResponse({ ...disc, state: freshState });
        break;
      }

      case 'SWITCH_SERVER': {
        if (!state.browserServers || state.browserServers.length <= 1) {
          const disc = await discoverWorkingServers(state);
          const freshState = await getState();
          sendResponse({ ...disc, state: freshState });
          return;
        }
        state.activeServerIndex = (state.activeServerIndex + 1) % state.browserServers.length;
        await saveState(state);
        await applyProxyState(state);
        sendResponse({
          ok: true,
          active: getActiveBrowserServer(state),
          state,
        });
        break;
      }

      case 'UPDATE_STATE': {
        const patch = message.patch || {};
        const next = {
          ...state,
          ...patch,
          platforms: patch.platforms ? { ...state.platforms, ...patch.platforms } : state.platforms,
          customProxy: patch.customProxy
            ? { ...state.customProxy, ...patch.customProxy }
            : state.customProxy,
        };
        await saveState(next);

        if (patch.preset || patch.dohProvider) {
          await syncEngineConfig(next);
        }

        if (
          'adblockEnabled' in patch ||
          'trackerBlockEnabled' in patch ||
          'adblockAllowlist' in patch ||
          'phishingShieldEnabled' in patch ||
          'phishingAllowlist' in patch ||
          'customBlocklist' in patch ||
          'communityFilterEnabled' in patch
        ) {
          await applyAdblockState(next);
        }

        if (patch.autoConnectEnabled) {
          evaluateAutoConnect();
        }

        const result = await applyProxyState(next);
        const engine =
          next.engineMode === 'splitwire'
            ? await checkLocalEngine(next.splitwireControlPort)
            : { online: null, latencyMs: null };
        sendResponse({ ...result, state: next, engine });
        break;
      }

      case 'ADD_CUSTOM_BLOCK': {
        const rawClean = sanitizeDomain(message.domain);
        const clean = rawClean ? rawClean.replace(/^www\./, '') : null;
        if (!clean) {
          sendResponse({ ok: false, error: 'INVALID' });
          return;
        }
        if (state.customBlocklist.includes(clean)) {
          sendResponse({ ok: false, error: 'EXISTS', state });
          return;
        }
        state.customBlocklist.unshift(clean);
        await saveState(state);
        await applyAdblockState(state);
        sendResponse({ ok: true, domain: clean, state });
        break;
      }

      case 'REMOVE_CUSTOM_BLOCK': {
        const target = (message.domain || '').toLowerCase().trim().replace(/^www\./, '');
        state.customBlocklist = state.customBlocklist.filter(
          (d) => d.toLowerCase().trim().replace(/^www\./, '') !== target
        );
        await saveState(state);
        await applyAdblockState(state);
        sendResponse({ ok: true, state });
        break;
      }

      case 'ALLOW_PHISHING_SITE': {
        const clean = sanitizeDomain(message.domain);
        if (clean && !state.phishingAllowlist.includes(clean)) {
          state.phishingAllowlist.unshift(clean);
          await saveState(state);
          await applyAdblockState(state);
        }
        sendResponse({ ok: true, state });
        break;
      }

      case 'UPDATE_COMMUNITY_FILTERS': {
        const res = await refreshCommunityFilters();
        sendResponse(res);
        break;
      }

      case 'TOGGLE_ADBLOCK_SITE': {
        const clean = sanitizeDomain(message.domain);
        if (!clean) {
          sendResponse({ ok: false, error: 'INVALID' });
          return;
        }
        const exists = state.adblockAllowlist.includes(clean);
        if (exists) {
          state.adblockAllowlist = state.adblockAllowlist.filter((d) => d !== clean);
        } else {
          state.adblockAllowlist.unshift(clean);
        }
        await saveState(state);
        await applyAdblockState(state);
        sendResponse({ ok: true, paused: !exists, domain: clean, state });
        break;
      }

      case 'REMOVE_ADBLOCK_ALLOWLIST': {
        state.adblockAllowlist = state.adblockAllowlist.filter((d) => d !== message.domain);
        await saveState(state);
        await applyAdblockState(state);
        sendResponse({ ok: true, state });
        break;
      }

      case 'ADD_DOMAIN': {
        const clean = sanitizeDomain(message.domain);
        if (!clean) {
          sendResponse({ ok: false, error: 'INVALID' });
          return;
        }
        if (state.customDomains.includes(clean)) {
          sendResponse({ ok: false, error: 'EXISTS', state });
          return;
        }
        state.customDomains.unshift(clean);
        await saveState(state);
        await applyProxyState(state);
        sendResponse({ ok: true, domain: clean, state });
        break;
      }

      case 'REMOVE_DOMAIN': {
        state.customDomains = state.customDomains.filter((d) => d !== message.domain);
        await saveState(state);
        await applyProxyState(state);
        sendResponse({ ok: true, state });
        break;
      }

      case 'ADD_EXCLUSION': {
        const clean = sanitizeDomain(message.domain);
        if (!clean) {
          sendResponse({ ok: false, error: 'INVALID' });
          return;
        }
        if (state.exclusions.includes(clean)) {
          sendResponse({ ok: false, error: 'EXISTS', state });
          return;
        }
        state.exclusions.unshift(clean);
        await saveState(state);
        await applyProxyState(state);
        sendResponse({ ok: true, domain: clean, state });
        break;
      }

      case 'REMOVE_EXCLUSION': {
        state.exclusions = state.exclusions.filter((d) => d !== message.domain);
        await saveState(state);
        await applyProxyState(state);
        sendResponse({ ok: true, state });
        break;
      }

      case 'CHECK_ENGINE': {
        const engine = await checkLocalEngine(state.splitwireControlPort);
        if (state.connected && state.engineMode === 'splitwire') {
          await updateBadgeAndIcon(state, engine.online);
        }
        sendResponse({ engine });
        break;
      }

      case 'CLEAR_ENGINE_CACHE': {
        try {
          const res = await fetch(
            `http://127.0.0.1:${state.splitwireControlPort || 8081}/clear-cache`,
            { method: 'POST' }
          );
          sendResponse({ ok: res.ok });
        } catch (_) {
          sendResponse({ ok: false });
        }
        break;
      }

      default:
        sendResponse({ ok: false, error: 'UNKNOWN_MESSAGE' });
    }
  })();
  return true;
});
