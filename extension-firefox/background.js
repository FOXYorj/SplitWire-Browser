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
const IS_FIREFOX =
  typeof browser !== 'undefined' && Boolean(browser.proxy && browser.proxy.onRequest);

let isProbing = false;
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

// Lifecycle listeners
chrome.runtime.onInstalled.addListener(async () => {
  const state = await getState();
  await saveState(state);
  await applyProxyState(state);
});

chrome.runtime.onStartup.addListener(async () => {
  const state = await getState();
  await applyProxyState(state);
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== HEALTH_ALARM) return;
  const state = await getState();
  if (!state.connected || state.engineMode !== 'splitwire') {
    await chrome.alarms.clear(HEALTH_ALARM);
    return;
  }
  const health = await checkLocalEngine(state.splitwireControlPort);
  await updateBadgeAndIcon(state, health.online);
});

// Message API for popup
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    const state = await getState();

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
          state.connected = false;
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

        const result = await applyProxyState(next);
        const engine =
          next.engineMode === 'splitwire'
            ? await checkLocalEngine(next.splitwireControlPort)
            : { online: null, latencyMs: null };
        sendResponse({ ...result, state: next, engine });
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
