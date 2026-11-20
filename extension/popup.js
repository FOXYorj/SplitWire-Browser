'use strict';

let currentState = null;
let currentEngine = { online: null, latencyMs: null, data: null };
let platformDomains = {};
let timerInterval = null;
let toastTimeout = null;
let isScanning = false;

const $ = (id) => document.getElementById(id);

const COUNTRY_NAMES = {
  tr: {
    DE: 'Almanya',
    NL: 'Hollanda',
    FR: 'Fransa',
    GB: 'Birleşik Krallık',
    SE: 'İsveç',
    FI: 'Finlandiya',
    PL: 'Polonya',
    AT: 'Avusturya',
    CH: 'İsviçre',
    RO: 'Romanya',
    BG: 'Bulgaristan',
    GR: 'Yunanistan',
    HU: 'Macaristan',
    SK: 'Slovakya',
    RS: 'Sırbistan',
    HR: 'Hırvatistan',
    CZ: 'Çekya',
    BE: 'Belçika',
    DK: 'Danimarka',
    NO: 'Norveç',
    IT: 'İtalya',
    ES: 'İspanya',
    IE: 'İrlanda',
    LU: 'Lüksemburg',
    SI: 'Slovenya',
    US: 'ABD',
    CA: 'Kanada',
    SG: 'Singapur',
  },
  en: {
    DE: 'Germany',
    NL: 'Netherlands',
    FR: 'France',
    GB: 'United Kingdom',
    SE: 'Sweden',
    FI: 'Finland',
    PL: 'Poland',
    AT: 'Austria',
    CH: 'Switzerland',
    RO: 'Romania',
    BG: 'Bulgaria',
    GR: 'Greece',
    HU: 'Hungary',
    SK: 'Slovakia',
    RS: 'Serbia',
    HR: 'Croatia',
    CZ: 'Czechia',
    BE: 'Belgium',
    DK: 'Denmark',
    NO: 'Norway',
    IT: 'Italy',
    ES: 'Spain',
    IE: 'Ireland',
    LU: 'Luxembourg',
    SI: 'Slovenia',
    US: 'United States',
    CA: 'Canada',
    SG: 'Singapore',
  },
};

function t(key, vars = {}) {
  const lang = (currentState && currentState.lang) || 'tr';
  const dict = TRANSLATIONS[lang] || TRANSLATIONS.tr;
  let str = dict[key] || TRANSLATIONS.tr[key] || key;
  for (const [k, v] of Object.entries(vars)) {
    str = str.replace(`{${k}}`, String(v));
  }
  return str;
}

function getCountryLabel(code) {
  const lang = (currentState && currentState.lang) || 'tr';
  const map = COUNTRY_NAMES[lang] || COUNTRY_NAMES.tr;
  return map[code] || code || 'EU';
}

function showToast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => el.classList.remove('show'), 2400);
}

function sendMessage(payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(payload, (response) => {
      resolve(response || {});
    });
  });
}

function applyTranslations() {
  document.documentElement.lang = currentState.lang || 'tr';
  $('langLabel').textContent = (currentState.lang || 'tr').toUpperCase();

  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (key) el.textContent = t(key);
  });

  $('domainInput').placeholder = t('addDomainPlaceholder');
  $('exclusionInput').placeholder = t('exclusionPlaceholder');
  $('quickPasteInput').placeholder = t('quickPastePlaceholder');
}

function formatDuration(ms) {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const h = String(Math.floor(totalSec / 3600)).padStart(2, '0');
  const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0');
  const s = String(totalSec % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function startOrStopTimer() {
  clearInterval(timerInterval);
  const timerEl = $('sessionTimer');
  if (currentState && currentState.connected && currentState.connectedAt && !isScanning) {
    timerEl.classList.remove('hidden');
    const tick = () => {
      timerEl.textContent = formatDuration(Date.now() - currentState.connectedAt);
    };
    tick();
    timerInterval = setInterval(tick, 1000);
  } else {
    timerEl.classList.add('hidden');
    timerEl.textContent = '00:00:00';
  }
}

function countActiveDomains() {
  const set = new Set();
  for (const [key, enabled] of Object.entries(currentState.platforms || {})) {
    if (enabled && platformDomains[key]) {
      platformDomains[key].forEach((d) => set.add(d));
    }
  }
  (currentState.customDomains || []).forEach((d) => set.add(d));
  return set.size;
}

function getActiveBrowserServer() {
  const list = (currentState && currentState.browserServers) || [];
  if (list.length === 0) return null;
  const idx = (currentState.activeServerIndex || 0) % list.length;
  return list[idx] || list[0];
}

function renderChipList(containerId, items, emptyText, onRemove) {
  const container = $(containerId);
  container.innerHTML = '';

  if (!items || items.length === 0) {
    const empty = document.createElement('span');
    empty.className = 'empty-note';
    empty.textContent = emptyText;
    container.appendChild(empty);
    return;
  }

  for (const domain of items) {
    const chip = document.createElement('span');
    chip.className = 'chip';

    const label = document.createElement('span');
    label.textContent = domain;

    const btn = document.createElement('button');
    btn.className = 'chip-remove';
    btn.type = 'button';
    btn.textContent = '×';
    btn.setAttribute('aria-label', `Remove ${domain}`);
    btn.addEventListener('click', () => onRemove(domain));

    chip.appendChild(label);
    chip.appendChild(btn);
    container.appendChild(chip);
  }
}

function setScanningState(flag) {
  isScanning = flag;
  $('powerBtn').disabled = flag;
  $('switchServerBtn').disabled = flag;
  $('refreshServerBtn').disabled = flag;
  $('refreshServerBtn').classList.toggle('spinning', flag);
  $('findNewServersBtn').disabled = flag;
  renderUI();
}

function renderUI() {
  if (!currentState) return;

  // Theme & Language
  document.documentElement.setAttribute('data-theme', currentState.theme || 'dark');
  applyTranslations();

  const isLocalSplitWire = currentState.engineMode === 'splitwire';
  const isBrowserMode = currentState.engineMode === 'browser';
  const engineOffline = isLocalSplitWire && currentEngine && currentEngine.online === false;
  const activeSrv = getActiveBrowserServer();

  // Brand logo & Hero visual state
  $('brandLogo').classList.toggle('connected', currentState.connected && !isScanning);

  const hero = $('heroArea');
  hero.classList.remove('connected', 'connecting', 'warning');
  if (isScanning) {
    hero.classList.add('connecting');
  } else if (currentState.connected) {
    hero.classList.add(engineOffline ? 'warning' : 'connected');
  }

  // Status Title
  if (isScanning) {
    $('statusTitle').textContent = t('statusConnecting');
  } else if (currentState.connected) {
    if (engineOffline) {
      $('statusTitle').textContent = t('statusEngineOffline');
    } else {
      $('statusTitle').textContent =
        currentState.tunnelMode === 'full' ? t('statusConnectedFull') : t('statusConnectedSplit');
    }
  } else {
    $('statusTitle').textContent = t('statusDisconnected');
  }

  // Engine Status Pill
  const dot = $('engineDot');
  const statusText = $('engineStatusText');
  dot.className = 'dot';

  if (isBrowserMode) {
    dot.classList.add(activeSrv ? 'online' : 'neutral');
    statusText.textContent = activeSrv
      ? `${t('engineBrowserReady')} · ${activeSrv.latencyMs}ms`
      : t('engineBrowserReady');
  } else if (isLocalSplitWire) {
    if (currentEngine && currentEngine.online) {
      dot.classList.add('online');
      statusText.textContent =
        currentEngine.latencyMs != null
          ? `${t('engineReady')} · ${currentEngine.latencyMs}ms`
          : t('engineReady');
    } else {
      dot.classList.add('offline');
      statusText.textContent = t('engineOfflineShort');
    }
  } else if (currentState.engineMode === 'byedpi') {
    const port = currentState.localSocksPort || 1080;
    dot.classList.add('neutral');
    statusText.textContent = `${port === 40000 ? t('engineWarpShort') : t('engineByedpiShort')} · :${port}`;
  } else {
    dot.classList.add(currentState.customProxy.host ? 'online' : 'offline');
    statusText.textContent = currentState.customProxy.host
      ? `${currentState.customProxy.scheme} · ${currentState.customProxy.host}`
      : t('engineCustomShort');
  }

  // Active Browser Server Card (only shown in In-Browser Zero-File Mode)
  $('browserServerCard').classList.toggle('hidden', !isBrowserMode);
  if (isBrowserMode) {
    const badgeEl = $('serverCountryBadge');
    badgeEl.classList.remove('ping-medium', 'ping-slow');
    if (isScanning) {
      badgeEl.textContent = '...';
      $('serverNameText').textContent = t('serverSearching');
      $('serverSubText').textContent = t('serverHttpsNote');
    } else if (activeSrv) {
      const cc = activeSrv.country || 'EU';
      const countryName = getCountryLabel(cc);
      const cityPart = activeSrv.city ? ` · ${activeSrv.city}` : '';
      const poolCount = currentState.browserServers.length;
      if (activeSrv.latencyMs > 320) badgeEl.classList.add('ping-slow');
      else if (activeSrv.latencyMs > 150) badgeEl.classList.add('ping-medium');
      badgeEl.textContent = cc;
      $('serverNameText').textContent = `${countryName}${cityPart}`;
      $('serverSubText').textContent = `SOCKS5 · ${activeSrv.ip} · ${activeSrv.latencyMs}ms (${poolCount})`;
    } else {
      badgeEl.textContent = 'EU';
      $('serverNameText').textContent = t('serverNone');
      $('serverSubText').textContent = t('serverHttpsNote');
    }
  }

  // Inline Warning Banner (only when user picked local DPI engine & it isn't running)
  $('engineWarningBanner').classList.toggle('hidden', !engineOffline);

  // Session Timer
  startOrStopTimer();

  // Tunnel Mode Segmented Control
  document.querySelectorAll('#tunnelModeGroup .seg-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.mode === currentState.tunnelMode);
  });
  $('tunnelModeHint').textContent =
    currentState.tunnelMode === 'full' ? t('modeFullHint') : t('modeSplitHint');
  $('quickPlatformsCard').classList.toggle('hidden', currentState.tunnelMode === 'full');

  // Platform Toggles & Count
  document.querySelectorAll('input[data-platform]').forEach((input) => {
    const key = input.dataset.platform;
    input.checked = Boolean(currentState.platforms[key]);
  });
  $('activeDomainCount').textContent = t('activeSitesCount', { n: countActiveDomains() });

  // Domains & Exclusions Chips
  renderChipList('customDomainList', currentState.customDomains, t('noCustomDomains'), async (d) => {
    const res = await sendMessage({ type: 'REMOVE_DOMAIN', domain: d });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });

  renderChipList('exclusionList', currentState.exclusions, '—', async (d) => {
    const res = await sendMessage({ type: 'REMOVE_EXCLUSION', domain: d });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });

  // Settings: Engine Mode Cards
  document.querySelectorAll('#engineModeGrid .engine-card').forEach((card) => {
    card.classList.toggle('active', card.dataset.engine === currentState.engineMode);
  });

  $('browserModeSettingsCard').classList.toggle('hidden', !isBrowserMode);
  $('localSocksCard').classList.toggle('hidden', currentState.engineMode !== 'byedpi');
  $('dpiSettingsCard').classList.toggle('hidden', !isLocalSplitWire);
  $('customProxyCard').classList.toggle('hidden', currentState.engineMode !== 'custom');
  $('engineStatsRow').classList.toggle('hidden', !isLocalSplitWire);
  $('engineActionRow').classList.toggle('hidden', !isLocalSplitWire);

  // Highlight active local SOCKS5 port button
  const port = currentState.localSocksPort || 1080;
  $('presetByedpiPortBtn').classList.toggle('active-port', port === 1080);
  $('presetWarpPortBtn').classList.toggle('active-port', port === 40000);

  // Settings selects & inputs
  $('regionSelect').value = currentState.browserRegion || 'eu';
  $('presetSelect').value = currentState.preset || 'auto';
  $('dohSelect').value = currentState.dohProvider || 'cloudflare';
  $('webrtcToggle').checked = Boolean(currentState.webrtcProtection);

  $('proxySchemeSelect').value = currentState.customProxy.scheme || 'HTTPS';
  $('proxyHostInput').value = currentState.customProxy.host || '';
  $('proxyPortInput').value = currentState.customProxy.port || 443;

  // Engine Stats
  if (currentEngine && currentEngine.online && currentEngine.data && currentEngine.data.stats) {
    $('statBypassed').textContent = String(currentEngine.data.stats.bypassedRequests || 0);
    $('statCache').textContent = String(currentEngine.data.stats.dohCacheSize || 0);
    $('statLatency').textContent =
      currentEngine.latencyMs != null ? `${currentEngine.latencyMs}ms` : '--';
  } else {
    $('statBypassed').textContent = '0';
    $('statCache').textContent = '0';
    $('statLatency').textContent = '--';
  }
}

function switchTab(tabName) {
  document.querySelectorAll('.nav-tab').forEach((btn) => {
    const isActive = btn.dataset.tab === tabName;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', String(isActive));
  });
  document.querySelectorAll('.tab-panel').forEach((panel) => {
    panel.classList.toggle('active', panel.id === `panel-${tabName}`);
  });
}

function parseQuickProxyString(raw) {
  const s = (raw || '').trim();
  if (!s) return null;
  let scheme = 'HTTPS';
  let rest = s;
  const protoMatch = s.match(/^(https?|socks5h?|proxy):\/\//i);
  if (protoMatch) {
    const p = protoMatch[1].toLowerCase();
    if (p.startsWith('socks5')) scheme = 'SOCKS5';
    else if (p === 'https') scheme = 'HTTPS';
    else scheme = 'PROXY';
    rest = s.slice(protoMatch[0].length);
  }
  // Strip optional credentials & trailing slash
  rest = rest.split('/')[0];
  if (rest.includes('@')) rest = rest.split('@').pop();
  const parts = rest.split(':');
  if (parts.length < 2) return null;
  const host = parts[0].trim();
  const port = parseInt(parts[1], 10);
  if (!host || !port || port < 1 || port > 65535) return null;
  return { scheme, host, port };
}

async function runFreshServerScan() {
  if (isScanning) return;
  setScanningState(true);
  const res = await sendMessage({ type: 'DISCOVER_SERVERS' });
  if (res.state) currentState = res.state;
  setScanningState(false);

  if (res.ok && res.active) {
    showToast(t('toastServerFound', { cc: getCountryLabel(res.active.country), ms: res.active.latencyMs }));
  } else {
    showToast(t('toastNoServers'));
  }
}

function bindEvents() {
  // Tab navigation
  document.querySelectorAll('.nav-tab').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  $('manageDomainsBtn').addEventListener('click', () => switchTab('domains'));

  $('switchToBrowserFromWarn').addEventListener('click', async () => {
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { engineMode: 'browser' } });
    if (res.state) {
      currentState = res.state;
      renderUI();
      showToast(t('toastSwitchedBrowser'));
    }
  });

  // Theme toggle
  $('themeBtn').addEventListener('click', async () => {
    const nextTheme = currentState.theme === 'dark' ? 'light' : 'dark';
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { theme: nextTheme } });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });

  // Language toggle
  $('langBtn').addEventListener('click', async () => {
    const nextLang = currentState.lang === 'tr' ? 'en' : 'tr';
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { lang: nextLang } });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });

  // Big One-Click Power Toggle
  $('powerBtn').addEventListener('click', async () => {
    if (isScanning) return;
    const willScan =
      !currentState.connected &&
      currentState.engineMode === 'browser' &&
      (!getActiveBrowserServer() ||
        Date.now() - (getActiveBrowserServer().verifiedAt || 0) > 20 * 60_000);

    if (willScan) setScanningState(true);

    const res = await sendMessage({ type: 'TOGGLE_CONNECT' });
    if (res.state) currentState = res.state;
    if (res.engine) currentEngine = res.engine;

    if (willScan) {
      setScanningState(false);
    } else {
      renderUI();
    }

    if (res.error === 'CUSTOM_PROXY_MISSING') {
      showToast(t('customProxyMissing'));
      switchTab('settings');
      return;
    }
    if (res.error === 'NO_SERVERS') {
      showToast(t('toastNoServers'));
      return;
    }

    showToast(currentState.connected ? t('toastConnected') : t('toastDisconnected'));
  });

  // Switch to next verified in-browser server
  $('switchServerBtn').addEventListener('click', async () => {
    if (isScanning) return;
    const needsScan = !currentState.browserServers || currentState.browserServers.length <= 1;
    if (needsScan) {
      await runFreshServerScan();
      return;
    }
    const res = await sendMessage({ type: 'SWITCH_SERVER' });
    if (res.state) currentState = res.state;
    renderUI();
    if (res.ok && res.active) {
      showToast(t('toastServerSwitched', { cc: getCountryLabel(res.active.country), ms: res.active.latencyMs }));
    }
  });

  // Force fresh scan of EU/global servers
  $('refreshServerBtn').addEventListener('click', runFreshServerScan);
  $('findNewServersBtn').addEventListener('click', runFreshServerScan);

  // Region filter change
  $('regionSelect').addEventListener('change', async (e) => {
    const res = await sendMessage({
      type: 'UPDATE_STATE',
      patch: { browserRegion: e.target.value, browserServers: [], activeServerIndex: 0 },
    });
    if (res.state) {
      currentState = res.state;
      renderUI();
      await runFreshServerScan();
    }
  });

  // Tunnel Mode Switcher
  document.querySelectorAll('#tunnelModeGroup .seg-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const mode = btn.dataset.mode;
      if (mode === currentState.tunnelMode) return;
      const res = await sendMessage({ type: 'UPDATE_STATE', patch: { tunnelMode: mode } });
      if (res.state) {
        currentState = res.state;
        renderUI();
      }
    });
  });

  // Quick Platform Toggles
  document.querySelectorAll('input[data-platform]').forEach((input) => {
    input.addEventListener('change', async () => {
      const key = input.dataset.platform;
      const res = await sendMessage({
        type: 'UPDATE_STATE',
        patch: { platforms: { [key]: input.checked } },
      });
      if (res.state) {
        currentState = res.state;
        renderUI();
      }
    });
  });

  // Add Custom Domain Form
  $('addDomainForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('domainInput');
    const val = input.value.trim();
    if (!val) return;

    const res = await sendMessage({ type: 'ADD_DOMAIN', domain: val });
    if (res.ok && res.state) {
      input.value = '';
      currentState = res.state;
      renderUI();
      showToast(`${t('toastDomainAdded')}: ${res.domain}`);
    } else if (res.error === 'EXISTS') {
      showToast(t('toastDomainExists'));
    } else {
      showToast(t('toastDomainInvalid'));
    }
  });

  // Add Current Active Tab's Hostname (1-click)
  $('addCurrentTabBtn').addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const activeTab = tabs && tabs[0];
      if (!activeTab || !activeTab.url || !/^https?:\/\//i.test(activeTab.url)) {
        showToast(t('toastTabUnavailable'));
        return;
      }
      const host = new URL(activeTab.url).hostname.replace(/^www\./, '');
      const res = await sendMessage({ type: 'ADD_DOMAIN', domain: host });
      if (res.ok && res.state) {
        currentState = res.state;
        renderUI();
        showToast(`${t('toastDomainAdded')}: ${res.domain}`);
      } else if (res.error === 'EXISTS') {
        showToast(t('toastDomainExists'));
      } else {
        showToast(t('toastTabUnavailable'));
      }
    } catch (_) {
      showToast(t('toastTabUnavailable'));
    }
  });

  // Add Exclusion Domain Form
  $('addExclusionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('exclusionInput');
    const val = input.value.trim();
    if (!val) return;

    const res = await sendMessage({ type: 'ADD_EXCLUSION', domain: val });
    if (res.ok && res.state) {
      input.value = '';
      currentState = res.state;
      renderUI();
      showToast(`${t('toastDomainAdded')}: ${res.domain}`);
    } else if (res.error === 'EXISTS') {
      showToast(t('toastDomainExists'));
    } else {
      showToast(t('toastDomainInvalid'));
    }
  });

  // Engine Mode Cards
  document.querySelectorAll('#engineModeGrid .engine-card').forEach((card) => {
    card.addEventListener('click', async () => {
      const engineMode = card.dataset.engine;
      if (engineMode === currentState.engineMode) return;
      const res = await sendMessage({ type: 'UPDATE_STATE', patch: { engineMode } });
      if (res.state) {
        currentState = res.state;
        currentEngine = res.engine || currentEngine;
        renderUI();
      }
    });
  });

  // Local SOCKS5 Port quick presets (ByeDPI 1080 / WARP 40000)
  $('presetByedpiPortBtn').addEventListener('click', async () => {
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { localSocksPort: 1080 } });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });
  $('presetWarpPortBtn').addEventListener('click', async () => {
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { localSocksPort: 40000 } });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });

  // Quick Paste Proxy Parser
  $('quickPasteInput').addEventListener('input', (e) => {
    const parsed = parseQuickProxyString(e.target.value);
    if (parsed) {
      $('proxySchemeSelect').value = parsed.scheme;
      $('proxyHostInput').value = parsed.host;
      $('proxyPortInput').value = parsed.port;
    }
  });

  // DPI Preset Change (syncs live to local engine)
  $('presetSelect').addEventListener('change', async (e) => {
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { preset: e.target.value } });
    if (res.state) {
      currentState = res.state;
      currentEngine = res.engine || currentEngine;
      renderUI();
      showToast(t('toastPresetSaved'));
    }
  });

  // DoH Provider Change (syncs live to local engine)
  $('dohSelect').addEventListener('change', async (e) => {
    const res = await sendMessage({ type: 'UPDATE_STATE', patch: { dohProvider: e.target.value } });
    if (res.state) {
      currentState = res.state;
      currentEngine = res.engine || currentEngine;
      renderUI();
      showToast(t('toastDohSaved'));
    }
  });

  // Open Chrome/Edge/Brave Built-in Secure DNS Settings (or show Firefox path)
  const openDns = () => {
    if (/firefox/i.test(navigator.userAgent)) {
      showToast(t('toastFirefoxDnsHint'));
      return;
    }
    chrome.tabs.create({ url: 'chrome://settings/security' });
  };
  $('openBrowserDnsBtn').addEventListener('click', openDns);
  $('openBrowserDnsBtnTop').addEventListener('click', openDns);

  // Save Custom Proxy
  $('saveCustomProxyBtn').addEventListener('click', async () => {
    const scheme = $('proxySchemeSelect').value;
    const host = $('proxyHostInput').value.trim();
    const port = parseInt($('proxyPortInput').value, 10) || 443;

    const res = await sendMessage({
      type: 'UPDATE_STATE',
      patch: { customProxy: { scheme, host, port } },
    });
    if (res.state) {
      currentState = res.state;
      renderUI();
      showToast(t('toastProxySaved'));
    }
  });

  // WebRTC Protection Toggle
  $('webrtcToggle').addEventListener('change', async (e) => {
    const res = await sendMessage({
      type: 'UPDATE_STATE',
      patch: { webrtcProtection: e.target.checked },
    });
    if (res.state) {
      currentState = res.state;
      renderUI();
    }
  });

  // Test Local DPI Engine
  $('testEngineBtn').addEventListener('click', async () => {
    const res = await sendMessage({ type: 'CHECK_ENGINE' });
    currentEngine = res.engine || { online: false };
    renderUI();
    if (currentEngine.online) {
      showToast(t('toastEngineOk', { ms: currentEngine.latencyMs ?? 1 }));
    } else {
      showToast(t('toastEngineFail'));
    }
  });

  // Clear Engine DoH Cache
  $('clearCacheBtn').addEventListener('click', async () => {
    const res = await sendMessage({ type: 'CLEAR_ENGINE_CACHE' });
    if (res.ok) {
      const check = await sendMessage({ type: 'CHECK_ENGINE' });
      currentEngine = check.engine || currentEngine;
      renderUI();
      showToast(t('toastCacheCleared'));
    } else {
      showToast(t('toastEngineFail'));
    }
  });
}

// Initialize popup
(async function init() {
  bindEvents();
  const res = await sendMessage({ type: 'GET_STATE' });
  currentState = res.state;
  currentEngine = res.engine || { online: null };
  platformDomains = res.platformDomains || {};
  renderUI();
})();
