'use strict';

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { DohResolver, DOH_PROVIDERS } = require('./doh');
const {
  PRESETS,
  splitTlsClientHello,
  splitHttpRequest,
  writeChunksSequentially,
} = require('./dpi');

const VERSION = '1.0.0';
const CONFIG_PATH = path.join(__dirname, 'config.json');

function loadConfig() {
  const defaults = {
    proxyHost: '127.0.0.1',
    proxyPort: 8080,
    controlPort: 8081,
    preset: 'auto',
    dohProvider: 'cloudflare',
  };
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return { ...defaults, ...parsed };
  } catch (_) {
    return defaults;
  }
}

function saveConfig(cfg) {
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', 'utf8');
  } catch (_) {
    // Non-fatal if read-only
  }
}

const config = loadConfig();
const doh = new DohResolver(config.dohProvider);

const stats = {
  startedAt: Date.now(),
  totalRequests: 0,
  bypassedRequests: 0,
  activeConnections: 0,
  recentDomains: [], // most recent 10 unique domains
};

function recordDomain(host) {
  if (!host) return;
  const clean = host.toLowerCase();
  const idx = stats.recentDomains.indexOf(clean);
  if (idx !== -1) stats.recentDomains.splice(idx, 1);
  stats.recentDomains.unshift(clean);
  if (stats.recentDomains.length > 10) stats.recentDomains.pop();
}

function parseAuthority(authority) {
  // Handle IPv6 like [::1]:443 or host:port
  if (authority.startsWith('[')) {
    const closeBracket = authority.indexOf(']');
    const host = authority.slice(1, closeBracket);
    const port = parseInt(authority.slice(closeBracket + 2), 10) || 443;
    return { host, port };
  }
  const lastColon = authority.lastIndexOf(':');
  if (lastColon === -1) return { host: authority, port: 443 };
  return {
    host: authority.slice(0, lastColon),
    port: parseInt(authority.slice(lastColon + 1), 10) || 443,
  };
}

function safeDestroy(sock) {
  if (sock && !sock.destroyed) {
    sock.destroy();
  }
}

/**
 * Main HTTP / HTTPS CONNECT Proxy Server
 */
const proxyServer = http.createServer(async (req, res) => {
  stats.totalRequests++;

  let targetUrl;
  try {
    targetUrl = new URL(req.url);
  } catch (_) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('SplitWire Browser Engine: Bad Proxy Request');
    return;
  }

  const host = targetUrl.hostname;
  const port = parseInt(targetUrl.port, 10) || 80;
  recordDomain(host);

  let ip;
  try {
    ip = await doh.resolve(host);
  } catch (err) {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`DNS resolution failed for ${host}: ${err.message}`);
    return;
  }

  const preset = PRESETS[config.preset] || PRESETS.auto;
  const clientSocket = req.socket;
  const remoteSocket = net.createConnection({ host: ip, port });
  remoteSocket.setNoDelay(true);
  remoteSocket.setTimeout(30_000);

  stats.activeConnections++;
  stats.bypassedRequests++;
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    safeDestroy(remoteSocket);
  };

  remoteSocket.on('connect', () => {
    // Reconstruct raw HTTP request with path-only URI
    const pathAndQuery = `${targetUrl.pathname}${targetUrl.search}` || '/';
    let rawHeaders = `${req.method} ${pathAndQuery} HTTP/${req.httpVersion}\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const k = req.rawHeaders[i];
      const v = req.rawHeaders[i + 1];
      if (k.toLowerCase() === 'proxy-connection') continue;
      rawHeaders += `${k}: ${v}\r\n`;
    }
    rawHeaders += '\r\n';

    const chunks = splitHttpRequest(Buffer.from(rawHeaders, 'latin1'), config.preset);
    writeChunksSequentially(remoteSocket, chunks, preset.delayMs, (err) => {
      if (err) {
        cleanup();
        safeDestroy(clientSocket);
        return;
      }
      req.pipe(remoteSocket);
      remoteSocket.pipe(clientSocket);
    });
  });

  remoteSocket.on('timeout', () => cleanup());
  remoteSocket.on('error', () => {
    cleanup();
    if (!res.headersSent) {
      try {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('Upstream connection error');
      } catch (_) {}
    } else {
      safeDestroy(clientSocket);
    }
  });
  remoteSocket.on('close', cleanup);
  clientSocket.on('error', cleanup);
  clientSocket.on('close', cleanup);
});

/**
 * HTTPS / WebSocket CONNECT tunnel with TLS Record & TCP Splitting
 */
proxyServer.on('connect', async (req, clientSocket, head) => {
  stats.totalRequests++;
  const { host, port } = parseAuthority(req.url);
  recordDomain(host);

  let ip;
  try {
    ip = await doh.resolve(host);
  } catch (_) {
    if (!clientSocket.destroyed) {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      clientSocket.end();
    }
    return;
  }

  const preset = PRESETS[config.preset] || PRESETS.auto;
  const remoteSocket = net.createConnection({ host: ip, port });
  remoteSocket.setNoDelay(true);
  remoteSocket.setTimeout(60_000);
  clientSocket.setNoDelay(true);

  stats.activeConnections++;
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    stats.activeConnections = Math.max(0, stats.activeConnections - 1);
    safeDestroy(remoteSocket);
    safeDestroy(clientSocket);
  };

  remoteSocket.on('connect', () => {
    if (clientSocket.destroyed) {
      cleanup();
      return;
    }

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const handleFirstPacket = (firstChunk) => {
      if (!firstChunk || firstChunk.length === 0) {
        clientSocket.pipe(remoteSocket);
        remoteSocket.pipe(clientSocket);
        return;
      }

      stats.bypassedRequests++;
      const chunks = splitTlsClientHello(firstChunk, config.preset);

      // Pause client reads while transmitting split ClientHello so ordering is strictly preserved
      clientSocket.pause();
      writeChunksSequentially(remoteSocket, chunks, preset.delayMs, (err) => {
        if (err) {
          cleanup();
          return;
        }
        clientSocket.resume();
        clientSocket.pipe(remoteSocket);
        remoteSocket.pipe(clientSocket);
      });
    };

    if (head && head.length > 0) {
      handleFirstPacket(head);
    } else {
      clientSocket.once('data', handleFirstPacket);
    }
  });

  remoteSocket.on('timeout', cleanup);
  remoteSocket.on('error', () => {
    if (!clientSocket.destroyed && !clientSocket.writableEnded) {
      try {
        clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      } catch (_) {}
    }
    cleanup();
  });
  remoteSocket.on('close', cleanup);
  clientSocket.on('error', cleanup);
  clientSocket.on('close', cleanup);
});

proxyServer.on('clientError', (err, socket) => {
  safeDestroy(socket);
});

/**
 * Localhost-only Control API for the SplitWire Browser Extension
 */
function isAllowedOrigin(origin) {
  if (!origin) return true; // Local curl / CLI
  return (
    origin.startsWith('chrome-extension://') ||
    origin.startsWith('moz-extension://') ||
    origin.startsWith('extension://')
  );
}

const controlServer = http.createServer((req, res) => {
  const origin = req.headers.origin || '';
  if (!isAllowedOrigin(origin)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Forbidden origin' }));
    return;
  }

  const corsHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  };
  if (origin) {
    corsHeaders['Access-Control-Allow-Origin'] = origin;
    corsHeaders['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    corsHeaders['Access-Control-Allow-Headers'] = 'Content-Type';
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  if (req.method === 'GET' && req.url === '/status') {
    res.writeHead(200, corsHeaders);
    res.end(
      JSON.stringify({
        running: true,
        name: 'SplitWire Browser Engine',
        version: VERSION,
        proxyHost: config.proxyHost,
        proxyPort: config.proxyPort,
        preset: config.preset,
        dohProvider: config.dohProvider,
        availablePresets: Object.keys(PRESETS),
        availableDohProviders: Object.keys(DOH_PROVIDERS),
        uptimeSec: Math.floor((Date.now() - stats.startedAt) / 1000),
        stats: {
          totalRequests: stats.totalRequests,
          bypassedRequests: stats.bypassedRequests,
          activeConnections: stats.activeConnections,
          dohCacheSize: doh.getCacheSize(),
          dohHits: doh.stats.hits,
          recentDomains: stats.recentDomains,
        },
      })
    );
    return;
  }

  if (req.method === 'POST' && req.url === '/config') {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 8192) req.destroy();
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.preset && PRESETS[data.preset]) {
          config.preset = data.preset;
        }
        if (data.dohProvider && DOH_PROVIDERS[data.dohProvider]) {
          config.dohProvider = data.dohProvider;
          doh.setProvider(data.dohProvider);
        }
        saveConfig(config);
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ ok: true, preset: config.preset, dohProvider: config.dohProvider }));
      } catch (err) {
        res.writeHead(400, corsHeaders);
        res.end(JSON.stringify({ ok: false, error: 'Invalid JSON' }));
      }
    });
    return;
  }

  if (req.method === 'POST' && req.url === '/clear-cache') {
    doh.clearCache();
    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (req.method === 'POST' && req.url === '/shutdown') {
    res.writeHead(200, corsHeaders);
    res.end(JSON.stringify({ ok: true, message: 'Shutting down' }));
    setTimeout(() => {
      proxyServer.close();
      controlServer.close();
      process.exit(0);
    }, 100);
    return;
  }

  res.writeHead(404, corsHeaders);
  res.end(JSON.stringify({ error: 'Not found' }));
});

// Start listening strictly on 127.0.0.1
proxyServer.listen(config.proxyPort, config.proxyHost, () => {
  controlServer.listen(config.controlPort, config.proxyHost, () => {
    console.log('');
    console.log('  ====================================================');
    console.log(`   SplitWire Browser — Sürücüsüz DPI Motoru v${VERSION}`);
    console.log('  ====================================================');
    console.log(`   Proxy Adresi   : http://${config.proxyHost}:${config.proxyPort}`);
    console.log(`   Kontrol API    : http://${config.proxyHost}:${config.controlPort}/status`);
    console.log(`   DPI Stratejisi : ${PRESETS[config.preset]?.name || config.preset}`);
    console.log(`   DoH Sağlayıcı  : ${DOH_PROVIDERS[config.dohProvider]?.name || config.dohProvider}`);
    console.log('   WinDivert      : KULLANILMIYOR (Antivirüs dostu)');
    console.log('  ====================================================');
    console.log('   Tarayıcı uzantısından tek tıkla bağlanabilirsiniz.');
    console.log('   Durdurmak için CTRL+C tuşlarına basın.\n');
  });
});

proxyServer.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[HATA] Port ${config.proxyPort} zaten kullanımda. SplitWire Motoru zaten çalışıyor olabilir.`);
  } else {
    console.error('[HATA] Proxy sunucusu başlatılamadı:', err.message);
  }
  process.exit(1);
});

controlServer.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[HATA] Kontrol portu ${config.controlPort} zaten kullanımda.`);
  } else {
    console.error('[HATA] Kontrol sunucusu başlatılamadı:', err.message);
  }
  process.exit(1);
});
