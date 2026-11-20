'use strict';

const https = require('https');
const dns = require('dns');
const net = require('net');

/**
 * Direct-IP DNS-over-HTTPS (DoH) providers.
 * Connecting straight to IP addresses prevents ISP UDP-53 DNS hijacking
 * from interfering with initial DoH endpoint resolution.
 */
const DOH_PROVIDERS = {
  cloudflare: {
    name: 'Cloudflare (1.1.1.1)',
    host: '1.1.1.1',
    port: 443,
    servername: 'cloudflare-dns.com',
    path: (domain) => `/dns-query?name=${encodeURIComponent(domain)}&type=A`,
    headers: { Accept: 'application/dns-json', Host: 'cloudflare-dns.com' },
  },
  google: {
    name: 'Google (8.8.8.8)',
    host: '8.8.8.8',
    port: 443,
    servername: 'dns.google',
    path: (domain) => `/resolve?name=${encodeURIComponent(domain)}&type=A`,
    headers: { Accept: 'application/dns-json', Host: 'dns.google' },
  },
  quad9: {
    name: 'Quad9 (9.9.9.9)',
    host: '9.9.9.9',
    port: 5053,
    servername: 'dns.quad9.net',
    path: (domain) => `/dns-query?name=${encodeURIComponent(domain)}&type=A`,
    headers: { Accept: 'application/dns-json', Host: 'dns.quad9.net' },
  },
  adguard: {
    name: 'AdGuard DNS',
    host: '94.140.14.14',
    port: 443,
    servername: 'dns.adguard-dns.com',
    path: (domain) => `/resolve?name=${encodeURIComponent(domain)}&type=A`,
    headers: { Accept: 'application/dns-json', Host: 'dns.adguard-dns.com' },
  },
};

class DohResolver {
  constructor(providerKey = 'cloudflare') {
    this.providerKey = DOH_PROVIDERS[providerKey] ? providerKey : 'cloudflare';
    this.cache = new Map(); // domain -> { ip, expiresAt }
    this.inflight = new Map(); // domain -> Promise<string>
    this.stats = { hits: 0, misses: 0, fallbacks: 0 };
    // Keep-alive HTTPS agent for low-latency DoH queries
    this.agent = new https.Agent({ keepAlive: true, maxSockets: 16 });
  }

  setProvider(providerKey) {
    if (DOH_PROVIDERS[providerKey] && providerKey !== this.providerKey) {
      this.providerKey = providerKey;
      this.cache.clear();
    }
  }

  clearCache() {
    this.cache.clear();
  }

  getCacheSize() {
    return this.cache.size;
  }

  async resolve(hostname) {
    // Strip brackets from IPv6 literals if present
    const cleanHost = hostname.replace(/^\[|\]$/g, '').trim().toLowerCase();

    // Already an IP address -> return immediately
    if (net.isIP(cleanHost)) {
      return cleanHost;
    }

    // Localhost shortcuts
    if (cleanHost === 'localhost') {
      return '127.0.0.1';
    }

    // Check cache
    const now = Date.now();
    const cached = this.cache.get(cleanHost);
    if (cached && cached.expiresAt > now) {
      this.stats.hits++;
      return cached.ip;
    }

    // Deduplicate concurrent lookups for the same domain
    if (this.inflight.has(cleanHost)) {
      return this.inflight.get(cleanHost);
    }

    this.stats.misses++;
    const promise = this._resolveWithFallback(cleanHost).finally(() => {
      this.inflight.delete(cleanHost);
    });

    this.inflight.set(cleanHost, promise);
    return promise;
  }

  async _resolveWithFallback(domain) {
    // Try primary selected provider first
    const order = [this.providerKey];
    if (this.providerKey !== 'cloudflare') order.push('cloudflare');
    if (this.providerKey !== 'google') order.push('google');

    for (const key of order) {
      try {
        const result = await this._queryProvider(DOH_PROVIDERS[key], domain);
        if (result && result.ip) {
          const ttlMs = Math.min(Math.max((result.ttl || 300) * 1000, 60_000), 3_600_000);
          this.cache.set(domain, { ip: result.ip, expiresAt: Date.now() + ttlMs });
          return result.ip;
        }
      } catch (_) {
        // Try next provider
      }
    }

    // Final fallback: system DNS
    this.stats.fallbacks++;
    return new Promise((resolve, reject) => {
      dns.lookup(domain, { family: 4 }, (err, address) => {
        if (err) {
          dns.lookup(domain, (err2, addr2) => {
            if (err2) return reject(err2);
            resolve(addr2);
          });
          return;
        }
        resolve(address);
      });
    });
  }

  _queryProvider(provider, domain) {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: provider.host,
          port: provider.port,
          servername: provider.servername,
          path: provider.path(domain),
          method: 'GET',
          headers: provider.headers,
          agent: this.agent,
          timeout: 3000,
        },
        (res) => {
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`DoH HTTP ${res.statusCode}`));
          }

          let raw = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            raw += chunk;
            if (raw.length > 65536) {
              req.destroy(new Error('DoH response too large'));
            }
          });
          res.on('end', () => {
            try {
              const json = JSON.parse(raw);
              if (Array.isArray(json.Answer)) {
                // Find first A record (type 1)
                const aRec = json.Answer.find(
                  (rec) => rec.type === 1 && typeof rec.data === 'string' && net.isIPv4(rec.data)
                );
                if (aRec) {
                  return resolve({ ip: aRec.data, ttl: aRec.TTL || 300 });
                }
              }
              reject(new Error('No A record in DoH response'));
            } catch (err) {
              reject(err);
            }
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error('DoH query timeout'));
      });
      req.on('error', reject);
      req.end();
    });
  }
}

module.exports = { DohResolver, DOH_PROVIDERS };
