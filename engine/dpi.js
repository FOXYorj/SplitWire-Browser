'use strict';

/**
 * Pure user-space DPI Bypass transforms (Zero kernel drivers, zero WinDivert).
 *
 * Implements RFC-compliant TLS Record Fragmentation (--tlsrec) and
 * TCP ClientHello / HTTP Host segmentation (--split), inspired by
 * ByeDPI / SpoofDPI strategies used in SplitWire-Turkey.
 */

const PRESETS = {
  auto: {
    id: 'auto',
    name: 'Otomatik (Önerilen)',
    mode: 'tlsrec_sni',
    splitOffset: 2,
    delayMs: 2,
    httpMixHost: false,
  },
  ttnet: {
    id: 'ttnet',
    name: 'Türk Telekom / TTNET',
    mode: 'tlsrec_1plus_s',
    splitOffset: 1,
    delayMs: 2,
    httpMixHost: true,
  },
  superonline: {
    id: 'superonline',
    name: 'Superonline (Agresif)',
    mode: 'tlsrec_multi',
    splitOffset: 1,
    delayMs: 4,
    httpMixHost: true,
  },
  vodafone: {
    id: 'vodafone',
    name: 'Vodafone / Kablonet',
    mode: 'tcp_split',
    splitOffset: 2,
    delayMs: 3,
    httpMixHost: false,
  },
};

/**
 * Locate the SNI hostname byte range inside a TLS ClientHello handshake payload
 * (payload starts right after the 5-byte TLS record header).
 *
 * Returns { start, end } relative to `payload`, or null if not found.
 */
function findSniRange(payload) {
  try {
    // Handshake type 0x01 = ClientHello
    if (!payload || payload.length < 44 || payload[0] !== 0x01) return null;

    let pos = 4; // handshake type (1) + handshake length (3)
    pos += 2; // client_version (2)
    pos += 32; // random (32)

    if (pos >= payload.length) return null;
    const sessionIdLen = payload[pos];
    pos += 1 + sessionIdLen;

    if (pos + 2 > payload.length) return null;
    const cipherSuitesLen = payload.readUInt16BE(pos);
    pos += 2 + cipherSuitesLen;

    if (pos + 1 > payload.length) return null;
    const compressionLen = payload[pos];
    pos += 1 + compressionLen;

    if (pos + 2 > payload.length) return null;
    const extensionsLen = payload.readUInt16BE(pos);
    pos += 2;

    const extensionsEnd = Math.min(pos + extensionsLen, payload.length);
    while (pos + 4 <= extensionsEnd) {
      const extType = payload.readUInt16BE(pos);
      const extLen = payload.readUInt16BE(pos + 2);
      pos += 4;

      if (extType === 0x0000 && pos + extLen <= extensionsEnd) {
        // Server Name Indication extension
        if (extLen >= 5) {
          const listLen = payload.readUInt16BE(pos);
          if (listLen >= 3 && payload[pos + 2] === 0x00) {
            const nameLen = payload.readUInt16BE(pos + 3);
            const nameStart = pos + 5;
            const nameEnd = nameStart + nameLen;
            if (nameEnd <= pos + extLen) {
              return { start: nameStart, end: nameEnd };
            }
          }
        }
      }
      pos += extLen;
    }
  } catch (_) {
    return null;
  }
  return null;
}

/**
 * Wrap a payload slice into a valid TLS Handshake record header.
 */
function makeTlsRecord(versionHi, versionLo, slice) {
  const header = Buffer.allocUnsafe(5);
  header[0] = 0x16; // Handshake
  header[1] = versionHi;
  header[2] = versionLo;
  header.writeUInt16BE(slice.length, 3);
  return Buffer.concat([header, slice]);
}

/**
 * Produce an array of Buffer chunks to send sequentially over TCP for a TLS ClientHello.
 * Guaranteed to never corrupt TLS framing even if the packet is truncated or non-TLS.
 */
function splitTlsClientHello(chunk, presetKey = 'auto') {
  const preset = PRESETS[presetKey] || PRESETS.auto;

  // Check if this looks like a TLS Handshake record (0x16 0x03 0x00..0x04)
  const isTlsHandshake =
    chunk.length > 10 &&
    chunk[0] === 0x16 &&
    chunk[1] === 0x03 &&
    chunk[2] <= 0x04 &&
    chunk[5] === 0x01;

  if (!isTlsHandshake) {
    // Non-TLS or non-ClientHello: simple safe 2-part TCP split
    if (chunk.length <= 4) return [chunk];
    return [chunk.subarray(0, 2), chunk.subarray(2)];
  }

  const versionHi = chunk[1];
  const versionLo = chunk[2];
  const recordLen = chunk.readUInt16BE(3);
  const fullRecordBytes = 5 + recordLen;

  // Safety guard: only rewrite TLS record headers if the complete TLS record
  // arrived in this single chunk. Otherwise fall back to pure TCP splitting.
  const canRewriteTlsRecord =
    preset.mode !== 'tcp_split' && chunk.length >= fullRecordBytes && recordLen > 10;

  if (!canRewriteTlsRecord) {
    // Pure TCP segmentation (never touches TLS record headers)
    const payload = chunk.subarray(5);
    const sni = findSniRange(payload);
    if (sni) {
      const mid = 5 + sni.start + Math.max(1, Math.floor((sni.end - sni.start) / 2));
      const p1 = Math.min(preset.splitOffset || 2, mid - 1);
      if (p1 > 0 && mid < chunk.length) {
        return [chunk.subarray(0, p1), chunk.subarray(p1, mid), chunk.subarray(mid)];
      }
    }
    const cut = Math.min(preset.splitOffset || 2, chunk.length - 1);
    return [chunk.subarray(0, cut), chunk.subarray(cut)];
  }

  const payload = chunk.subarray(5, fullRecordBytes);
  const trailing = chunk.length > fullRecordBytes ? chunk.subarray(fullRecordBytes) : null;
  const sni = findSniRange(payload);

  const records = [];

  if (preset.mode === 'tlsrec_multi' && sni && sni.end - sni.start >= 3) {
    // Superonline aggressive mode: split into 3 TLS records around & inside SNI
    const split1 = Math.max(1, sni.start + 1);
    const split2 = Math.max(split1 + 1, sni.start + Math.floor((sni.end - sni.start) / 2) + 1);
    records.push(makeTlsRecord(versionHi, versionLo, payload.subarray(0, split1)));
    records.push(makeTlsRecord(versionHi, versionLo, payload.subarray(split1, split2)));
    records.push(makeTlsRecord(versionHi, versionLo, payload.subarray(split2)));
  } else if (preset.mode === 'tlsrec_1plus_s' && sni) {
    // ByeDPI-style `--tlsrec 1+s`: split 1 byte into the SNI hostname
    const cut = Math.min(Math.max(1, sni.start + 1), payload.length - 1);
    const rec1 = makeTlsRecord(versionHi, versionLo, payload.subarray(0, cut));
    const rec2 = makeTlsRecord(versionHi, versionLo, payload.subarray(cut));
    // Also split first byte of rec1 at TCP level (--split 1)
    records.push(rec1.subarray(0, 1));
    records.push(rec1.subarray(1));
    records.push(rec2);
  } else {
    // Default `tlsrec_sni`: split right in the middle of the SNI domain name
    const cut = sni
      ? Math.min(Math.max(1, sni.start + Math.floor((sni.end - sni.start) / 2)), payload.length - 1)
      : Math.min(2, payload.length - 1);
    records.push(makeTlsRecord(versionHi, versionLo, payload.subarray(0, cut)));
    records.push(makeTlsRecord(versionHi, versionLo, payload.subarray(cut)));
  }

  if (trailing && trailing.length > 0) {
    records.push(trailing);
  }

  return records;
}

/**
 * Split / obfuscate a plain HTTP request so DPI inspecting the `Host:` header fails.
 */
function splitHttpRequest(rawBuffer, presetKey = 'auto') {
  const preset = PRESETS[presetKey] || PRESETS.auto;
  let buf = rawBuffer;

  if (preset.httpMixHost) {
    const str = buf.toString('latin1');
    const modified = str.replace(/\r\nHost:/i, '\r\nhOsT:');
    buf = Buffer.from(modified, 'latin1');
  }

  // Find `Host:` header value to split right through the hostname
  const idx = buf.indexOf('Host:', 0, 'latin1');
  const idxAlt = idx === -1 ? buf.indexOf('hOsT:', 0, 'latin1') : idx;
  if (idxAlt !== -1 && idxAlt + 9 < buf.length) {
    const cut = idxAlt + 8;
    return [buf.subarray(0, cut), buf.subarray(cut)];
  }

  if (buf.length > 4) {
    return [buf.subarray(0, 3), buf.subarray(3)];
  }
  return [buf];
}

/**
 * Write chunks sequentially with TCP_NODELAY and micro-delay so the OS
 * transmits them in distinct TCP segments rather than coalescing them.
 */
function writeChunksSequentially(socket, chunks, delayMs, onComplete) {
  let index = 0;

  function writeNext() {
    if (socket.destroyed) {
      if (onComplete) onComplete(new Error('Socket destroyed'));
      return;
    }
    if (index >= chunks.length) {
      if (onComplete) onComplete(null);
      return;
    }

    const part = chunks[index++];
    socket.write(part, (err) => {
      if (err) {
        if (onComplete) onComplete(err);
        return;
      }
      if (index < chunks.length) {
        if (delayMs > 0) {
          setTimeout(writeNext, delayMs);
        } else {
          setImmediate(writeNext);
        }
      } else if (onComplete) {
        onComplete(null);
      }
    });
  }

  writeNext();
}

module.exports = {
  PRESETS,
  findSniRange,
  splitTlsClientHello,
  splitHttpRequest,
  writeChunksSequentially,
};
