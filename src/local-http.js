'use strict';
// A minimal JSON-over-HTTP client for the recorder on 127.0.0.1. Loading
// node's `http` costs about 8 ms per process, which every hook pays; `net` is
// already loaded, so the hook and the CLI speak HTTP/1.1 over it directly.
const net = require('net');

/** @param {Buffer} buf */
function decodeChunked(buf) {
  /** @type {Buffer[]} */
  const out = [];
  for (let i = 0; i < buf.length;) {
    const eol = buf.indexOf('\r\n', i);
    if (eol < 0) break;
    const size = parseInt(buf.toString('latin1', i, eol), 16);
    if (!size) break;
    out.push(buf.subarray(eol + 2, eol + 2 + size));
    i = eol + 2 + size + 2;
  }
  return Buffer.concat(out);
}

/**
 * One request to the recorder. Resolves with the status and the parsed JSON
 * body (null if empty or not JSON); rejects on a socket error or timeout.
 * @param {{ port: number, method?: string, path: string, token?: string, body?: string | object | null, timeout?: number }} opts
 * @returns {Promise<{ status: number, body: any }>}
 */
function request({ port, method = 'GET', path, token = '', body = null, timeout = 5000 }) {
  return new Promise((resolve, reject) => {
    const payload = body == null ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const head = [
      `${method} ${path} HTTP/1.1`, `host: 127.0.0.1:${port}`, 'connection: close', 'content-type: application/json',
      `x-blackbox-token: ${token}`, ...(payload ? [`content-length: ${payload.length}`] : []), '', '',
    ].join('\r\n');
    /** @type {Buffer[]} */
    const chunks = [];
    const sock = net.connect({ host: '127.0.0.1', port }, () => sock.write(payload ? Buffer.concat([Buffer.from(head), payload]) : head));
    sock.setTimeout(timeout, () => sock.destroy(new Error('timeout')));
    sock.on('data', (c) => chunks.push(c));
    sock.on('error', reject);
    sock.on('close', () => {
      const raw = Buffer.concat(chunks);
      const split = raw.indexOf('\r\n\r\n');
      if (split < 0) return reject(new Error('bad response'));
      const header = raw.toString('latin1', 0, split);
      const status = Number(/^HTTP\/1\.\d (\d{3})/.exec(header)?.[1]);
      let data = raw.subarray(split + 4);
      if (/^transfer-encoding:\s*chunked/im.test(header)) data = decodeChunked(data);
      let parsed = null;
      try { parsed = JSON.parse(data.toString('utf8') || 'null'); } catch { /* not JSON */ }
      resolve({ status, body: parsed });
    });
  });
}

module.exports = { request };
