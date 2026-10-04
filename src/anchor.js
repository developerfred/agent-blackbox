'use strict';
// Automatic, opt-in anchoring: when the user configures a target, the daemon
// commits a Merkle batch now and then and publishes the head and root there.
// Nothing is sent unless `config.anchor` names a file or a webhook, and what
// goes out is only the head and root: sequence numbers, hashes, a signature
// and a key id. No payload, summary, session id or path.
const fs = require('fs');
const path = require('path');

const DEFAULTS = { every: 100, minutes: 60 };

/**
 * Normalised settings, or null when automatic anchoring is off.
 * @param {import('./types').Config} cfg
 * @returns {{ every: number, minutes: number, file?: string, webhook?: string } | null}
 */
function settings(cfg) {
  const a = /** @type {any} */ (cfg.anchor);
  if (!a || typeof a !== 'object' || (!a.file && !a.webhook)) return null;
  const every = Number(a.every);
  const minutes = Number(a.minutes);
  return {
    every: every >= 1 ? Math.floor(every) : DEFAULTS.every,
    minutes: minutes > 0 ? minutes : DEFAULTS.minutes,
    file: typeof a.file === 'string' ? a.file : undefined,
    webhook: typeof a.webhook === 'string' ? a.webhook : undefined,
  };
}

/**
 * Is a new batch due? Enough new records, or some new records and enough time.
 * @param {{ every: number, minutes: number }} s
 * @param {{ newRecords: number, lastAt: number | null, now: number }} x
 */
function due(s, { newRecords, lastAt, now }) {
  if (newRecords < 1) return false;
  if (newRecords >= s.every) return true;
  return lastAt == null || now - lastAt >= s.minutes * 60 * 1000;
}

/**
 * Publish one anchor to the configured targets. Throws when any target fails,
 * so the caller keeps it and tries again.
 * @param {Record<string, unknown>} anchor
 * @param {{ file?: string, webhook?: string }} s
 * @param {typeof fetch} [fetchImpl]
 */
async function publish(anchor, s, fetchImpl = fetch) {
  const errors = [];
  if (s.file) {
    try {
      fs.mkdirSync(path.dirname(s.file), { recursive: true });
      fs.appendFileSync(s.file, JSON.stringify(anchor) + '\n');
    } catch (e) { errors.push(`file: ${/** @type {Error} */ (e).message}`); }
  }
  if (s.webhook) {
    try {
      if (!/^https?:\/\//.test(s.webhook)) throw new Error('webhook must be an http(s) URL');
      const res = await fetchImpl(s.webhook, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(anchor), signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (e) { errors.push(`webhook: ${/** @type {Error} */ (e).message}`); }
  }
  if (errors.length) throw new Error(errors.join('; '));
}

module.exports = { settings, due, publish, DEFAULTS };
