'use strict';
// Small helpers shared by several modules.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
/** @param {crypto.BinaryLike} data */
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
/** Claude Code's config folder (CLAUDE_CONFIG_DIR or ~/.claude). */
const claudeDir = () => process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
/**
 * Parsed JSON file, or `fallback` when it is missing or invalid.
 * @template T
 * @param {string} file
 * @param {T} [fallback]
 * @returns {any | T}
 */
function readJson(file, fallback = /** @type {any} */ (null)) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    catch {
        return fallback;
    }
}
/**
 * Parse one JSON line; null when it is not valid JSON.
 * @param {string} line
 * @returns {any}
 */
function parseLine(line) {
    try {
        return JSON.parse(line);
    }
    catch {
        return null;
    }
}
/**
 * Every valid JSON line of a file, in order (missing file: empty list).
 * @param {string} file
 * @returns {any[]}
 */
function readJsonl(file) {
    let text;
    try {
        text = fs.readFileSync(file, 'utf8');
    }
    catch {
        return [];
    }
    const out = [];
    for (const line of text.split('\n')) {
        const rec = line && parseLine(line);
        if (rec)
            out.push(rec);
    }
    return out;
}
/**
 * A copy of `obj` without keys whose value is null or undefined, so options
 * can be spread over defaults without overwriting them.
 * @template {object} T
 * @param {T} obj
 * @returns {Partial<T>}
 */
const defined = (obj) => /** @type {Partial<T>} */ (Object.fromEntries(Object.entries(/** @type {Record<string, unknown>} */ (obj)).filter(([, v]) => v != null)));
/**
 * `list` plus `item` (once), keeping only the newest `max`.
 * @template T
 * @param {T[]} list
 * @param {T} item
 * @param {number} [max]
 * @returns {T[]}
 */
const pushCapped = (list, item, max = 500) => (list.includes(item) ? list : [...list, item].slice(-max));
/** @param {string} p */
const statOf = (p) => { try {
    return fs.statSync(p);
}
catch {
    return null;
} };
/** @param {string} p */
const isDir = (p) => !!statOf(p)?.isDirectory();
/** @param {string} p */
const isFile = (p) => !!statOf(p)?.isFile();
/** Does anything exist at this path? @param {string} p */
const exists = (p) => { try {
    fs.accessSync(p);
    return true;
}
catch {
    return false;
} };
/**
 * Last path segment (POSIX or ~/ style), or `fallback` for an empty path.
 * @param {string} p
 * @param {string} [fallback]
 */
const baseName = (p, fallback = '') => p.split('/').filter(Boolean).pop() || fallback;
module.exports = { baseName, isDir, isFile, exists, sha256, claudeDir, readJson, parseLine, readJsonl, defined, pushCapped };
