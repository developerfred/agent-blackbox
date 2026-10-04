"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.baseName = exports.num = exports.escHtml = exports.exists = exports.isFile = exports.isDir = exports.pushCapped = exports.defined = exports.claudeDir = exports.sha256 = void 0;
exports.readJson = readJson;
exports.parseLine = parseLine;
exports.readJsonl = readJsonl;
exports.stablePath = stablePath;
// Small helpers shared by several modules.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
exports.sha256 = sha256;
/** Claude Code's config folder (CLAUDE_CONFIG_DIR or ~/.claude). */
const claudeDir = () => process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
exports.claudeDir = claudeDir;
/** Parsed JSON file, or `fallback` when it is missing or invalid. */
function readJson(file, fallback = null) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    catch {
        return fallback;
    }
}
/** Parse one JSON line; null when it is not valid JSON. */
function parseLine(line) {
    try {
        return JSON.parse(line);
    }
    catch {
        return null;
    }
}
/** Every valid JSON line of a file, in order (missing file: empty list). */
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
 */
const defined = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v != null));
exports.defined = defined;
/** `list` plus `item` (once), keeping only the newest `max`. */
const pushCapped = (list, item, max = 500) => (list.includes(item) ? list : [...list, item].slice(-max));
exports.pushCapped = pushCapped;
const statOf = (p) => { try {
    return fs.statSync(p);
}
catch {
    return null;
} };
const isDir = (p) => !!statOf(p)?.isDirectory();
exports.isDir = isDir;
const isFile = (p) => !!statOf(p)?.isFile();
exports.isFile = isFile;
/** Does anything exist at this path? */
const exists = (p) => { try {
    fs.accessSync(p);
    return true;
}
catch {
    return false;
} };
exports.exists = exists;
// Homebrew installs into versioned folders (…/Cellar/<name>/<version>/…) that
// disappear on upgrade; its stable symlinks live in …/opt/<name>/. Anything that
// must survive `brew upgrade` (hooks, the recorder service) points at the stable path.
function stablePath(p) {
    const m = /^(.*)\/Cellar\/([^/]+)\/[^/]+\/(.*)$/.exec(p);
    if (!m)
        return p;
    const opt = path.join(m[1], 'opt', m[2], m[3]);
    return fs.existsSync(opt) ? opt : p;
}
const HTML_ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
/** HTML-escape any value (null and undefined become the empty string). */
const escHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => HTML_ESC[ch]);
exports.escHtml = escHtml;
/** A count with thousands separators ("1,234"); nothing becomes 0. */
const num = (x) => Number(x || 0).toLocaleString('en-US');
exports.num = num;
/** Last path segment (POSIX or ~/ style), or `fallback` for an empty path. */
const baseName = (p, fallback = '') => p.split('/').filter(Boolean).pop() || fallback;
exports.baseName = baseName;
