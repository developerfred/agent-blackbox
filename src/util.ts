// Small helpers shared by several modules.
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';

export const sha256 = (data: crypto.BinaryLike): string => crypto.createHash('sha256').update(data).digest('hex');

/** Claude Code's config folder (CLAUDE_CONFIG_DIR or ~/.claude). */
export const claudeDir = (): string => process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');

/** Parsed JSON file, or `fallback` when it is missing or invalid. */
export function readJson<T = any>(file: string, fallback: T = null as T): any | T {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/** Parse one JSON line; null when it is not valid JSON. */
export function parseLine(line: string): any {
  try { return JSON.parse(line); } catch { return null; }
}

/** Every valid JSON line of a file, in order (missing file: empty list). */
export function readJsonl(file: string): any[] {
  let text: string;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
  const out: any[] = [];
  for (const line of text.split('\n')) {
    const rec = line && parseLine(line);
    if (rec) out.push(rec);
  }
  return out;
}

/**
 * A copy of `obj` without keys whose value is null or undefined, so options
 * can be spread over defaults without overwriting them.
 */
export const defined = <T extends object>(obj: T): Partial<T> =>
  Object.fromEntries(Object.entries(obj).filter(([, v]) => v != null)) as Partial<T>;

/** `list` plus `item` (once), keeping only the newest `max`. */
export const pushCapped = <T>(list: T[], item: T, max = 500): T[] => (list.includes(item) ? list : [...list, item].slice(-max));

const statOf = (p: string): fs.Stats | null => { try { return fs.statSync(p); } catch { return null; } };
export const isDir = (p: string): boolean => !!statOf(p)?.isDirectory();
export const isFile = (p: string): boolean => !!statOf(p)?.isFile();
/** Does anything exist at this path? */
export const exists = (p: string): boolean => { try { fs.accessSync(p); return true; } catch { return false; } };

// Homebrew installs into versioned folders (…/Cellar/<name>/<version>/…) that
// disappear on upgrade; its stable symlinks live in …/opt/<name>/. Anything that
// must survive `brew upgrade` (hooks, the recorder service) points at the stable path.
export function stablePath(p: string): string {
  const m = /^(.*)\/Cellar\/([^/]+)\/[^/]+\/(.*)$/.exec(p);
  if (!m) return p;
  const opt = path.join(m[1], 'opt', m[2], m[3]);
  return fs.existsSync(opt) ? opt : p;
}

const HTML_ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
/** HTML-escape any value (null and undefined become the empty string). */
export const escHtml = (s: unknown): string => String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => HTML_ESC[ch]);

/** A count with thousands separators ("1,234"); nothing becomes 0. */
export const num = (x: unknown): string => Number(x || 0).toLocaleString('en-US');

/** Last path segment (POSIX or ~/ style), or `fallback` for an empty path. */
export const baseName = (p: string, fallback = ''): string => p.split('/').filter(Boolean).pop() || fallback;
