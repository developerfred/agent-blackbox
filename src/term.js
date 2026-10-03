'use strict';
// Terminal colors, shared by the CLI and the text reports.

/** @typedef {(s: unknown) => string} Paint */

/**
 * ANSI painters that return the text unchanged when color is off.
 * @param {boolean | undefined} enabled
 * @returns {{ red: Paint, green: Paint, yellow: Paint, dim: Paint, bold: Paint, cyan: Paint, bySeverity: Record<string, Paint> }}
 */
function palette(enabled) {
  /** @param {number} code @returns {Paint} */
  const c = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const red = c(31), green = c(32), yellow = c(33), dim = c(2), bold = c(1), cyan = c(36);
  return { red, green, yellow, dim, bold, cyan, bySeverity: { high: red, medium: yellow, low: dim, none: green } };
}

module.exports = { palette };
