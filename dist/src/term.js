"use strict";
// Terminal colors, shared by the CLI and the text reports.
Object.defineProperty(exports, "__esModule", { value: true });
exports.palette = palette;
/** ANSI painters that return the text unchanged when color is off. */
function palette(enabled) {
    const c = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
    const red = c(31), green = c(32), yellow = c(33), dim = c(2), bold = c(1), cyan = c(36);
    return { red, green, yellow, dim, bold, cyan, bySeverity: { high: red, medium: yellow, low: dim, none: green } };
}
