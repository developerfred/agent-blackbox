'use strict';
// Pieces every adapter needs.

/** Claude Code's PreToolUse deny reply, used when the recorder is down and failMode is "closed".
 * @param {string} reason */
function failClosedVerdict(reason) {
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}

/** Turn the recorder's verdict into what an agent without an "ask" prompt can act on.
 * @param {import('../types').Verdict | undefined} v
 * @param {boolean} canAsk
 * @param {'deny' | 'allow'} askFallback
 * @returns {import('../types').Verdict | undefined} */
function withAskFallback(v, canAsk, askFallback) {
  if (!v || v.permission !== 'ask' || canAsk) return v;
  if (askFallback === 'allow') return { ...v, permission: null, notice: v.reason };
  return { ...v, permission: 'deny', reason: `${v.reason} (this agent cannot ask you, so the call was blocked)` };
}

/** Parse a value an agent sends as a JSON string; keep it as-is when it is not JSON.
 * @param {unknown} v */
function maybeJson(v) {
  if (typeof v !== 'string') return v;
  try { return JSON.parse(v); } catch { return v; }
}

/** @param {unknown} s @returns {string} */
const str = (s) => (typeof s === 'string' ? s : '');

module.exports = { failClosedVerdict, withAskFallback, maybeJson, str };
