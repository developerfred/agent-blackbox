'use strict';
// Pieces every adapter needs.
/** Claude Code's PreToolUse deny reply, used when the recorder is down and failMode is "closed".
 * @param {string} reason */
function failClosedVerdict(reason) {
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}
/** Turn the recorder's verdict into what an agent without an "ask" prompt can act on.
 * @param {import('../types').Verdict | null | undefined} v
 * @param {boolean} canAsk
 * @param {'deny' | 'allow'} askFallback
 * @returns {import('../types').Verdict | null | undefined} */
function withAskFallback(v, canAsk, askFallback) {
    if (!v || v.permission !== 'ask' || canAsk)
        return v;
    if (askFallback === 'allow')
        return { ...v, permission: null, notice: v.reason };
    return { ...v, permission: 'deny', reason: `${v.reason} (this agent cannot ask you, so the call was blocked)` };
}
/** Parse a value an agent sends as a JSON string; keep it as-is when it is not JSON.
 * @param {unknown} v */
function maybeJson(v) {
    if (typeof v !== 'string')
        return v;
    try {
        return JSON.parse(v);
    }
    catch {
        return v;
    }
}
/** @param {unknown} s @returns {string} */
const str = (s) => (typeof s === 'string' ? s : '');
/** Marks a hook command as ours, as an argument (some agents run commands without a shell, so no trailing comment). */
const MARKER = '--agent-blackbox-hook';
/** @param {any} h */
const isOurs = (h) => !!h && typeof h.command === 'string' && h.command.includes('agent-blackbox-hook');
/** Remove our hook entries from `json.hooks`, keeping the user's own, and drop what is left empty.
 * @param {Record<string, any>} json
 * @param {boolean} nested true for { hooks: [{ command }] } groups, false for flat [{ command }] entries */
function stripOurs(json, nested) {
    const hooks = json.hooks || {};
    for (const ev of Object.keys(hooks)) {
        hooks[ev] = (hooks[ev] || []).map((/** @type {any} */ g) => (nested ? { ...g, hooks: (g.hooks || []).filter((/** @type {any} */ h) => !isOurs(h)) } : g))
            .filter((/** @type {any} */ g) => (nested ? g.hooks.length : !isOurs(g)));
        if (!hooks[ev].length)
            delete hooks[ev];
    }
    if (Object.keys(hooks).length)
        json.hooks = hooks;
    else
        delete json.hooks;
}
module.exports = { failClosedVerdict, withAskFallback, maybeJson, str, MARKER, isOurs, stripOurs };
