"use strict";
// Pieces every adapter needs.
Object.defineProperty(exports, "__esModule", { value: true });
exports.isOurs = exports.MARKER = exports.str = void 0;
exports.failClosedVerdict = failClosedVerdict;
exports.withAskFallback = withAskFallback;
exports.maybeJson = maybeJson;
exports.stripOurs = stripOurs;
/** Claude Code's PreToolUse deny reply, used when the recorder is down and failMode is "closed". */
function failClosedVerdict(reason) {
    return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}
/** Turn the recorder's verdict into what an agent without an "ask" prompt can act on. */
function withAskFallback(v, canAsk, askFallback) {
    if (!v || v.permission !== 'ask' || canAsk)
        return v;
    if (askFallback === 'allow')
        return { ...v, permission: null, notice: v.reason };
    return { ...v, permission: 'deny', reason: `${v.reason} (this agent cannot ask you, so the call was blocked)` };
}
/** Parse a value an agent sends as a JSON string; keep it as-is when it is not JSON. */
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
const str = (s) => (typeof s === 'string' ? s : '');
exports.str = str;
/** Marks a hook command as ours, as an argument (some agents run commands without a shell, so no trailing comment). */
exports.MARKER = '--agent-blackbox-hook';
const isOurs = (h) => !!h && typeof h.command === 'string' && h.command.includes('agent-blackbox-hook');
exports.isOurs = isOurs;
/** Remove our hook entries from `json.hooks`, keeping the user's own, and drop what is left empty.
 * `nested`: true for { hooks: [{ command }] } groups, false for flat [{ command }] entries. */
function stripOurs(json, nested) {
    const hooks = json.hooks || {};
    for (const ev of Object.keys(hooks)) {
        hooks[ev] = (hooks[ev] || []).map((g) => (nested ? { ...g, hooks: (g.hooks || []).filter((h) => !(0, exports.isOurs)(h)) } : g))
            .filter((g) => (nested ? g.hooks.length : !(0, exports.isOurs)(g)));
        if (!hooks[ev].length)
            delete hooks[ev];
    }
    if (Object.keys(hooks).length)
        json.hooks = hooks;
    else
        delete json.hooks;
}
