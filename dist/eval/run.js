"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runCase = runCase;
exports.runAll = runAll;
exports.runCaseVia = runCaseVia;
exports.runAgent = runAgent;
// Runs the evasion corpus through the policy. Used by the tests and by
// `blackbox eval`, which prints the catch rate, false alarms and known gaps.
const policy_1 = require("../src/policy");
const paths_1 = require("../src/paths");
const adapters_1 = require("../src/adapters");
const corpus_1 = require("./corpus");
const native_1 = require("./native");
const sessionFor = (base, ev) => (ev.session ? `${base}-${ev.session}` : base);
/** A step before the call, in the canonical (Claude Code) event format. */
function canon(ev, session_id) {
    if ('start' in ev)
        return { kind: 'start', session_id, cwd: ev.cwd };
    if ('prompt' in ev)
        return { kind: 'prompt', session_id, prompt: ev.prompt };
    return { kind: 'post', session_id, cwd: ev.cwd, tool: ev.post, input: ev.input, response: ev.response };
}
function runCase(c, mode = 'ask') {
    const state = { sessions: {} };
    const policy = new policy_1.Policy({ ...paths_1.DEFAULT_CONFIG, mode }, state, 'eval-salt', { protect: [], readFile: (f) => (c.files || {})[f.replace(/^\.\//, '')] || null });
    const session_id = `eval-${c.id}`;
    // events may name another session (ev.session) and its folder (ev.cwd); { start: true } is a SessionStart
    for (const ev of c.before || []) {
        const sid = sessionFor(session_id, ev);
        if ('start' in ev)
            policy.sessionStart({ session_id: sid, cwd: ev.cwd });
        else if ('prompt' in ev)
            policy.userPrompt({ session_id: sid, prompt: ev.prompt });
        else
            policy.postToolUse({ session_id: sid, cwd: ev.cwd, tool_name: ev.post, tool_input: ev.input, tool_response: ev.response });
    }
    const sid = sessionFor(session_id, c.call);
    const d = policy.preToolUse({ session_id: sid, tool_name: c.call.tool, tool_input: c.call.input });
    const blocked = !!d && ['ask', 'deny'].includes(d.decision);
    return { id: c.id, expect: c.expect, gap: c.gap || null, decision: d ? d.decision : 'none', rule: d ? d.rule : null, blocked, pass: (c.expect === 'block') === blocked };
}
function runAll(mode) {
    const results = corpus_1.CASES.map((c) => runCase(c, mode));
    const attacks = results.filter((r) => r.expect === 'block' && !r.gap);
    const benign = results.filter((r) => r.expect === 'allow');
    const gaps = results.filter((r) => r.gap);
    return {
        results,
        caught: attacks.filter((r) => r.blocked).length, attacks: attacks.length,
        falseAlarms: benign.filter((r) => r.blocked).length, benign: benign.length,
        gapsOpen: gaps.filter((r) => !r.blocked).length, gaps: gaps.length,
    };
}
/** One case as an agent would send it: every event is re-written in the agent's format, decoded by its adapter, and only then judged. A case is not applicable when the agent has no hook for one of its events. */
function runCaseVia(c, agent, mode = 'ask') {
    const adapter = (0, adapters_1.getAdapter)(agent);
    const encode = native_1.ENCODERS[agent];
    const state = { sessions: {} };
    const policy = new policy_1.Policy({ ...paths_1.DEFAULT_CONFIG, mode }, state, 'eval-salt', { protect: [], readFile: (f) => (c.files || {})[f.replace(/^\.\//, '')] || null });
    const session_id = `eval-${c.id}`;
    const decode = (e) => {
        const native = encode(e);
        return native ? adapter.decode(native) : null;
    };
    const before = (c.before || []).map((ev) => ({ ev, d: decode(canon(ev, sessionFor(session_id, ev))) }));
    const call = decode({ kind: 'pre', session_id: sessionFor(session_id, c.call), tool: c.call.tool, input: c.call.input });
    const events = [...before.map((x) => x.d), call];
    if (events.some((d) => !d))
        return { id: c.id, expect: c.expect, gap: c.gap || null, applicable: false };
    for (const { ev, d } of before) {
        const x = d;
        if ('start' in ev)
            policy.sessionStart(x);
        else if ('prompt' in ev)
            policy.userPrompt(x);
        else
            policy.postToolUse(x);
    }
    const dec = policy.preToolUse(call);
    const blocked = !!dec && ['ask', 'deny'].includes(dec.decision);
    return { id: c.id, expect: c.expect, gap: c.gap || null, applicable: true, decision: dec ? dec.decision : 'none', rule: dec ? dec.rule : null, blocked, pass: (c.expect === 'block') === blocked };
}
/** The corpus through one adapter: what it catches, what it falsely alarms on, which cases the agent cannot express at all, and where the answer differs from the same case in Claude Code's own format. */
function runAgent(agent, mode) {
    const rows = corpus_1.CASES.map((c) => ({ ...runCaseVia(c, agent, mode), base: runCase(c, mode) }));
    const live = rows.filter((r) => r.applicable);
    const attacks = live.filter((r) => r.expect === 'block' && !r.gap);
    const benign = live.filter((r) => r.expect === 'allow');
    return {
        agent, total: rows.length, applicable: live.length,
        notApplicable: rows.filter((r) => !r.applicable).map((r) => r.id),
        caught: attacks.filter((r) => r.blocked).length, attacks: attacks.length,
        falseAlarms: benign.filter((r) => r.blocked).length, benign: benign.length,
        // same case, different answer than in Claude Code's format: a loss (or gain) in translation
        diverged: live.filter((r) => r.blocked !== r.base.blocked).map((r) => ({ id: r.id, claude: r.base.decision, via: r.decision })),
        results: rows,
    };
}
