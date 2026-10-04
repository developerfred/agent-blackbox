'use strict';
// Runs the evasion corpus through the policy. Used by the tests and by
// `blackbox eval`, which prints the catch rate, false alarms and known gaps.
const { Policy } = require('../src/policy');
const { DEFAULT_CONFIG } = require('../src/paths');
const { CASES } = require('./corpus');
/** @param {any} c @param {import('../src/types').Mode} [mode] */
function runCase(c, mode = 'ask') {
    const state = { sessions: {} };
    const policy = new Policy({ ...DEFAULT_CONFIG, mode }, state, 'eval-salt', { protect: [], readFile: (f) => (c.files || {})[f.replace(/^\.\//, '')] || null });
    const session_id = `eval-${c.id}`;
    // events may name another session (ev.session) and its folder (ev.cwd); { start: true } is a SessionStart
    for (const ev of c.before || []) {
        const sid = ev.session ? `${session_id}-${ev.session}` : session_id;
        if (ev.start)
            policy.sessionStart({ session_id: sid, cwd: ev.cwd });
        else if (ev.prompt)
            policy.userPrompt({ session_id: sid, prompt: ev.prompt });
        else
            policy.postToolUse({ session_id: sid, cwd: ev.cwd, tool_name: ev.post, tool_input: ev.input, tool_response: ev.response });
    }
    const sid = c.call.session ? `${session_id}-${c.call.session}` : session_id;
    const d = policy.preToolUse({ session_id: sid, tool_name: c.call.tool, tool_input: c.call.input });
    const blocked = !!d && ['ask', 'deny'].includes(d.decision);
    return { id: c.id, expect: c.expect, gap: c.gap || null, decision: d ? d.decision : 'none', rule: d ? d.rule : null, blocked, pass: (c.expect === 'block') === blocked };
}
/** @param {import('../src/types').Mode} [mode] */
function runAll(mode) {
    const results = CASES.map((c) => runCase(c, mode));
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
/**
 * One case as an agent would send it: every event is re-written in the agent's
 * format, decoded by its adapter, and only then judged. A case is not
 * applicable when the agent has no hook for one of its events.
 * @param {any} c @param {string} agent @param {import('../src/types').Mode} [mode]
 */
function runCaseVia(c, agent, mode = 'ask') {
    const { getAdapter } = require('../src/adapters');
    const { ENCODERS } = require('./native');
    const adapter = getAdapter(agent);
    const encode = ENCODERS[agent];
    const state = { sessions: {} };
    const policy = new Policy({ ...DEFAULT_CONFIG, mode }, state, 'eval-salt', { protect: [], readFile: (/** @type {string} */ f) => (c.files || {})[f.replace(/^\.\//, '')] || null });
    const session_id = `eval-${c.id}`;
    /** @param {any} ev @param {'pre' | 'post'} [kind] */
    const decoded = (ev, kind = 'post') => {
        const sid = ev.session ? `${session_id}-${ev.session}` : session_id;
        const native = encode(ev.start ? { kind: 'start', session_id: sid, cwd: ev.cwd }
            : ev.prompt ? { kind: 'prompt', session_id: sid, prompt: ev.prompt }
                : { kind, session_id: sid, cwd: ev.cwd, tool: kind === 'pre' ? ev.tool : ev.post, input: ev.input, response: ev.response });
        return native ? adapter.decode(native) : null;
    };
    const events = [...(c.before || []).map((/** @type {any} */ ev) => ({ ev, d: decoded(ev) })), { ev: c.call, d: decoded({ ...c.call, tool: c.call.tool }, 'pre') }];
    if (events.some((x) => !x.d))
        return { id: c.id, expect: c.expect, gap: c.gap || null, applicable: false };
    for (const { ev, d } of events.slice(0, -1)) {
        const x = /** @type {import('../src/types').HookEvent} */ (d);
        if (ev.start)
            policy.sessionStart(x);
        else if (ev.prompt)
            policy.userPrompt(x);
        else
            policy.postToolUse(x);
    }
    const last = /** @type {import('../src/types').HookEvent} */ (events[events.length - 1].d);
    const dec = policy.preToolUse(last);
    const blocked = !!dec && ['ask', 'deny'].includes(dec.decision);
    return { id: c.id, expect: c.expect, gap: c.gap || null, applicable: true, decision: dec ? dec.decision : 'none', rule: dec ? dec.rule : null, blocked, pass: (c.expect === 'block') === blocked };
}
/**
 * The corpus through one adapter: what it catches, what it falsely alarms on,
 * which cases the agent cannot express at all, and where the answer differs
 * from the same case in Claude Code's own format.
 * @param {string} agent @param {import('../src/types').Mode} [mode]
 */
function runAgent(agent, mode) {
    const rows = CASES.map((c) => ({ ...runCaseVia(c, agent, mode), base: runCase(c, mode) }));
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
module.exports = { runCase, runAll, runCaseVia, runAgent };
