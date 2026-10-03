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
  for (const ev of c.before || []) {
    if (ev.prompt) policy.userPrompt({ session_id, prompt: ev.prompt });
    else policy.postToolUse({ session_id, tool_name: ev.post, tool_input: ev.input, tool_response: ev.response });
  }
  const d = policy.preToolUse({ session_id, tool_name: c.call.tool, tool_input: c.call.input });
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

module.exports = { runCase, runAll };
