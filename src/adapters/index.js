'use strict';
// Agent adapters. The recorder, the policy and the ledger speak one canonical
// event format (Claude Code's hook events: PreToolUse, PostToolUse, ... with
// Claude Code's tool names). An adapter is the only code that knows one
// agent's own format: it decodes the agent's hook payload into a canonical
// event, and encodes the recorder's verdict into what the agent understands.
//
// Adapters load lazily: every hook process pays for what it requires.

const IDS = ['claude'];

/** @param {string} id @returns {import('../types').Adapter} */
function getAdapter(id) {
  if (!IDS.includes(id)) throw new Error(`unknown agent "${id}" (known: ${IDS.join(', ')})`);
  return require(`./${id}`);
}

module.exports = { IDS, getAdapter };
