"use strict";
// Agent adapters. The recorder, the policy and the ledger speak one canonical
// event format (Claude Code's hook events: PreToolUse, PostToolUse, ... with
// Claude Code's tool names). An adapter is the only code that knows one
// agent's own format: it decodes the agent's hook payload into a canonical
// event, and encodes the recorder's verdict into what the agent understands.
//
// Adapters load lazily: every hook process pays for what it requires.
Object.defineProperty(exports, "__esModule", { value: true });
exports.IDS = void 0;
exports.getAdapter = getAdapter;
exports.IDS = ['claude', 'codex', 'cursor', 'gemini'];
function getAdapter(id) {
    if (!exports.IDS.includes(id))
        throw new Error(`unknown agent "${id}" (known: ${exports.IDS.join(', ')})`);
    // loaded on demand: a hook process pays only for the adapter it uses
    return require(`./${id}`);
}
