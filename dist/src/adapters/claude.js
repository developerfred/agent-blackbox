'use strict';
// Claude Code: the reference adapter. Its hook payloads are the canonical
// event format, and the recorder's reply already has Claude Code's shape.
const { failClosedVerdict } = require('./shared');
/** @type {import('../types').Adapter} */
const adapter = {
    id: 'claude',
    name: 'Claude Code',
    // every lifecycle event, and "ask" is a native permission decision
    capabilities: { preTool: true, ask: true, postTool: true, prompt: true, session: true },
    decode(native) { return /** @type {import('../types').HookEvent} */ (native); },
    encode(res) { return { stdout: res && res.stdout ? res.stdout : null }; },
    failClosed(ev, reason) { return ev.hook_event_name === 'PreToolUse' ? { stdout: failClosedVerdict(reason) } : null; },
};
module.exports = adapter;
