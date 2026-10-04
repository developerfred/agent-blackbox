"use strict";
// OpenAI Codex CLI. Its hooks (~/.codex/hooks.json) deliberately follow Claude
// Code's: the same event names, snake_case payloads with session_id, cwd,
// tool_name, tool_input, tool_response, and the same PreToolUse deny reply.
// What differs is the tools and what a hook may do:
//   - PreToolUse covers Bash, apply_patch and MCP tool calls, not every tool
//     Codex has (web search and other built-ins do not reach it);
//   - a hook cannot hand a decision to the human, so an "ask" becomes a block.
const path = require("path");
const os = require("os");
const shared_1 = require("./shared");
const EVENTS = ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'];
const TOOL_EVENTS = new Set(['PreToolUse', 'PostToolUse']);
const codexHome = () => process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
/** The files an apply_patch patch adds, updates, deletes or moves to. */
function patchFiles(patch) {
    const files = [];
    for (const m of patch.matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/gm))
        files.push(m[1].trim());
    return files;
}
function patchText(input) {
    for (const k of ['command', 'patch', 'input'])
        if (typeof input[k] === 'string')
            return input[k];
    if (Array.isArray(input.command))
        return input.command.join('\n'); // argv form: ["apply_patch", "<patch>"]
    return '';
}
const adapter = {
    id: 'codex',
    name: 'OpenAI Codex CLI',
    capabilities: { preTool: true, ask: false, postTool: true, prompt: true, session: true },
    decode(native) {
        const event = native.hook_event_name;
        if (!EVENTS.includes(event) || !native.session_id)
            return null;
        const ev = { ...native, agent: 'codex', session_id: String(native.session_id), prompt_id: native.turn_id };
        if (TOOL_EVENTS.has(event) && native.tool_name === 'apply_patch') {
            const input = native.tool_input || {};
            const patch = patchText(input);
            const files = patchFiles(patch);
            // the patch text is content, not a target: keep it out of `command`, which the policy reads as one
            ev.tool_name = 'Edit';
            ev.tool_input = { file_path: files[0] || '', file_paths: files, new_string: patch };
        }
        else if (TOOL_EVENTS.has(event) && native.tool_name === 'web_search') {
            ev.tool_name = 'WebSearch';
        }
        return ev;
    },
    encode(res, native, opts = {}) {
        const v = (0, shared_1.withAskFallback)(res && res.verdict, adapter.capabilities.ask, opts.askFallback || 'deny');
        if (!v)
            return {};
        const out = {};
        if (v.permission === 'deny' && native.hook_event_name === 'PreToolUse') {
            out.hookSpecificOutput = { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: v.agentMessage };
            out.systemMessage = v.reason;
        }
        else if (v.notice)
            out.systemMessage = v.notice;
        return Object.keys(out).length ? { stdout: out } : {};
    },
    failClosed(ev, reason) { return ev.hook_event_name === 'PreToolUse' ? { stdout: (0, shared_1.failClosedVerdict)(reason) } : null; },
    hooksFile: {
        file: () => path.join(codexHome(), 'hooks.json'),
        add(json, command) {
            json.hooks ||= {};
            for (const e of EVENTS) {
                const group = { hooks: [{ type: 'command', command, timeout: 10 }] };
                (json.hooks[e] ||= []).push(TOOL_EVENTS.has(e) ? { matcher: '.*', ...group } : group);
            }
            return EVENTS;
        },
        remove(json) { (0, shared_1.stripOurs)(json, true); },
        note: 'Codex hooks are experimental. If yours is off, enable them (the `codex_hooks` feature in ~/.codex/config.toml) and restart Codex.',
    },
};
module.exports = adapter;
