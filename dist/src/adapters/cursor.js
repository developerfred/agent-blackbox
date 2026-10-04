"use strict";
// Cursor (editor and agent). Hooks live in ~/.cursor/hooks.json, one command
// per event name, each event with its own payload and its own reply:
//   beforeShellExecution / beforeMCPExecution  { permission: allow|deny|ask, user_message, agent_message }
//   beforeReadFile                              { permission } (the file content is in the payload)
//   beforeSubmitPrompt                          { continue }
// What that means for enforcement:
//   - shell and MCP calls can be blocked or put to the human before they run;
//   - file reads are seen with their content (taint is learned) but never blocked;
//   - file edits arrive only afterFileEdit: recorded, not gated. The memory-write
//     rule cannot stop a write in Cursor, it can only be seen afterwards.
// Only the events above are registered; Cursor's other hook points are left alone.
const path = require("path");
const os = require("os");
const shared_1 = require("./shared");
/** native event -> canonical event */
const EVENTS = {
    beforeShellExecution: 'PreToolUse',
    afterShellExecution: 'PostToolUse',
    beforeMCPExecution: 'PreToolUse',
    afterMCPExecution: 'PostToolUse',
    beforeReadFile: 'PostToolUse',
    afterFileEdit: 'PostToolUse',
    beforeSubmitPrompt: 'UserPromptSubmit',
    stop: 'Stop',
};
const GATED = new Set(['beforeShellExecution', 'beforeMCPExecution']);
/** The MCP server's name: Cursor names the tool, not always the server. */
function mcpServer(n) {
    let name = (0, shared_1.str)(n.server) || (0, shared_1.str)(n.server_name);
    if (!name && (0, shared_1.str)(n.url)) {
        try {
            name = new URL(n.url).hostname;
        }
        catch { /* not a URL */ }
    }
    if (!name && (0, shared_1.str)(n.command))
        name = path.basename(n.command.trim().split(/\s+/)[0]);
    return (name || 'cursor').replace(/[^\w.-]/g, '_');
}
const adapter = {
    id: 'cursor',
    name: 'Cursor',
    capabilities: { preTool: true, ask: true, postTool: true, prompt: true, session: false },
    decode(native) {
        const event = EVENTS[native.hook_event_name];
        const sid = (0, shared_1.str)(native.conversation_id) || (0, shared_1.str)(native.session_id);
        if (!event || !sid)
            return null;
        const ev = {
            hook_event_name: event, agent: 'cursor', session_id: sid,
            cwd: (0, shared_1.str)(native.cwd) || (Array.isArray(native.workspace_roots) ? (0, shared_1.str)(native.workspace_roots[0]) : '') || undefined,
            prompt_id: (0, shared_1.str)(native.generation_id) || undefined,
            tool_use_id: (0, shared_1.str)(native.generation_id) || undefined,
        };
        switch (native.hook_event_name) {
            case 'beforeShellExecution':
                Object.assign(ev, { tool_name: 'Bash', tool_input: { command: (0, shared_1.str)(native.command) } });
                break;
            case 'afterShellExecution':
                Object.assign(ev, { tool_name: 'Bash', tool_input: { command: (0, shared_1.str)(native.command) }, tool_response: native.output });
                break;
            case 'beforeMCPExecution':
                Object.assign(ev, { tool_name: `mcp__${mcpServer(native)}__${(0, shared_1.str)(native.tool_name)}`, tool_input: (0, shared_1.maybeJson)(native.tool_input) });
                break;
            case 'afterMCPExecution':
                Object.assign(ev, { tool_name: `mcp__${mcpServer(native)}__${(0, shared_1.str)(native.tool_name)}`, tool_input: (0, shared_1.maybeJson)(native.tool_input), tool_response: (0, shared_1.maybeJson)(native.result_json) });
                break;
            // the content arrives with the request to read, so this is where the session learns what it read
            case 'beforeReadFile':
                Object.assign(ev, { tool_name: 'Read', tool_input: { file_path: (0, shared_1.str)(native.file_path) }, tool_response: { file: { content: native.content } } });
                break;
            case 'afterFileEdit':
                Object.assign(ev, { tool_name: 'Edit', tool_input: { file_path: (0, shared_1.str)(native.file_path), edits: native.edits } });
                break;
            case 'beforeSubmitPrompt':
                ev.prompt = (0, shared_1.str)(native.prompt);
                break;
            default: ev.reason = native.status;
        }
        return ev;
    },
    encode(res, native) {
        const name = native.hook_event_name;
        const v = res && res.verdict;
        if (GATED.has(name)) {
            if (v && (v.permission === 'ask' || v.permission === 'deny')) {
                const reply = { permission: v.permission, user_message: v.reason, agent_message: v.agentMessage };
                return { stdout: { ...reply, userMessage: reply.user_message, agentMessage: reply.agent_message } };
            }
            return { stdout: { permission: 'allow', ...(v && v.notice ? { user_message: v.notice, userMessage: v.notice } : {}) } };
        }
        if (name === 'beforeReadFile')
            return { stdout: { permission: 'allow' } };
        if (name === 'beforeSubmitPrompt')
            return { stdout: { continue: true } };
        return {};
    },
    failClosed(ev, reason) {
        if (ev.hook_event_name !== 'PreToolUse')
            return null;
        const agent_message = 'This action was blocked by a policy.';
        return { stdout: { permission: 'deny', user_message: reason, userMessage: reason, agent_message, agentMessage: agent_message } };
    },
    hooksFile: {
        file: () => path.join(os.homedir(), '.cursor', 'hooks.json'),
        add(json, command) {
            json.version ||= 1;
            json.hooks ||= {};
            for (const e of Object.keys(EVENTS))
                (json.hooks[e] ||= []).push({ command, timeout: 10 });
            return Object.keys(EVENTS);
        },
        remove(json) { (0, shared_1.stripOurs)(json, false); },
        note: 'Restart Cursor so it reads the new hooks. File edits are recorded after they happen, not gated.',
    },
};
module.exports = adapter;
