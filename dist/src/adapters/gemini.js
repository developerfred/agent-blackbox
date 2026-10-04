'use strict';
// Google Gemini CLI. Hooks live in ~/.gemini/settings.json under "hooks", keyed
// by Gemini's own event names; a hook reads JSON on stdin and prints only JSON
// on stdout. Gemini's tools have their own names, which this adapter maps to
// the canonical ones (run_shell_command is Bash, replace is Edit, ...).
//   - BeforeTool can deny a call ({ decision: "deny", reason }); there is no
//     "ask", so an "ask" becomes a block;
//   - AfterTool sees the result, so the session learns what it read;
//   - BeforeAgent is the prompt, AfterAgent the end of a turn.
// Gemini's model-level hooks (BeforeModel, AfterModel, BeforeToolSelection) are not used.
const path = require('path');
const os = require('os');
const { withAskFallback, stripOurs, str } = require('./shared');
/** native event -> canonical event */
const EVENTS = /** @type {Record<string, string>} */ ({
    SessionStart: 'SessionStart',
    SessionEnd: 'SessionEnd',
    BeforeAgent: 'UserPromptSubmit',
    AfterAgent: 'Stop',
    BeforeTool: 'PreToolUse',
    AfterTool: 'PostToolUse',
    Notification: 'Notification',
});
const TOOL_EVENTS = new Set(['BeforeTool', 'AfterTool']);
/** @param {string} text @returns {string[]} */
const urlsIn = (text) => (text.match(/https?:\/\/[^\s"'<>)\]]+/g) || []).map((u) => u.replace(/[.,;:]+$/, ''));
/** One Gemini tool call as the canonical { tool_name, tool_input }.
 * @param {Record<string, any>} n */
function mapTool(n) {
    const name = str(n.tool_name);
    const input = n.tool_input && typeof n.tool_input === 'object' ? n.tool_input : {};
    const file = str(input.file_path) || str(input.absolute_path);
    const mcp = n.mcp_context && typeof n.mcp_context === 'object' ? n.mcp_context : null;
    if (mcp && str(mcp.server_name))
        return { tool_name: `mcp__${mcp.server_name}__${str(mcp.tool_name) || name}`, tool_input: input };
    switch (name) {
        case 'run_shell_command': return { tool_name: 'Bash', tool_input: { command: str(input.command), directory: input.directory } };
        case 'read_file': return { tool_name: 'Read', tool_input: { file_path: file } };
        case 'read_many_files': {
            const paths = [].concat(input.paths || input.include || []).map(String);
            return { tool_name: 'Read', tool_input: { file_path: paths[0] || '', path: paths.join('\n') } };
        }
        case 'write_file': return { tool_name: 'Write', tool_input: { file_path: file, content: input.content } };
        case 'replace': return { tool_name: 'Edit', tool_input: { file_path: file, old_string: input.old_string, new_string: input.new_string } };
        case 'web_fetch': {
            // the tool takes a prompt that holds the URL(s)
            const urls = urlsIn(str(input.prompt) || str(input.url));
            return { tool_name: 'WebFetch', tool_input: { url: urls[0] || '', urls: urls.slice(1), prompt: input.prompt } };
        }
        case 'google_web_search': return { tool_name: 'WebSearch', tool_input: { query: str(input.query) } };
        case 'search_file_content':
        case 'grep_search': return { tool_name: 'Grep', tool_input: { pattern: str(input.pattern), path: str(input.dir_path) || str(input.path) } };
        case 'glob': return { tool_name: 'Glob', tool_input: { pattern: str(input.pattern) } };
        // Gemini's long-term memory is the GEMINI.md that later sessions load as instructions
        case 'save_memory': return { tool_name: 'Write', tool_input: { file_path: path.join(os.homedir(), '.gemini', 'GEMINI.md'), content: str(input.fact) } };
        default: {
            const m = /^mcp__(.+?)__(.+)$/.exec(name) || /^mcp_(.+?)_(.+)$/.exec(name);
            return { tool_name: m ? `mcp__${m[1]}__${m[2]}` : name, tool_input: input };
        }
    }
}
/** @type {import('../types').Adapter} */
const adapter = {
    id: 'gemini',
    name: 'Gemini CLI',
    capabilities: { preTool: true, ask: false, postTool: true, prompt: true, session: true },
    decode(native) {
        const event = EVENTS[native.hook_event_name];
        if (!event || !native.session_id)
            return null;
        /** @type {import('../types').HookEvent} */
        const ev = { hook_event_name: event, agent: 'gemini', session_id: String(native.session_id), cwd: str(native.cwd) || undefined };
        if (TOOL_EVENTS.has(native.hook_event_name)) {
            Object.assign(ev, mapTool(native));
            if (native.hook_event_name === 'AfterTool')
                ev.tool_response = native.tool_response;
        }
        else if (native.hook_event_name === 'BeforeAgent')
            ev.prompt = str(native.prompt);
        else if (native.hook_event_name === 'AfterAgent')
            ev.last_assistant_message = str(native.prompt_response);
        else if (native.hook_event_name === 'SessionStart')
            ev.source = native.source;
        else if (native.hook_event_name === 'SessionEnd')
            ev.reason = native.reason;
        else if (native.hook_event_name === 'Notification')
            ev.message = str(native.message);
        return ev;
    },
    encode(res, native, opts = {}) {
        const v = withAskFallback(res && res.verdict, adapter.capabilities.ask, opts.askFallback || 'deny');
        if (!v)
            return {};
        /** @type {Record<string, any>} */
        const out = {};
        if (v.permission === 'deny' && native.hook_event_name === 'BeforeTool') {
            out.decision = 'deny';
            out.reason = v.agentMessage;
            out.systemMessage = v.reason;
        }
        else if (v.notice)
            out.systemMessage = v.notice;
        return Object.keys(out).length ? { stdout: out } : {};
    },
    failClosed(ev, reason) {
        if (ev.hook_event_name !== 'PreToolUse')
            return null;
        return { stdout: { decision: 'deny', reason: 'This action was blocked by a policy.', systemMessage: reason } };
    },
    hooksFile: {
        file: () => path.join(os.homedir(), '.gemini', 'settings.json'),
        add(json, command) {
            json.hooks ||= {};
            for (const e of Object.keys(EVENTS)) {
                const hook = { name: 'agent-blackbox', type: 'command', command, timeout: 10000 };
                (json.hooks[e] ||= []).push(TOOL_EVENTS.has(e) ? { matcher: '.*', hooks: [hook] } : { hooks: [hook] });
            }
            return Object.keys(EVENTS);
        },
        remove(json) { stripOurs(json, true); },
        note: 'Gemini CLI hooks may need to be enabled in your Gemini settings, and take effect in a new session.',
    },
};
module.exports = adapter;
