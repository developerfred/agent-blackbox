"use strict";
// The evasion corpus is written in the canonical event format (Claude Code's).
// To measure what an adapter does to it, each corpus event is re-written the
// way the agent would send it, decoded by the real adapter, and only then given
// to the policy. An event the agent has no hook for cannot be written, and the
// whole case is then not applicable to that agent: that is a coverage fact, and
// it is reported as one.
//
// The re-writing is ours, from the same understanding of each agent's hooks
// the adapter was built on. It shows that the mapping loses nothing the
// policy needs; it does not show that a real agent sends these payloads.
Object.defineProperty(exports, "__esModule", { value: true });
exports.ENCODERS = void 0;
const text = (v) => (typeof v === 'string' ? v : JSON.stringify(v == null ? '' : v));
const isMcp = (t) => /^mcp__.+?__.+/.test(t || '');
const mcpParts = (t) => { const m = /^mcp__(.+?)__(.+)$/.exec(t) || []; return { server: m[1] || '', tool: m[2] || '' }; };
function codex(e) {
    const base = { session_id: e.session_id, cwd: e.cwd, turn_id: 't1' };
    if (e.kind === 'start')
        return { ...base, hook_event_name: 'SessionStart' };
    if (e.kind === 'prompt')
        return { ...base, hook_event_name: 'UserPromptSubmit', prompt: e.prompt };
    const name = e.kind === 'pre' ? 'PreToolUse' : 'PostToolUse';
    const input = e.input || {};
    let tool = null;
    if (e.tool === 'Bash')
        tool = { tool_name: 'Bash', tool_input: { command: input.command } };
    else if (e.tool === 'Write')
        tool = { tool_name: 'apply_patch', tool_input: { command: `*** Begin Patch\n*** Add File: ${input.file_path}\n${String(input.content || '').split('\n').map((l) => '+' + l).join('\n')}\n*** End Patch` } };
    else if (e.tool === 'Edit')
        tool = { tool_name: 'apply_patch', tool_input: { command: `*** Begin Patch\n*** Update File: ${input.file_path}\n@@\n-${input.old_string}\n+${input.new_string}\n*** End Patch` } };
    else if (isMcp(e.tool))
        tool = { tool_name: e.tool, tool_input: input };
    if (!tool)
        return null; // no hook for reads, searches or web tools
    return { ...base, hook_event_name: name, ...tool, tool_use_id: 'u1', ...(e.kind === 'post' ? { tool_response: e.response } : {}) };
}
function cursor(e) {
    const base = { conversation_id: e.session_id, generation_id: 'g1', workspace_roots: [e.cwd || '/repo'], ...(e.cwd ? { cwd: e.cwd } : {}) };
    if (e.kind === 'start')
        return null; // no session hook registered
    if (e.kind === 'prompt')
        return { ...base, hook_event_name: 'beforeSubmitPrompt', prompt: e.prompt };
    const input = e.input || {};
    if (e.kind === 'pre') {
        if (e.tool === 'Bash')
            return { ...base, hook_event_name: 'beforeShellExecution', command: input.command };
        if (isMcp(e.tool)) {
            const m = mcpParts(e.tool);
            return { ...base, hook_event_name: 'beforeMCPExecution', server: m.server, tool_name: m.tool, tool_input: JSON.stringify(input) };
        }
        return null; // file edits are only seen afterwards; reads and web tools have no gate
    }
    if (e.tool === 'Bash')
        return { ...base, hook_event_name: 'afterShellExecution', command: input.command, output: text(e.response) };
    if (isMcp(e.tool)) {
        const m = mcpParts(e.tool);
        return { ...base, hook_event_name: 'afterMCPExecution', server: m.server, tool_name: m.tool, tool_input: JSON.stringify(input), result_json: JSON.stringify(e.response) };
    }
    if (e.tool === 'Read') {
        const r = e.response;
        return { ...base, hook_event_name: 'beforeReadFile', file_path: input.file_path, content: r && r.file ? r.file.content : text(r) };
    }
    if (e.tool === 'Write')
        return { ...base, hook_event_name: 'afterFileEdit', file_path: input.file_path, edits: [{ old_string: '', new_string: input.content }] };
    if (e.tool === 'Edit')
        return { ...base, hook_event_name: 'afterFileEdit', file_path: input.file_path, edits: [{ old_string: input.old_string, new_string: input.new_string }] };
    return null;
}
function gemini(e) {
    const base = { session_id: e.session_id, cwd: e.cwd, transcript_path: '/t', timestamp: 'x' };
    if (e.kind === 'start')
        return { ...base, hook_event_name: 'SessionStart', source: 'startup' };
    if (e.kind === 'prompt')
        return { ...base, hook_event_name: 'BeforeAgent', prompt: e.prompt };
    const input = e.input || {};
    let tool = null;
    if (e.tool === 'Bash')
        tool = { tool_name: 'run_shell_command', tool_input: { command: input.command } };
    else if (e.tool === 'Read')
        tool = { tool_name: 'read_file', tool_input: { file_path: input.file_path } };
    else if (e.tool === 'Write')
        tool = { tool_name: 'write_file', tool_input: { file_path: input.file_path, content: input.content } };
    else if (e.tool === 'Edit')
        tool = { tool_name: 'replace', tool_input: { file_path: input.file_path, old_string: input.old_string, new_string: input.new_string } };
    else if (e.tool === 'WebFetch')
        tool = { tool_name: 'web_fetch', tool_input: { prompt: `Fetch ${input.url} and summarize it` } };
    else if (e.tool === 'WebSearch')
        tool = { tool_name: 'google_web_search', tool_input: { query: input.query } };
    else if (e.tool === 'Grep')
        tool = { tool_name: 'search_file_content', tool_input: { pattern: input.pattern, dir_path: input.path } };
    else if (isMcp(e.tool)) {
        const m = mcpParts(e.tool);
        tool = { tool_name: `mcp_${m.server}_${m.tool}`, tool_input: input, mcp_context: { server_name: m.server, tool_name: m.tool } };
    }
    if (!tool)
        return null; // PowerShell and skills do not exist in Gemini CLI
    const r = e.response;
    return { ...base, hook_event_name: e.kind === 'pre' ? 'BeforeTool' : 'AfterTool', ...tool, ...(e.kind === 'post' ? { tool_response: typeof r === 'string' ? { llmContent: r } : r } : {}) };
}
// What an agent does with the shell when it has no tool of its own: Codex reads files
// with cat, fetches pages with curl. Without this, the corpus's setup steps (read .env,
// fetch a page) could not be written for it, and nearly every case would be skipped.
function viaShell(e) {
    if (e.kind !== 'pre' && e.kind !== 'post')
        return e;
    const input = e.input || {};
    const content = e.response && e.response.file ? e.response.file.content : e.response;
    if (e.tool === 'Read')
        return { ...e, tool: 'Bash', input: { command: `cat ${input.file_path}` }, response: content };
    if (e.tool === 'WebFetch')
        return { ...e, tool: 'Bash', input: { command: `curl -sL ${input.url}` }, response: e.response };
    if (e.tool === 'Grep')
        return { ...e, tool: 'Bash', input: { command: `grep -rn "${input.pattern}" ${input.path || '.'}` }, response: e.response };
    return e;
}
/** Cursor has a read hook, but no web or search hook. */
function cursorShell(e) {
    return e.tool === 'WebFetch' || e.tool === 'Grep' ? viaShell(e) : e;
}
exports.ENCODERS = {
    codex: (e) => codex(viaShell(e)),
    cursor: (e) => cursor(cursorShell(e)),
    gemini,
};
