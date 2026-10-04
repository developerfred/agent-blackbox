"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GENAI = void 0;
exports.toOtlpTraces = toOtlpTraces;
exports.toOtlpLogs = toOtlpLogs;
// Ledger records -> OpenTelemetry (OTLP/JSON), using the GenAI semantic
// conventions where one exists and a `blackbox.*` namespace for what the
// conventions do not cover (policy decisions, taint, chain position).
//
// Local by default: this module only builds JSON. Nothing is sent anywhere
// unless the user runs `blackbox export --endpoint <url>`. Metadata only:
// session, tool and rule names, decisions, timestamps and chain hashes. Never
// payloads, summaries, prompts, commands or paths, which stay in the ledger.
//
// The GenAI conventions are still in development upstream, so the attribute
// names are kept in one table (GENAI) to follow them as they change.
const util_1 = require("./util");
exports.GENAI = {
    operation: 'gen_ai.operation.name',
    provider: 'gen_ai.provider.name',
    conversation: 'gen_ai.conversation.id',
    agentId: 'gen_ai.agent.id',
    agentName: 'gen_ai.agent.name',
    toolName: 'gen_ai.tool.name',
    toolCallId: 'gen_ai.tool.call.id',
};
function kv(key, v) {
    if (v === undefined || v === null || v === '')
        return null;
    if (typeof v === 'boolean')
        return { key, value: { boolValue: v } };
    if (typeof v === 'number' && Number.isInteger(v))
        return { key, value: { intValue: String(v) } };
    if (typeof v === 'number')
        return { key, value: { doubleValue: v } };
    return { key, value: { stringValue: String(v) } };
}
const attrs = (o) => Object.entries(o).map(([k, v]) => kv(k, v)).filter(Boolean);
const nanos = (iso) => String(BigInt(Date.parse(iso)) * 1000000n);
/** Stable ids so re-exporting the same ledger gives the same trace and span ids. */
const id = (s, len) => (0, util_1.sha256)(s).slice(0, len);
function resource(version) {
    return { attributes: attrs({ 'service.name': 'agent-blackbox', 'service.version': version }) };
}
const SCOPE = { name: 'agent-blackbox.ledger' };
const chainAttrs = (rec) => ({ 'blackbox.record.seq': rec.seq, 'blackbox.record.hash': rec.hash });
/**
 * One `execute_tool` span per tool call: starts at PreToolUse, ends at the
 * PostToolUse / PostToolUseFailure with the same tool_use_id. A call that never
 * finished (denied, or the session ended) is a zero-length span.
 */
function toOtlpTraces(records, { version = '0' } = {}) {
    const calls = new Map();
    const get = (k) => {
        let c = calls.get(k);
        if (!c) {
            c = { decisions: [], taints: [] };
            calls.set(k, c);
        }
        return c;
    };
    for (const r of records) {
        if (!r.tool_use_id || !r.session_id)
            continue;
        const c = get(r.session_id + '/' + r.tool_use_id);
        if (r.kind === 'hook' && r.event === 'PreToolUse')
            c.pre = r;
        else if (r.kind === 'hook' && (r.event === 'PostToolUse' || r.event === 'PostToolUseFailure'))
            c.post = r;
        else if (r.kind === 'decision')
            c.decisions.push(r);
        else if (r.kind === 'taint')
            c.taints.push(r);
    }
    const spans = [];
    for (const [key, c] of calls) {
        const first = c.pre || c.post;
        if (!first)
            continue;
        const start = c.pre || first;
        const end = c.post || start;
        const denied = c.decisions.find((d) => d.decision === 'deny' || d.decision === 'ask');
        const failed = end.event === 'PostToolUseFailure';
        spans.push({
            traceId: id(first.session_id, 32),
            spanId: id(key, 16),
            name: `execute_tool ${first.tool_name || 'unknown'}`,
            kind: 1, // INTERNAL
            startTimeUnixNano: nanos(start.ts),
            endTimeUnixNano: nanos(end.ts),
            attributes: attrs({
                [exports.GENAI.operation]: 'execute_tool',
                [exports.GENAI.provider]: 'anthropic',
                [exports.GENAI.conversation]: first.session_id,
                [exports.GENAI.agentId]: first.agent_id,
                [exports.GENAI.toolName]: first.tool_name,
                [exports.GENAI.toolCallId]: first.tool_use_id,
                'blackbox.record.seq': start.seq,
                'blackbox.record.hash': start.hash,
                'blackbox.decision': (denied || c.decisions[0] || {}).decision,
                'blackbox.rule': (denied || c.decisions[0] || {}).rule,
                'blackbox.taint': c.taints.length ? c.taints.map((t) => t.flag).join(',') : undefined,
            }),
            events: c.decisions.map((d) => ({
                name: 'blackbox.decision',
                timeUnixNano: nanos(d.ts),
                attributes: attrs({ 'blackbox.decision': d.decision, 'blackbox.rule': d.rule, ...chainAttrs(d) }),
            })),
            status: failed ? { code: 2 } : denied ? { code: 2, message: `blackbox ${denied.decision}: ${denied.rule}` } : { code: 1 },
        });
    }
    spans.sort((a, b) => (BigInt(a.startTimeUnixNano) < BigInt(b.startTimeUnixNano) ? -1 : 1));
    return { resourceSpans: [{ resource: resource(version), scopeSpans: [{ scope: SCOPE, spans }] }] };
}
// Records that are not tool calls become log records: policy decisions are the
// audit trail the GenAI conventions do not define yet, so they carry blackbox.*.
const LOG_KINDS = new Set(['decision', 'taint', 'intent', 'purge', 'settings', 'genesis']);
function toOtlpLogs(records, { version = '0' } = {}) {
    const logRecords = [];
    for (const r of records) {
        if (!LOG_KINDS.has(r.kind))
            continue;
        logRecords.push({
            timeUnixNano: nanos(r.ts),
            severityText: r.decision === 'deny' || r.decision === 'alert' ? 'WARN' : 'INFO',
            body: { stringValue: `blackbox.${r.kind}` },
            traceId: r.session_id ? id(r.session_id, 32) : undefined,
            spanId: r.session_id && r.tool_use_id ? id(r.session_id + '/' + r.tool_use_id, 16) : undefined,
            attributes: attrs({
                'event.name': `blackbox.${r.kind}`,
                [exports.GENAI.conversation]: r.session_id,
                [exports.GENAI.toolName]: r.tool_name,
                [exports.GENAI.toolCallId]: r.tool_use_id,
                'blackbox.decision': r.decision,
                'blackbox.rule': r.rule,
                'blackbox.taint.flag': r.flag,
                'blackbox.key_id': r.key_id,
                ...chainAttrs(r),
            }),
        });
    }
    return { resourceLogs: [{ resource: resource(version), scopeLogs: [{ scope: SCOPE, logRecords }] }] };
}
