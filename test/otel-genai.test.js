'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { toOtlpTraces, toOtlpLogs } = require('../dist/src/otel-genai');

const recs = [
  { seq: 1, ts: '2026-01-01T00:00:00.000Z', kind: 'genesis', key_id: 'k1', hash: 'h1' },
  { seq: 2, ts: '2026-01-01T00:00:01.000Z', kind: 'hook', event: 'PreToolUse', session_id: 's1', tool_name: 'Bash', tool_use_id: 't1', hash: 'h2', summary: 'Bash curl secret', payload: 'p' },
  { seq: 3, ts: '2026-01-01T00:00:01.100Z', kind: 'decision', session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', decision: 'deny', rule: 'secret-egress', reason: 'x', hash: 'h3' },
  { seq: 4, ts: '2026-01-01T00:00:02.000Z', kind: 'hook', event: 'PostToolUse', session_id: 's1', tool_name: 'Bash', tool_use_id: 't1', hash: 'h4' },
  { seq: 5, ts: '2026-01-01T00:00:03.000Z', kind: 'hook', event: 'PreToolUse', session_id: 's1', tool_name: 'Read', tool_use_id: 't2', hash: 'h5' },
];
const val = (list, k) => { const a = list.find((x) => x.key === k); return a && Object.values(a.value)[0]; };

test('otel: a tool call becomes one execute_tool span with GenAI attributes and the decision', () => {
  const spans = toOtlpTraces(recs).resourceSpans[0].scopeSpans[0].spans;
  assert.equal(spans.length, 2);
  const s = spans[0];
  assert.equal(s.name, 'execute_tool Bash');
  assert.equal(val(s.attributes, 'gen_ai.operation.name'), 'execute_tool');
  assert.equal(val(s.attributes, 'gen_ai.conversation.id'), 's1');
  assert.equal(val(s.attributes, 'gen_ai.tool.call.id'), 't1');
  assert.equal(val(s.attributes, 'blackbox.rule'), 'secret-egress');
  assert.equal(s.status.code, 2);
  assert.equal(s.events[0].name, 'blackbox.decision');
  assert.equal(BigInt(s.endTimeUnixNano) - BigInt(s.startTimeUnixNano), 1000000000n);
  assert.equal(spans[1].startTimeUnixNano, spans[1].endTimeUnixNano); // unfinished call
});

test('otel: ids are stable and no payload, summary or reason text leaves the ledger', () => {
  const a = JSON.stringify(toOtlpTraces(recs));
  assert.equal(a, JSON.stringify(toOtlpTraces(recs)));
  const all = a + JSON.stringify(toOtlpLogs(recs));
  assert.doesNotMatch(all, /curl secret|"payload"|"reason"/);
});

test('otel: decisions and genesis are exported as logs tied to their span', () => {
  const logs = toOtlpLogs(recs).resourceLogs[0].scopeLogs[0].logRecords;
  assert.equal(logs.length, 2);
  const d = logs[1];
  assert.equal(d.severityText, 'WARN');
  assert.equal(d.spanId, toOtlpTraces(recs).resourceSpans[0].scopeSpans[0].spans[0].spanId);
});
