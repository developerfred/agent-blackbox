'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { brief } = require('../dist/src/brief');

let seq = 0;
const rec = (o) => ({ v: 1, seq: ++seq, ts: `2026-10-04T10:00:${String(seq).padStart(2, '0')}.000Z`, prev: 'p', hash: `h${'0'.repeat(30)}${seq}`, sig: 's', session_id: 's1', kind: 'hook', ...o });
const records = () => {
  seq = 0;
  return [
    rec({ event: 'SessionStart', cwd: '/work/app', summary: 'startup /work/app' }),
    rec({ event: 'UserPromptSubmit', summary: 'fix the login bug' }),
    rec({ event: 'PreToolUse', tool_name: 'Read', summary: 'Read /work/app/a.js' }),
    rec({ event: 'PreToolUse', tool_name: 'Edit', summary: 'Edit /work/app/a.js' }),
    rec({ event: 'PreToolUse', tool_name: 'Edit', summary: 'Edit /work/app/a.js' }),
    rec({ event: 'PreToolUse', tool_name: 'Write', summary: 'Write /work/app/b `x`.js' }),
    rec({ kind: 'taint', flag: 'untrusted', why: 'read a web page' }),
    rec({ kind: 'decision', decision: 'ask', rule: 'lethal-trifecta', reason: 'unnamed host | evil' }),
    rec({ kind: 'decision', decision: 'warn', rule: 'x', reason: 'noise' }),
    rec({ kind: 'otel', event: 'api_request', summary: 'ignored' }),
    rec({ session_id: 's2', event: 'UserPromptSubmit', summary: 'other session' }),
  ];
};

test('brief summarizes one session and ignores others and otel', () => {
  const md = brief(records(), 's1');
  assert.match(md, /^# Session brief: `s1`/);
  assert.match(md, /\*\*1 decision needed attention\*\* \(lethal-trifecta\)/);
  assert.match(md, /- Project: `\/work\/app`/);
  assert.match(md, /- Tool calls: 4, prompts: 1/);
  assert.match(md, /\| Edit \| 2 \|/);
  assert.match(md, /- `\/work\/app\/a\.js` \(2 edits\)/);
  assert.match(md, /\| #8 \| ask \| lethal-trifecta \| unnamed host \\\| evil \|/);
  assert.match(md, /#7 untrusted: read a web page/);
  assert.match(md, /\| #9 \| warn \| x \| noise \|/); // listed, but not counted as needing attention
  assert.doesNotMatch(md, /other session|ignored/);
});

test('brief is deterministic and safe to paste', () => {
  const a = brief(records(), 's1');
  assert.strictEqual(a, brief(records().reverse(), 's1'));
  assert.doesNotMatch(a, /b `x`/); // backticks cannot break out of inline code
});

test('brief says so when nothing needed attention, and hides sealed summaries', () => {
  const md = brief([rec({ event: 'UserPromptSubmit', summary: 'bbx1:abc' }), rec({ event: 'PreToolUse', tool_name: 'Write', summary: 'bbx1:def' })], 's1');
  assert.match(md, /\*\*No decision needed attention\.\*\*/);
  assert.doesNotMatch(md, /bbx1/);
  assert.doesNotMatch(md, /## Files changed/);
});

test('brief returns null for an unknown session', () => {
  assert.strictEqual(brief(records(), 'nope'), null);
});
