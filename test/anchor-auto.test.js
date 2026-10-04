'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { settings, due, publish } = require('../dist/src/anchor');

test('auto anchor: off unless a file or a webhook is configured', () => {
  assert.equal(settings({}), null);
  assert.equal(settings({ anchor: { every: 10 } }), null);
  assert.deepEqual(settings({ anchor: { file: '/x/a.jsonl' } }), { every: 100, minutes: 60, file: '/x/a.jsonl', webhook: undefined });
});

test('auto anchor: due after enough records, or some records and enough time', () => {
  const s = { every: 100, minutes: 60 };
  const min = 60 * 1000;
  assert.ok(!due(s, { newRecords: 0, lastAt: null, now: 0 }));
  assert.ok(due(s, { newRecords: 100, lastAt: 0, now: 1 }));
  assert.ok(!due(s, { newRecords: 5, lastAt: 0, now: 59 * min }));
  assert.ok(due(s, { newRecords: 5, lastAt: 0, now: 60 * min }));
  assert.ok(due(s, { newRecords: 1, lastAt: null, now: 0 }));
});

test('auto anchor: publishes to a file and a webhook, and fails loudly so it can be retried', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-auto-'));
  const file = path.join(dir, 'sub', 'anchors.jsonl');
  const calls = [];
  const ok = async (url, init) => { calls.push([url, JSON.parse(init.body)]); return { ok: true, status: 200 }; };
  const a = { seq: 9, hash: 'h', root: 'r', from: 1, to: 8 };
  await publish(a, { file, webhook: 'https://example.test/hook' }, ok);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).root, 'r');
  assert.equal(calls[0][0], 'https://example.test/hook');
  await assert.rejects(publish(a, { webhook: 'https://example.test/hook' }, async () => ({ ok: false, status: 503 })), /HTTP 503/);
  await assert.rejects(publish(a, { webhook: 'ftp://x' }, ok), /http\(s\)/);
});
