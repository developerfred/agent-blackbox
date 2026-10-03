'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { CASES } = require('../eval/corpus');
const { runCase, runAll } = require('../eval/run');

for (const c of CASES.filter((x) => !x.gap)) {
  test(`evasion corpus: ${c.id} → ${c.expect}`, () => {
    const r = runCase(c);
    assert.ok(r.pass, `expected ${c.expect}, got ${r.decision} (${r.rule})`);
  });
}

test('evasion corpus: known gaps are still listed (fix one → move it out of the gap list)', () => {
  for (const c of CASES.filter((x) => x.gap)) {
    assert.ok(!runCase(c).blocked, `${c.id} is now caught: remove its gap note`);
  }
});

test('evasion corpus: deny mode blocks the same attacks', () => {
  const r = runAll('deny');
  assert.equal(r.caught, r.attacks);
  assert.equal(r.falseAlarms, 0);
});
