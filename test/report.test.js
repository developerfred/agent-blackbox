'use strict';
// The terminal reports are pinned against output captured before they were refactored.
const test = require('node:test');
const assert = require('node:assert');
const fx = require('./fixtures/report');
const golden = require('./fixtures/report-golden.json');
const { renderMcp } = require('../src/mcp-report');
const { renderSkills } = require('../src/skills-report');

test('blackbox mcp report: plain, colored with --all, and ordering', () => {
  assert.equal(renderMcp(fx.mcpAudits, fx.summary, {}), golden.mcp);
  assert.equal(renderMcp(fx.mcpAudits, fx.summary, { color: true, all: true }), golden.mcpColorAll);
  assert.ok(!golden.mcp.includes('\x1b['), 'no escapes without color');
  assert.ok(golden.mcpColorAll.includes('\x1b[31m'), 'high risk is red');
});

test('blackbox skills report: sorted by risk then name, low notes behind --all', () => {
  assert.equal(renderSkills(fx.skills, {}), golden.skills);
  assert.equal(renderSkills(fx.skills, { color: true, all: true }), golden.skillsColorAll);
  assert.equal(renderSkills([], {}), golden.empty);
  const names = [...golden.skills.matchAll(/^ {2}(?:high|medium|low|clean) +(\S+)/gm)].map((m) => m[1]);
  assert.deepEqual(names, ['zeta', 'beta', 'alpha']);
});
