#!/usr/bin/env node
// Builds the agent-facing text files served by the site from the repo docs:
//   site/llms-full.txt   README + agent guide + privacy, concatenated
//   site/agent-guide.md  a copy of docs/AGENT-GUIDE.md
// llms.txt itself is written by hand. Run after editing any of the sources.
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8').trim();

const parts = [
  ['README.md', read('README.md')],
  ['docs/AGENT-GUIDE.md', read('docs/AGENT-GUIDE.md')],
  ['docs/PRIVACY.md', read('docs/PRIVACY.md')],
];
const out = '# agent-blackbox, full documentation\n\n> Concatenation of the README, the agent guide and the privacy notes. Source: https://github.com/developerfred/agent-blackbox\n\n' +
  parts.map(([name, body]) => `<!-- ${name} -->\n\n${body}`).join('\n\n---\n\n') + '\n';
fs.writeFileSync(path.join(root, 'site', 'llms-full.txt'), out);
fs.copyFileSync(path.join(root, 'docs', 'AGENT-GUIDE.md'), path.join(root, 'site', 'agent-guide.md'));
console.log('wrote site/llms-full.txt and site/agent-guide.md');
