'use strict';
// Terminal view of `blackbox skills`.
const { palette } = require('./term');

/** @type {Record<string, number>} */
const SEV_ORDER = { high: 0, medium: 1, low: 2, none: 3 };

/**
 * @param {import('./types').SkillAudit[]} audits
 * @param {{ color?: boolean, all?: boolean }} [opts]
 */
function renderSkills(audits, { color = false, all = false } = {}) {
  const { red, yellow, dim, bold, cyan, bySeverity: sevCol } = palette(color);
  const out = [bold(`agent-blackbox skills · ${audits.length} installed`)];
  if (!audits.length) {
    out.push(dim('  no skills found (looked in ~/.claude, ~/.agents, ~/.cursor, ~/.codex, ~/.copilot and this project)'));
    return out.join('\n');
  }
  const sorted = [...audits].sort((a, b) => SEV_ORDER[a.risk] - SEV_ORDER[b.risk] || a.name.localeCompare(b.name));
  const tally = { high: 0, medium: 0, low: 0, none: 0 };
  for (const a of audits) tally[a.risk]++;
  out.push(dim(`  ${tally.high} high · ${tally.medium} medium · ${tally.low} low · ${tally.none} clean`));
  out.push('');
  for (const a of sorted) {
    const pin = a.pin.status === 'changed' ? red('changed since pin') : a.pin.status === 'pinned' ? dim('pinned') : dim('not pinned');
    const counts = [a.counts.high && red(`${a.counts.high} high`), a.counts.medium && yellow(`${a.counts.medium} medium`), a.counts.low && dim(`${a.counts.low} low`)].filter(Boolean).join(' ');
    out.push(`  ${sevCol[a.risk]((a.risk === 'none' ? 'clean' : a.risk).padEnd(7))} ${a.name.slice(0, 34).padEnd(34)} ${dim(a.source.padEnd(16))} ${String(a.fileCount).padStart(4)} files  ${pin}  ${counts}`);
    for (const f of a.findings) {
      if (!all && f.severity === 'low') continue;
      out.push(`      ${sevCol[f.severity]('•')} ${f.rule} ${dim(`${f.file}${f.line ? ':' + f.line : ''}`)} ${f.message}`);
      if (f.excerpt) out.push(dim(`          ${f.excerpt}`));
    }
  }
  out.push('');
  out.push(dim('  Static checks find known risky patterns; a clean result is not proof a skill is safe.'));
  if (audits.some((a) => a.pin.status !== 'pinned')) out.push(`  Record today's content so later changes are flagged: ${cyan('blackbox skills --pin')}`);
  if (!all && audits.some((a) => a.counts.low)) out.push(dim('  Low-severity notes hidden; show them with --all.'));
  return out.join('\n');
}

module.exports = { renderSkills };
