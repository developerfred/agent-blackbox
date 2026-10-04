'use strict';
// Benchmarks for the hot paths. No dependencies; numbers are medians and p95s
// of many runs. Usage: node bench/run.js [--json] [--only name]
//
// Budgets (see ROADMAP): policy decision < 1 ms, hook round trip < 20 ms at p95.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-bench-'));
process.env.BLACKBOX_HOME = path.join(TMP, 'home');
const PORT = 20000 + Math.floor(Math.random() * 20000);
process.env.BLACKBOX_PORT = String(PORT);

const { Policy } = require('../src/policy');
const { DEFAULT_CONFIG, ensureDirs, readToken, readAdminToken } = require('../src/paths');
const { CASES } = require('../eval/corpus');

const args = process.argv.slice(2);
const only = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;
/** @type {Record<string, { p50: number, p95: number, n: number, unit: string, budget: number | null }>} */
const results = {};

/** @param {number[]} xs @param {number} p */
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const now = () => Number(process.hrtime.bigint()) / 1e6; // ms
/** @param {string} name @param {number[]} samples @param {string} [unit] @param {number | null} [budget] */
function record(name, samples, unit = 'ms', budget = null) {
  const r = { p50: pct(samples, 0.5), p95: pct(samples, 0.95), n: samples.length, unit, budget };
  results[name] = r;
  if (!args.includes('--json')) {
    const flag = budget != null && r.p95 > budget ? '  OVER BUDGET' : '';
    console.log(`${name.padEnd(34)} p50 ${r.p50.toFixed(3).padStart(9)} ${unit}   p95 ${r.p95.toFixed(3).padStart(9)} ${unit}   n=${r.n}${budget != null ? `   budget ${budget}` : ''}${flag}`);
  }
}
/** @param {string} n */
const want = (n) => !only || only === n;

function benchPolicy() {
  const cfg = { ...DEFAULT_CONFIG };
  const policy = new Policy(cfg, { sessions: {} }, 'bench-salt', { protect: [] });
  const calls = CASES.filter((c) => c.call.tool === 'Bash');
  // session state per case, as the hook would have built it
  const sessions = calls.map((c, i) => {
    const sid = `b${i}`;
    for (const ev of /** @type {any[]} */ (c.before || [])) {
      if (ev.prompt) policy.userPrompt({ session_id: sid, prompt: ev.prompt });
      else policy.postToolUse({ session_id: sid, tool_name: ev.post, tool_input: ev.input, tool_response: ev.response });
    }
    return sid;
  });
  /** @type {number[]} */
  const samples = [];
  for (let rep = 0; rep < 40; rep++) {
    calls.forEach((c, i) => {
      const t = now();
      policy.preToolUse({ session_id: sessions[i], tool_name: 'Bash', tool_input: c.call.input });
      samples.push(now() - t);
    });
  }
  record('policy.preToolUse (Bash, corpus)', samples, 'ms', 1);

  const big = { file: { content: Array.from({ length: 2000 }, (_, i) => `line ${i} some ordinary source text with words and a path /usr/lib/x${i}`).join('\n') + '\nAPI_KEY=abcd1234efgh5678ijkl' } };
  const post = [], scrub = [];
  for (let i = 0; i < 30; i++) {
    let t = now();
    policy.postToolUse({ session_id: 'big', tool_name: 'Read', tool_input: { file_path: '/r/a.txt' }, tool_response: big });
    post.push(now() - t);
    t = now();
    policy.scrub({ hook_event_name: 'PostToolUse', tool_response: big }, 'big');
    scrub.push(now() - t);
  }
  record('policy.postToolUse (140 KB read)', post);
  record('policy.scrub (140 KB response)', scrub);
}

/** @param {string} p @param {unknown} body @param {string} token @returns {Promise<number | undefined>} */
function post(p, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port: PORT, path: p, method: 'POST', headers: { host: `127.0.0.1:${PORT}`, 'content-type': 'application/json', 'x-blackbox-token': token }, agent: false }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end(data);
  });
}
/** @param {string} p @param {string} token @returns {Promise<{ status: number | undefined, body: string }>} */
function get(p, token) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: PORT, path: p, headers: { host: `127.0.0.1:${PORT}`, 'x-blackbox-token': token }, agent: false }, (res) => {
      /** @type {Buffer[]} */
      const out = []; res.on('data', (d) => out.push(d)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(out).toString() }));
    }).on('error', reject);
  });
}

async function benchDaemon() {
  ensureDirs();
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'dist', 'bin', 'blackbox.js'), 'daemon'], { stdio: 'ignore', env: process.env });
  const token = readToken(), admin = readAdminToken();
  for (let i = 0; i < 50; i++) { try { if ((await get('/health', token)).status === 200) break; } catch { /* starting */ } await new Promise((r) => setTimeout(r, 100)); }
  try {
    const sid = 'bench-session';
    const rt = [];
    for (let i = 0; i < 600; i++) {
      const pre = i % 2 === 0;
      const ev = pre
        ? { hook_event_name: 'PreToolUse', session_id: sid, tool_name: 'Bash', tool_input: { command: `ls -la dir${i}` }, tool_use_id: `t${i}` }
        : { hook_event_name: 'PostToolUse', session_id: sid, tool_name: 'Bash', tool_input: { command: 'ls' }, tool_response: 'file1\nfile2\n' + 'x'.repeat(2000), tool_use_id: `t${i - 1}` };
      const t = now();
      await post('/hook', ev, token);
      rt.push(now() - t);
    }
    record('daemon POST /hook round trip', rt.slice(50), 'ms', 20);

    // deny and taint paths write state; they are the slow ones
    const heavy = [];
    for (let i = 0; i < 100; i++) {
      const t = now();
      await post('/hook', { hook_event_name: 'PostToolUse', session_id: `h${i % 5}`, tool_name: 'Read', tool_input: { file_path: '/r/.env' }, tool_response: { file: { content: `API_KEY=secret${crypto.randomBytes(8).toString('hex')}\n` } }, tool_use_id: `h${i}` }, token);
      heavy.push(now() - t);
    }
    record('daemon POST /hook (taint + state save)', heavy, 'ms', 20);

    // lookup of one record's payload in a long ledger
    for (let i = 0; i < 4000; i++) await post('/hook', { hook_event_name: 'PostToolUse', session_id: `s${i % 40}`, tool_name: 'Bash', tool_input: { command: 'ls' }, tool_response: 'x', tool_use_id: `p${i}` }, token);
    const lk = [];
    for (let i = 0; i < 40; i++) {
      const seq = 2 + Math.floor(Math.random() * 7000);
      const t = now();
      await get(`/api/payload?seq=${seq}`, admin);
      lk.push(now() - t);
    }
    record('daemon GET /api/payload (~8k records)', lk, 'ms');
  } finally { child.kill('SIGTERM'); }
}

async function benchScan() {
  const dir = path.join(TMP, 'projects');
  const sessions = 60;
  for (let s = 0; s < sessions; s++) {
    const proj = path.join(dir, `-work-p${s % 6}`);
    fs.mkdirSync(proj, { recursive: true });
    const lines = [];
    let t = Date.parse('2026-09-20T10:00:00Z');
    const base = { sessionId: `s${s}`, cwd: `/work/p${s % 6}`, isSidechain: false };
    for (let i = 0; i < 150; i++) {
      const id = `toolu_${s}_${i}`;
      lines.push(JSON.stringify({ ...base, type: 'assistant', timestamp: new Date(t += 1000).toISOString(), message: { role: 'assistant', content: [{ type: 'tool_use', id, name: 'Bash', input: { command: i % 7 === 0 ? 'curl -s https://registry.npmjs.org/x' : `ls dir${i} && git status` } }] } }));
      lines.push(JSON.stringify({ ...base, type: 'user', timestamp: new Date(t += 1000).toISOString(), message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: 'out '.repeat(100) }] } }));
    }
    fs.writeFileSync(path.join(proj, `s${s}.jsonl`), lines.join('\n') + '\n');
  }
  const { scan, scanParallel } = require('../src/scan');
  const opts = { projectsDir: dir, days: 3650, now: Date.parse('2026-09-21T00:00:00Z'), cfg: { ...DEFAULT_CONFIG }, audits: [], mcpAudits: [] };
  const samples = [];
  for (let i = 0; i < 5; i++) {
    const t = now();
    scan(opts);
    samples.push(sessions / ((now() - t) / 1000));
  }
  record('scan (sessions per second)', samples, 'sess/s');
  const par = [];
  for (let i = 0; i < 5; i++) {
    const t = now();
    await scanParallel(opts);
    par.push(sessions / ((now() - t) / 1000));
  }
  record('scan --jobs auto (sessions per second)', par, 'sess/s');
}

(async () => {
  if (want('policy')) benchPolicy();
  if (want('daemon')) await benchDaemon();
  if (want('scan')) await benchScan();
  if (args.includes('--json')) console.log(JSON.stringify(results, null, 2));
  fs.rmSync(TMP, { recursive: true, force: true });
  process.exit(Object.values(results).some((r) => r.budget != null && r.p95 > r.budget) && args.includes('--strict') ? 1 : 0);
})();
