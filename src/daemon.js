'use strict';
// The daemon: a separate process from the agent. Hooks, the OTLP exporter and
// the raw-body files all feed it; it is the only holder of the signing key.
const fs = require('fs');
const path = require('path');
const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');
const { P, ensureDirs, readToken, loadConfig } = require('./paths');
const { Ledger, verify } = require('./ledger');
const { Policy, inputText, textOf, redact, AGENT_DENY_MESSAGE } = require('./policy');

const MAX_BODY = 64 * 1024 * 1024;
const ORPHAN_AFTER_MS = 3 * 60 * 1000;
const clip = (s, n = 160) => {
  const t = redact(s == null ? '' : String(s)).replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
};

function summarize(ev) {
  const target = inputText(ev.tool_input) || (ev.tool_input && ev.tool_input.query) || '';
  switch (ev.hook_event_name) {
    case 'UserPromptSubmit': return clip(ev.prompt);
    case 'PreToolUse': case 'PermissionRequest': case 'PermissionDenied':
      return clip(`${ev.tool_name} ${target}`);
    case 'PostToolUse': return clip(`${ev.tool_name} ${target} → ${textOf(ev.tool_response).length} bytes`);
    case 'PostToolUseFailure': return clip(`${ev.tool_name} ${target} ✗ ${ev.error || ''}`);
    case 'Stop': case 'SubagentStop': return clip(ev.last_assistant_message);
    case 'SubagentStart': return clip(ev.agent_type);
    case 'SessionStart': return clip(`${ev.source || ''} ${ev.cwd || ''}`);
    case 'SessionEnd': return clip(ev.reason);
    case 'Notification': return clip(ev.message);
    default: return '';
  }
}

function otlpValue(v) {
  if (!v) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('intValue' in v) return Number(v.intValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('boolValue' in v) return v.boolValue;
  if (v.arrayValue) return (v.arrayValue.values || []).map(otlpValue);
  if (v.kvlistValue) return Object.fromEntries((v.kvlistValue.values || []).map((kv) => [kv.key, otlpValue(kv.value)]));
  return null;
}

class Daemon {
  constructor() {
    this.cfg = loadConfig();
    this.token = readToken();
    this.sessions = new Map(); // id -> { id, first, last, cwd, events: [], flags: {}, alerts }
  }

  start() {
    this.ledger = new Ledger(P);
    this.loadState();
    this.policy = new Policy(this.cfg, this.state, this.state.salt);
    this.indexLedger();
    this.drainSpool();
    this.bodyTimer = setInterval(() => this.safe(() => this.pollBodies()), 2000);
    this.bodyTimer.unref();
  }

  safe(fn) { try { return fn(); } catch (e) { this.log('error', e.stack || String(e)); } }
  log(...a) { process.stderr.write(`[${new Date().toISOString()}] ${a.join(' ')}\n`); }

  loadState() {
    try { this.state = JSON.parse(fs.readFileSync(P.state, 'utf8')); } catch { this.state = {}; }
    this.state.sessions ||= {};
    this.state.salt ||= crypto.randomBytes(32).toString('hex');
    this.state.bodyIndexOffset ||= 0;
  }

  saveState() {
    const tmp = P.state + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
    fs.renameSync(tmp, P.state);
  }

  // ---- in-memory index for the timeline UI ----
  indexLedger() {
    if (!fs.existsSync(P.ledger)) return;
    for (const line of fs.readFileSync(P.ledger, 'utf8').split('\n')) {
      if (!line) continue;
      try { this.index(JSON.parse(line)); } catch { /* verify reports it */ }
    }
  }

  index(rec) {
    if (!rec.session_id) return;
    let s = this.sessions.get(rec.session_id);
    if (!s) {
      s = { id: rec.session_id, first: rec.ts, last: rec.ts, cwd: null, events: 0, tools: 0, flags: {}, decisions: 0, records: [] };
      this.sessions.set(rec.session_id, s);
    }
    s.last = rec.ts;
    s.events++;
    if (rec.event === 'SessionStart' && rec.cwd) s.cwd = rec.cwd;
    if (rec.event === 'PreToolUse') s.tools++;
    if (rec.kind === 'taint') s.flags[rec.flag] = rec.why;
    if (rec.kind === 'decision' && rec.decision !== 'note') s.decisions++;
    const { sig, ...lite } = rec;
    s.records.push(lite);
    if (s.records.length > 5000) s.records.shift();
  }

  append(kind, fields) {
    const rec = this.ledger.append(kind, fields);
    this.index(rec);
    return rec;
  }

  // ---- hooks ----
  // Order matters: the policy sees the raw event (it must learn which values
  // are secrets), then only a scrubbed copy is ever written to disk.
  handleHook(ev, meta = {}) {
    const event = ev.hook_event_name || 'unknown';
    const sid = ev.session_id;
    let decision = null;
    let post = null;
    let intent = [];
    if (event === 'PreToolUse') decision = this.policy.preToolUse(ev);
    else if (event === 'PostToolUse') post = this.policy.postToolUse(ev);
    else if (event === 'UserPromptSubmit') intent = this.policy.userPrompt(ev);

    const clean = this.policy.scrub(ev, sid);
    const blob = this.ledger.putBlob(clean);
    this.append('hook', {
      event,
      session_id: sid,
      prompt_id: ev.prompt_id,
      agent_id: ev.agent_id,
      tool_name: ev.tool_name,
      tool_use_id: ev.tool_use_id,
      cwd: event === 'SessionStart' ? ev.cwd : undefined,
      summary: summarize(clean),
      payload: blob.sha,
      payload_size: blob.size,
      spooled: meta.spooled || undefined,
      received_at: meta.received_at,
    });

    let stdout = null;
    if (decision) {
      this.append('decision', {
        session_id: sid, prompt_id: ev.prompt_id, tool_use_id: ev.tool_use_id, tool_name: ev.tool_name,
        decision: meta.spooled ? 'missed' : decision.decision, rule: decision.rule,
        secret: decision.secret, reason: redact(this.policy.scrubText(decision.reason, null)),
      });
      if (!meta.spooled && decision.decision === 'ask') {
        // "ask" reasons are shown to the human, who needs the detail to decide.
        stdout = {
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'ask',
            permissionDecisionReason: `[agent-blackbox] ${redact(decision.reason)}`,
          },
        };
      } else if (!meta.spooled && decision.decision === 'deny') {
        // "deny" reasons go back to the model: keep them uninformative and
        // tell the human the full story out of band.
        stdout = {
          systemMessage: `[agent-blackbox] blocked ${ev.tool_name}: ${redact(decision.reason)}`,
          hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: AGENT_DENY_MESSAGE },
        };
      }
      if (decision.decision === 'deny') this.saveState();
    }
    if (intent.length) {
      this.append('intent', { session_id: sid, prompt_id: ev.prompt_id, hosts: intent.slice(0, 50) });
      this.saveState();
    }
    if (post) {
      for (const t of post.taints) {
        this.append('taint', { session_id: sid, tool_use_id: ev.tool_use_id, tool_name: ev.tool_name, flag: t.flag, why: redact(this.policy.scrubText(t.why, null)) });
      }
      if (post.taints.length || post.secretsSeen) this.saveState();
    }
    if (event === 'SessionStart' && !meta.spooled) {
      stdout = { systemMessage: `agent-blackbox is recording this session (mode: ${this.cfg.mode}, ledger #${this.ledger.seq}).` };
    } else if (event === 'SessionEnd') {
      this.saveState();
    }
    return stdout;
  }

  // Store a raw API body with its secrets scrubbed, then delete the original.
  adoptScrubbed(file, sessionId) {
    const text = fs.readFileSync(file, 'utf8');
    let clean;
    try { clean = this.policy.scrub(JSON.parse(text), sessionId); } catch { clean = this.policy.scrubText(text, null); }
    const b = this.ledger.putBlob(clean);
    fs.unlinkSync(file);
    return b;
  }

  // Delete payload blobs (crypto-erasure style): the chain keeps every hash and
  // stays verifiable; `verify` reports the erased content as missing.
  purge(days) {
    const cutoff = days == null ? Infinity : Date.now() - days * 864e5;
    const old = new Set();
    const keep = new Set();
    for (const line of fs.readFileSync(P.ledger, 'utf8').split('\n')) {
      if (!line) continue;
      let r;
      try { r = JSON.parse(line); } catch { continue; }
      const target = Date.parse(r.ts) < cutoff ? old : keep;
      for (const f of ['payload', 'request_blob', 'response_blob']) if (r[f]) target.add(r[f]);
    }
    let erased = 0;
    for (const sha of old) {
      if (keep.has(sha)) continue;
      try { fs.unlinkSync(path.join(P.blobs, sha)); erased++; } catch { /* already gone */ }
    }
    let bodies = 0;
    for (const name of fs.existsSync(P.bodies) ? fs.readdirSync(P.bodies) : []) {
      if (!name.endsWith('.json')) continue;
      try { fs.unlinkSync(path.join(P.bodies, name)); bodies++; } catch { /* ignore */ }
    }
    this.append('purge', { erased_blobs: erased, erased_raw_bodies: bodies, before: days == null ? 'all' : new Date(cutoff).toISOString() });
    return { erased, bodies };
  }

  drainSpool() {
    if (!fs.existsSync(P.spool)) return;
    const work = P.spool + '.draining';
    fs.renameSync(P.spool, work);
    let n = 0;
    for (const line of fs.readFileSync(work, 'utf8').split('\n')) {
      if (!line) continue;
      try {
        const { payload, received_at } = JSON.parse(line);
        this.handleHook(payload, { spooled: true, received_at });
        n++;
      } catch (e) { this.log('spool line skipped:', e.message); }
    }
    fs.unlinkSync(work);
    if (n) this.log(`drained ${n} spooled events`);
  }

  // ---- OTLP/HTTP JSON logs from Claude Code's native telemetry ----
  handleOtlp(body) {
    let n = 0;
    for (const rl of body.resourceLogs || []) {
      const res = Object.fromEntries(((rl.resource && rl.resource.attributes) || []).map((a) => [a.key, otlpValue(a.value)]));
      for (const sl of rl.scopeLogs || []) {
        for (const lr of sl.logRecords || []) {
          const raw = Object.fromEntries((lr.attributes || []).map((a) => [a.key, otlpValue(a.value)]));
          const attrs = this.policy.scrub(raw, raw['session.id']);
          const blob = this.ledger.putBlob({ resource: res, body: this.policy.scrub(otlpValue(lr.body), raw['session.id']), attributes: attrs, timeUnixNano: lr.timeUnixNano });
          const name = attrs['event.name'] || otlpValue(lr.body) || 'log';
          this.append('otel', {
            event: name,
            service: res['service.name'],
            session_id: attrs['session.id'],
            prompt_id: attrs['prompt.id'],
            tool_use_id: attrs.tool_use_id,
            request_id: attrs.request_id,
            summary: clip([attrs.tool_name, attrs.model, attrs.cost_usd != null ? `$${Number(attrs.cost_usd).toFixed(4)}` : null,
              attrs.input_tokens != null ? `${attrs.input_tokens}in/${attrs.output_tokens}out` : null, attrs.decision, attrs.source]
              .filter((x) => x != null && x !== '').join(' ')),
            payload: blob.sha,
          });
          n++;
        }
      }
    }
    return n;
  }

  // ---- raw Messages API bodies (every model input and output) ----
  pollBodies() {
    if (!fs.existsSync(P.bodies)) return;
    const idx = path.join(P.bodies, 'index.jsonl');
    if (fs.existsSync(idx)) {
      const size = fs.statSync(idx).size;
      if (size < this.state.bodyIndexOffset) this.state.bodyIndexOffset = 0;
      if (size > this.state.bodyIndexOffset) {
        const fd = fs.openSync(idx, 'r');
        const buf = Buffer.alloc(size - this.state.bodyIndexOffset);
        fs.readSync(fd, buf, 0, buf.length, this.state.bodyIndexOffset);
        fs.closeSync(fd);
        const text = buf.toString('utf8');
        const end = text.lastIndexOf('\n');
        if (end >= 0) {
          for (const line of text.slice(0, end).split('\n')) {
            if (!line) continue;
            let e;
            try { e = JSON.parse(line); } catch { continue; }
            const fileOf = (f) => (f ? (path.isAbsolute(f) ? f : path.join(P.bodies, f)) : null);
            const reqF = fileOf(e.request_file);
            const resF = fileOf(e.response_file);
            const req = reqF && fs.existsSync(reqF) ? this.adoptScrubbed(reqF, e.session_id) : null;
            const res = resF && fs.existsSync(resF) ? this.adoptScrubbed(resF, e.session_id) : null;
            this.append('api_body', {
              session_id: e.session_id, request_id: e.request_id, message_uuid: e.message_uuid,
              model: e.model, query_source: e.query_source,
              request_blob: req && req.sha, request_size: req && req.size,
              response_blob: res && res.sha, response_size: res && res.size,
              summary: clip(`${e.model || ''} ${e.query_source || ''} req ${req ? req.size : '?'}B · res ${res ? res.size : '?'}B`),
            });
          }
          this.state.bodyIndexOffset += Buffer.byteLength(text.slice(0, end + 1));
          this.saveState();
        }
      }
    }
    // Bodies with no index line (failed requests, older Claude Code versions)
    const now = Date.now();
    for (const name of fs.readdirSync(P.bodies)) {
      if (!/\.(request|response)\.json$/.test(name)) continue;
      const f = path.join(P.bodies, name);
      let st;
      try { st = fs.statSync(f); } catch { continue; }
      if (now - st.mtimeMs < ORPHAN_AFTER_MS) continue;
      const b = this.adoptScrubbed(f, null);
      const which = name.endsWith('.request.json') ? 'request' : 'response';
      this.append('api_body', { orphan: true, file: name, [`${which}_blob`]: b.sha, [`${which}_size`]: b.size, summary: `unindexed ${which} body ${b.size}B` });
    }
  }

  // ---- HTTP ----
  listen(port = P.port, host = '127.0.0.1') {
    const okHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
    const server = http.createServer((req, res) => {
      const send = (code, obj, type = 'application/json') => {
        res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
        res.end(type === 'application/json' ? JSON.stringify(obj) : obj);
      };
      // DNS-rebinding guard: only answer requests addressed to loopback.
      if (!okHosts.has(req.headers.host)) return send(403, { error: 'bad host' });
      const url = new URL(req.url, `http://${req.headers.host}`);

      // The page itself holds no data; everything else needs the token.
      if (req.method === 'GET' && url.pathname === '/') {
        return send(200, fs.readFileSync(path.join(__dirname, 'ui.html'), 'utf8'), 'text/html; charset=utf-8');
      }
      // A custom header forces a CORS preflight, so web pages cannot forge or
      // read events; other local processes and users get 401 without the token.
      const tok = String(req.headers['x-blackbox-token'] || '');
      if (!this.token || tok.length !== this.token.length || !crypto.timingSafeEqual(Buffer.from(tok), Buffer.from(this.token))) {
        return send(401, { error: 'token' });
      }

      if (req.method === 'GET') {
        if (url.pathname === '/health') return send(200, { ok: true, seq: this.ledger.seq, head: this.ledger.head, mode: this.cfg.mode, pid: process.pid });
        if (url.pathname === '/api/sessions') {
          const list = [...this.sessions.values()].map(({ records, ...s }) => s).sort((a, b) => (a.last < b.last ? 1 : -1));
          return send(200, { head: { seq: this.ledger.seq, hash: this.ledger.head }, sessions: list });
        }
        if (url.pathname === '/api/events') {
          const s = this.sessions.get(url.searchParams.get('session'));
          return send(s ? 200 : 404, s ? s.records : { error: 'unknown session' });
        }
        if (url.pathname === '/api/verify') {
          return send(200, verify({ ledgerPath: P.ledger, pubPem: this.ledger.keys.pubPem, blobsDir: P.blobs }));
        }
        return send(404, { error: 'not found' });
      }

      if (req.method !== 'POST') return send(405, { error: 'method' });
      const chunks = [];
      let size = 0;
      req.on('data', (c) => { size += c.length; if (size > MAX_BODY) req.destroy(); else chunks.push(c); });
      req.on('end', () => {
        let raw = Buffer.concat(chunks);
        try {
          if (req.headers['content-encoding'] === 'gzip') raw = zlib.gunzipSync(raw);
          const body = raw.length ? JSON.parse(raw.toString('utf8')) : {};
          if (url.pathname === '/hook') return send(200, { stdout: this.safe(() => this.handleHook(body)) || null });
          if (url.pathname === '/v1/logs') { this.safe(() => this.handleOtlp(body)); return send(200, {}); }
          if (url.pathname === '/purge') return send(200, this.purge(body.days == null ? null : Number(body.days)));
          return send(404, { error: 'not found' });
        } catch (e) {
          this.log('bad request', url.pathname, e.message);
          return send(400, { error: 'bad json' });
        }
      });
    });
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve(server));
    });
  }
}

async function runDaemon() {
  ensureDirs();
  const d = new Daemon();
  let server;
  try {
    server = await d.listen();
  } catch (e) {
    if (e.code === 'EADDRINUSE') { process.stderr.write('agent-blackbox daemon already running\n'); process.exit(0); }
    throw e;
  }
  // Only the process that owns the port touches the ledger.
  d.start();
  fs.writeFileSync(P.pid, String(process.pid));
  d.log(`listening on 127.0.0.1:${P.port}, ledger seq ${d.ledger.seq}, mode ${d.cfg.mode}`);
  const stop = () => {
    d.safe(() => d.pollBodies());
    d.safe(() => d.saveState());
    try { if (fs.readFileSync(P.pid, 'utf8') === String(process.pid)) fs.unlinkSync(P.pid); } catch { /* gone */ }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1000).unref();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

module.exports = { Daemon, runDaemon, summarize };
