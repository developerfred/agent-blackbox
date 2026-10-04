// The agent-facing read API: stable, versioned JSON that an AI agent (or an MCP
// server acting for one) can parse without scraping the CLI or the UI.
//
// Two tiers, matching the two tokens the recorder already has:
//   public  readable with the ingest token (which the agent's own hook holds):
//           what blackbox is, how to talk to it, the rule catalogue, a minimal
//           health line. Nothing here says what was detected or enforced.
//   admin   readable with the admin token only: sessions and the decision/taint
//           trail. No payloads, no hook summaries (those hold prompt text), and
//           reasons are the already-masked ones the ledger stores in clear.
import * as fs from 'fs';
import * as path from 'path';

export const SCHEMA = 'blackbox.agent/v1';
const MAX_LIMIT = 500;

const pkg: { version: string } = (() => {
  for (const f of [path.join(__dirname, '..', 'package.json'), path.join(__dirname, '..', '..', 'package.json')]) {
    try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { /* next */ }
  }
  return { version: 'unknown' };
})();

/** One entry per rule the policy can report; names match `decision.rule` in the ledger. */
export const RULES = [
  { id: 'secret-egress', decision: 'deny', summary: 'A secret read earlier in the session appears in an outbound call.' },
  { id: 'sensitive-egress', decision: 'deny', summary: 'One command reads a sensitive file and sends data out.' },
  { id: 'lethal-trifecta', decision: 'ask', summary: 'The session touched private data and untrusted content, and now reaches an unnamed host.' },
  { id: 'secret-to-code', decision: 'ask', summary: 'A secret read earlier is passed to code the policy cannot inspect.' },
  { id: 'web3-transaction', decision: 'ask', summary: 'Signing or broadcasting a transaction, or key material on a command line.' },
  { id: 'memory-write', decision: 'ask', summary: 'A session that read untrusted content writes a file later sessions trust as instructions.' },
  { id: 'post-denial', decision: 'ask', summary: 'Something was already denied in this session and a call goes out.' },
  { id: 'self-protection', decision: 'deny', summary: 'A tool call touches the recorder\'s own data folder.' },
  { id: 'hook-tamper', decision: 'ask', summary: 'Claude Code settings or plugin files are edited.' },
  { id: 'risky-mcp', decision: 'ask', summary: 'A tool of an MCP server whose local configuration has high-risk findings.' },
  { id: 'risky-skill', decision: 'ask', summary: 'A skill with high-risk findings in the local audit is loaded.' },
];

export const RECORD_KINDS = ['genesis', 'hook', 'decision', 'intent', 'taint', 'settings', 'otel', 'api_body', 'purge', 'anchor'];

const obj = (properties: Record<string, unknown>, required: string[] = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: true });
const str = { type: 'string' };
const int = { type: 'integer' };
const bool = { type: 'boolean' };
const arr = (items: unknown) => ({ type: 'array', items });

/** Response shapes, shared by the OpenAPI document and the tests. */
export const SCHEMAS = {
  Capabilities: obj({ schema: str, name: str, version: str, description: str, scopes: obj({ public: arr(str), admin: arr(str) }), endpoints: arr(obj({ method: str, path: str, scope: str, summary: str })), record_kinds: arr(str), rules: arr(str), guarantees: arr(str), docs: obj({ ledger_spec: str, privacy: str }) }),
  Status: obj({ schema: str, recording: bool, ledger_seq: int, chain_ok: bool, encrypted: bool }),
  Rules: obj({ schema: str, rules: arr(obj({ id: str, decision: str, summary: str })) }),
  Sessions: obj({ schema: str, head: obj({ seq: int, hash: str }), sessions: arr(obj({ id: str, first: str, last: str, cwd: { type: ['string', 'null'] }, events: int, tools: int, decisions: int, taints: arr(str) })) }),
  Records: obj({ schema: str, records: arr(obj({ seq: int, ts: str, kind: str, hash: str })), next_after: { type: ['integer', 'null'] } }),
  Error: obj({ error: str }),
};

/** The endpoint table drives routing, /capabilities and /openapi.json, so they cannot drift apart. */
export const ENDPOINTS: { method: string; path: string; scope: string; schema: string | null; summary: string; params?: any[] }[] = [
  { method: 'GET', path: '/v1/agent/capabilities', scope: 'public', schema: 'Capabilities', summary: 'What agent-blackbox is, what this API offers and what it never returns. Start here.' },
  { method: 'GET', path: '/v1/agent/openapi.json', scope: 'public', schema: null, summary: 'This API as an OpenAPI 3.1 document.' },
  { method: 'GET', path: '/v1/agent/status', scope: 'public', schema: 'Status', summary: 'Is the recorder running and is the ledger chain intact. No mode, no findings.' },
  { method: 'GET', path: '/v1/agent/rules', scope: 'public', schema: 'Rules', summary: 'The policy rules that can appear in decisions.' },
  { method: 'GET', path: '/v1/agent/sessions', scope: 'admin', schema: 'Sessions', summary: 'Recorded sessions, newest first, with counts and taint flags.' },
  {
    method: 'GET', path: '/v1/agent/records', scope: 'admin', schema: 'Records',
    summary: 'Decision, taint, intent, settings and purge records, oldest first, as compact JSON. Never payloads or hook summaries.',
    params: [
      { name: 'session', in: 'query', schema: str, description: 'only this session id' },
      { name: 'kind', in: 'query', schema: str, description: 'comma-separated record kinds (default: decision,taint)' },
      { name: 'after', in: 'query', schema: int, description: 'return records with seq greater than this (cursor)' },
      { name: 'limit', in: 'query', schema: int, description: `1 to ${MAX_LIMIT}, default 100` },
    ],
  },
];

const GUARANTEES = [
  'Read-only: no endpoint here changes the ledger, the policy or the configuration.',
  'Loopback only: the recorder listens on 127.0.0.1 and rejects other Host headers.',
  'No payloads: prompts, tool arguments and tool results are never returned, only record metadata.',
  'No secrets: values are replaced by fingerprints before they reach the ledger; keys and tokens are never returned.',
  'Quiet toward the agent: the public tier does not reveal the enforcement mode, what was detected or why a call was denied.',
];

export function capabilities() {
  return {
    schema: SCHEMA,
    name: 'agent-blackbox',
    version: pkg.version,
    description: 'A local, tamper-evident flight recorder and lethal-trifecta firewall for AI coding agents.',
    scopes: {
      public: ENDPOINTS.filter((e) => e.scope === 'public').map((e) => e.path),
      admin: ENDPOINTS.filter((e) => e.scope === 'admin').map((e) => e.path),
    },
    endpoints: ENDPOINTS.map(({ method, path: p, scope, summary }) => ({ method, path: p, scope, summary })),
    record_kinds: RECORD_KINDS,
    rules: RULES.map((r) => r.id),
    guarantees: GUARANTEES,
    docs: { ledger_spec: 'docs/spec/ledger-v1.md', privacy: 'docs/PRIVACY.md' },
  };
}

export function openapi() {
  const paths: Record<string, any> = {};
  for (const e of ENDPOINTS) {
    const ok = e.schema
      ? { description: 'OK', content: { 'application/json': { schema: { $ref: `#/components/schemas/${e.schema}` } } } }
      : { description: 'OK', content: { 'application/json': { schema: { type: 'object' } } } };
    paths[e.path] = {
      get: {
        summary: e.summary,
        operationId: e.path.replace(/^\/v1\/agent\//, '').replace(/\.json$/, '').replace(/[^a-z]+/g, '_'),
        'x-blackbox-scope': e.scope,
        parameters: e.params || [],
        responses: {
          200: ok,
          401: { description: 'Missing or wrong x-blackbox-token', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          403: { description: 'This token\'s scope does not cover the endpoint', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    };
  }
  return {
    openapi: '3.1.0',
    info: { title: 'agent-blackbox agent API', version: pkg.version, description: GUARANTEES.join(' ') },
    servers: [{ url: 'http://127.0.0.1:7071', description: 'Default recorder port; BLACKBOX_PORT overrides it' }],
    security: [{ blackboxToken: [] }],
    components: {
      securitySchemes: { blackboxToken: { type: 'apiKey', in: 'header', name: 'x-blackbox-token', description: 'Ingest token for public endpoints, admin token for all.' } },
      schemas: SCHEMAS,
    },
    paths,
  };
}

const num = (v: unknown, dflt: number): number => { const n = Number(v); return v != null && v !== '' && Number.isFinite(n) ? Math.trunc(n) : dflt; };

/** Drop everything but metadata: no summary, no payload references, no signature. */
export function compact(rec: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = { seq: rec.seq, ts: rec.ts, kind: rec.kind, hash: rec.hash };
  for (const f of ['event', 'session_id', 'prompt_id', 'tool_name', 'tool_use_id', 'decision', 'rule', 'reason', 'flag', 'why', 'hosts', 'via', 'problems', 'from', 'to', 'count', 'root']) {
    if (rec[f] !== undefined) out[f] = rec[f];
  }
  return out;
}

/** Route one request. Returns null for a path that is not ours. */
export function handle(daemon: any, url: URL, admin: boolean): { status: number; body: any } | null {
  const ep = ENDPOINTS.find((e) => e.path === url.pathname);
  if (!ep) return url.pathname.startsWith('/v1/agent/') ? { status: 404, body: { error: 'not found' } } : null;
  if (ep.scope === 'admin' && !admin) return { status: 403, body: { error: 'this token cannot read records; use the admin token' } };
  switch (ep.path) {
    case '/v1/agent/capabilities': return { status: 200, body: capabilities() };
    case '/v1/agent/openapi.json': return { status: 200, body: openapi() };
    case '/v1/agent/rules': return { status: 200, body: { schema: SCHEMA, rules: RULES } };
    case '/v1/agent/status': {
      const v = daemon.verifyCached();
      return { status: 200, body: { schema: SCHEMA, recording: true, ledger_seq: daemon.ledger.seq, chain_ok: v.ok, encrypted: !!daemon.vault } };
    }
    case '/v1/agent/sessions': {
      const sessions = [...daemon.sessions.values()].map(({ seqs, flags, ...s }) => ({ ...s, taints: Object.keys(flags) }))
        .sort((a, b) => (a.last < b.last ? 1 : -1));
      return { status: 200, body: { schema: SCHEMA, head: { seq: daemon.ledger.seq, hash: daemon.ledger.head }, sessions } };
    }
    case '/v1/agent/records': {
      const kinds = new Set((url.searchParams.get('kind') || 'decision,taint').split(',').map((k) => k.trim()).filter(Boolean));
      const bad = [...kinds].filter((k) => !RECORD_KINDS.includes(k));
      if (bad.length) return { status: 400, body: { error: `unknown kind: ${bad.join(', ')}` } };
      const session = url.searchParams.get('session');
      const after = num(url.searchParams.get('after'), 0);
      const limit = Math.min(Math.max(num(url.searchParams.get('limit'), 100), 1), MAX_LIMIT);
      let seqs: number[];
      if (session) {
        const s = daemon.sessions.get(session);
        if (!s) return { status: 404, body: { error: 'unknown session' } };
        seqs = s.seqs;
      } else {
        seqs = [];
        for (let i = after + 1; i < daemon.lineOff.length; i++) if (daemon.lineOff[i] !== undefined) seqs.push(i);
      }
      // read in batches so a quiet kind filter over a long ledger does not load it all
      const out: Record<string, any>[] = [];
      let last = after;
      for (let i = 0; i < seqs.length && out.length < limit; i += 200) {
        const batch = seqs.slice(i, i + 200).filter((q: number) => q > after);
        for (const rec of daemon.readRecords(batch)) {
          last = rec.seq;
          if (kinds.has(rec.kind) && (!session || rec.session_id === session)) {
            out.push(compact(rec));
            if (out.length >= limit) break;
          }
        }
      }
      const more = out.length >= limit && seqs.some((q: number) => q > last);
      return { status: 200, body: { schema: SCHEMA, records: out, next_after: more ? last : null } };
    }
  }
  return { status: 404, body: { error: 'not found' } };
}

export const VERSION = pkg.version;
