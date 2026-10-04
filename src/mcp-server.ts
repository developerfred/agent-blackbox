// A local MCP server (stdio) that exposes the agent API as read-only tools, so a
// coding agent can ask blackbox what it is, whether it is recording and what the
// rules are, in the way agents already consume tools.
//
// It speaks newline-delimited JSON-RPC on stdin/stdout and calls the recorder on
// 127.0.0.1 with a token. By default that is the ingest token (the public tier);
// the record and session tools are offered only when started with `--admin`,
// i.e. by the human who is willing to hand the agent that view.
import { request } from './local-http';
import { ENDPOINTS, SCHEMAS, VERSION } from './agent-api';

export { ENDPOINTS };

const PROTOCOL = '2025-06-18';
const NAME = 'agent-blackbox';

export const TOOLS: { name: string; path: string; description: string; schema: string; admin?: boolean; props?: Record<string, unknown> }[] = [
  { name: 'blackbox_capabilities', path: '/v1/agent/capabilities', description: 'What agent-blackbox is, which tools and endpoints exist, rule ids, record kinds and what it never returns. Call this first.', schema: 'Capabilities' },
  { name: 'blackbox_status', path: '/v1/agent/status', description: 'Whether the recorder is running and the ledger chain is intact.', schema: 'Status' },
  { name: 'blackbox_rules', path: '/v1/agent/rules', description: 'The policy rules that can block or question a tool call, with their usual decision.', schema: 'Rules' },
  { name: 'blackbox_sessions', path: '/v1/agent/sessions', admin: true, description: 'Recorded sessions with event, tool and decision counts and taint flag names.', schema: 'Sessions' },
  {
    name: 'blackbox_records', path: '/v1/agent/records', admin: true, schema: 'Records',
    description: 'Decision and taint records (compact metadata, never payloads), oldest first. Page with next_after.',
    props: { session: { type: 'string', description: 'only this session id' }, kind: { type: 'string', description: 'comma-separated record kinds, default decision,taint' }, after: { type: 'integer', description: 'cursor: records with seq greater than this' }, limit: { type: 'integer', minimum: 1, maximum: 500 } },
  },
];

export function listTools({ admin = false }: { admin?: boolean } = {}) {
  return TOOLS.filter((t) => admin || !t.admin).map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: { type: 'object', properties: t.props || {}, additionalProperties: false },
    outputSchema: (SCHEMAS as Record<string, unknown>)[t.schema],
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }));
}

/** Returns a function that handles one JSON-RPC message; null means no response. */
export function createHandler({ admin = false, fetch }: { admin?: boolean; fetch: (path: string) => Promise<{ status: number; body: any }> }): (msg: any) => Promise<any | null> {
  const tools = new Map(TOOLS.filter((t) => admin || !t.admin).map((t) => [t.name, t]));
  const ok = (id: unknown, result: unknown) => ({ jsonrpc: '2.0', id, result });
  const err = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });
  return async (msg) => {
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return msg && msg.id !== undefined ? err(msg.id, -32600, 'invalid request') : null;
    const { id, method, params = {} } = msg;
    if (id === undefined) return null; // notifications (initialized, cancelled…) need no answer
    switch (method) {
      case 'initialize':
        return ok(id, { protocolVersion: PROTOCOL, capabilities: { tools: { listChanged: false } }, serverInfo: { name: NAME, version: VERSION }, instructions: 'Read-only view of the local agent-blackbox recorder. Start with blackbox_capabilities.' });
      case 'ping': return ok(id, {});
      case 'tools/list': return ok(id, { tools: listTools({ admin }) });
      case 'tools/call': {
        const t = tools.get(params.name);
        if (!t) return err(id, -32602, `unknown tool: ${params.name}`);
        const args = params.arguments || {};
        const q = new URLSearchParams();
        for (const k of Object.keys(t.props || {})) if (args[k] !== undefined && args[k] !== null) q.set(k, String(args[k]));
        let r: { status: number; body: any };
        try { r = await fetch(t.path + (q.toString() ? `?${q}` : '')); } catch (e) {
          return ok(id, { isError: true, content: [{ type: 'text', text: 'agent-blackbox recorder is not reachable on 127.0.0.1 (is it running? `blackbox start`)' }] });
        }
        if (r.status !== 200) return ok(id, { isError: true, content: [{ type: 'text', text: JSON.stringify(r.body || { error: `status ${r.status}` }) }] });
        return ok(id, { content: [{ type: 'text', text: JSON.stringify(r.body) }], structuredContent: r.body });
      }
      default: return err(id, -32601, `method not found: ${method}`);
    }
  };
}

/** Serve on stdio until stdin closes. */
export function serve({ admin = false, port, token }: { admin?: boolean; port: number; token: string }): void {
  const handle = createHandler({ admin, fetch: (path) => request({ port, path, token }) });
  let buf = '';
  const send = (m: unknown) => process.stdout.write(JSON.stringify(m) + '\n');
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buf += chunk;
    for (let i; (i = buf.indexOf('\n')) >= 0;) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let msg: any;
      try { msg = JSON.parse(line); } catch { send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); continue; }
      handle(msg).then((r) => { if (r) send(r); }, () => { if (msg && msg.id !== undefined) send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: 'internal error' } }); });
    }
  });
}
