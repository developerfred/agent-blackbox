// Claude Code: the reference adapter. Its hook payloads are the canonical
// event format, and the recorder's reply already has Claude Code's shape.
import { failClosedVerdict } from './shared';
import type { Adapter, HookEvent } from '../types';

const adapter: Adapter = {
  id: 'claude',
  name: 'Claude Code',
  // every lifecycle event, and "ask" is a native permission decision
  capabilities: { preTool: true, ask: true, postTool: true, prompt: true, session: true },
  decode(native) { return native as HookEvent; },
  encode(res) { return { stdout: res && res.stdout ? res.stdout : null }; },
  failClosed(ev, reason) { return ev.hook_event_name === 'PreToolUse' ? { stdout: failClosedVerdict(reason) } : null; },
};
export = adapter;
