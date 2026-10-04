// Pieces every adapter needs.

import type { Verdict } from '../types';

/** Claude Code's PreToolUse deny reply, used when the recorder is down and failMode is "closed". */
export function failClosedVerdict(reason: string) {
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
}

/** Turn the recorder's verdict into what an agent without an "ask" prompt can act on. */
export function withAskFallback(v: Verdict | null | undefined, canAsk: boolean, askFallback: 'deny' | 'allow'): Verdict | null | undefined {
  if (!v || v.permission !== 'ask' || canAsk) return v;
  if (askFallback === 'allow') return { ...v, permission: null, notice: v.reason };
  return { ...v, permission: 'deny', reason: `${v.reason} (this agent cannot ask you, so the call was blocked)` };
}

/** Parse a value an agent sends as a JSON string; keep it as-is when it is not JSON. */
export function maybeJson(v: unknown): unknown {
  if (typeof v !== 'string') return v;
  try { return JSON.parse(v); } catch { return v; }
}

export const str = (s: unknown): string => (typeof s === 'string' ? s : '');

/** Marks a hook command as ours, as an argument (some agents run commands without a shell, so no trailing comment). */
export const MARKER = '--agent-blackbox-hook';
export const isOurs = (h: any): boolean => !!h && typeof h.command === 'string' && h.command.includes('agent-blackbox-hook');

/** Remove our hook entries from `json.hooks`, keeping the user's own, and drop what is left empty.
 * `nested`: true for { hooks: [{ command }] } groups, false for flat [{ command }] entries. */
export function stripOurs(json: Record<string, any>, nested: boolean): void {
  const hooks = json.hooks || {};
  for (const ev of Object.keys(hooks)) {
    hooks[ev] = (hooks[ev] || []).map((g: any) => (nested ? { ...g, hooks: (g.hooks || []).filter((h: any) => !isOurs(h)) } : g))
      .filter((g: any) => (nested ? g.hooks.length : !isOurs(g)));
    if (!hooks[ev].length) delete hooks[ev];
  }
  if (Object.keys(hooks).length) json.hooks = hooks; else delete json.hooks;
}
