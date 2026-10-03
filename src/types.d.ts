// Shared types for the JavaScript sources (checked with `npm run typecheck`).
// Import them in JSDoc: /** @type {import('./types').Config} */

export type Mode = 'ask' | 'deny' | 'monitor';
export type Decision = 'ask' | 'deny' | 'alert' | 'note' | 'warn' | 'missed';

export interface Config {
  mode: Mode;
  encrypt: boolean;
  opaqueCode: 'ask' | 'alert';
  web3: 'ask' | 'alert' | 'off';
  failMode: 'open' | 'closed';
  allowHosts: string[];
  trustedMcpServers: string[];
  privateMcpServers: string[];
  /** set when the recorder runs as a dedicated OS user (blackbox harden) */
  remoteDaemon?: boolean;
  recorderHome?: string;
  recorderUser?: string;
  /** set in the recorder's own config when it cannot see the human's settings */
  hardened?: boolean;
  installed?: { hooks?: boolean; env: Record<string, string | null>; at?: string; settings?: string };
  [extra: string]: unknown;
}

/** A Claude Code hook event, as the hook forwards it. */
export interface HookEvent {
  hook_event_name?: string;
  session_id: string;
  cwd?: string;
  prompt?: string;
  prompt_id?: string;
  agent_id?: string;
  tool_name?: string;
  tool_input?: Record<string, any>;
  tool_response?: unknown;
  tool_use_id?: string;
  command_name?: string;
  command_args?: string;
  [extra: string]: unknown;
}

export interface Taint { why: string; at: string; tool_use_id?: string }

/** What the policy remembers about one session. */
export interface SessionState {
  private: Taint | null;
  untrusted: Taint | null;
  secrets: string[];
  /** lengths of the learned secrets (a superset), to skip hashing other tokens */
  secretLens?: number[];
  phraseLens?: number[];
  written: string[];
  netFiles: string[];
  intentHosts?: string[];
  denied?: { rule: string; at: string };
  cwd?: string;
}

export interface PolicyDecision {
  decision: Decision;
  rule: string;
  reason: string;
  secret?: string;
}

export interface Egress {
  yes: boolean;
  why?: string;
  intended?: boolean;
  opaque?: boolean;
  web3?: boolean;
}

export interface LedgerRecord {
  v: number;
  seq: number;
  ts: string;
  kind: string;
  prev: string;
  hash: string;
  sig: string;
  session_id?: string;
  event?: string;
  summary?: string;
  payload?: string;
  request_blob?: string;
  response_blob?: string;
  key?: string;
  [extra: string]: unknown;
}

/** What the daemon keeps in state.json. */
export interface DaemonState {
  sessions: Record<string, SessionState>;
  salt: string;
  bodyIndexOffset: number;
  integrity?: { fingerprint?: string; via: string | null; problems: string[]; at: string };
  [extra: string]: unknown;
}

export interface Paths {
  home: string; port: number; ledger: string; blobs: string; keys: string;
  privKey: string; pubKey: string; token: string; adminToken: string;
  config: string; state: string; spool: string; pid: string; log: string;
  bodies: string; anchors: string;
}
