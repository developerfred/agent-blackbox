// Shared types for the JavaScript sources (checked with `npm run typecheck`).
// Import them in JSDoc: /** @type {import('./types').Config} */

export type Mode = 'ask' | 'deny' | 'monitor';
export type Decision = 'ask' | 'deny' | 'alert' | 'note' | 'warn' | 'missed';

export interface Config {
  mode: Mode;
  encrypt: boolean;
  opaqueCode: 'ask' | 'alert';
  web3: 'ask' | 'alert' | 'off';
  memoryWrites: 'ask' | 'alert' | 'off';
  trustedDocs: string[];
  failMode: 'open' | 'closed';
  /** erase sessions older than this many days (crypto-erase); null or 0 keeps everything */
  retainDays?: number | null;
  allowHosts: string[];
  trustedMcpServers: string[];
  privateMcpServers: string[];
  /** set when the recorder runs as a dedicated OS user (blackbox harden) */
  remoteDaemon?: boolean;
  recorderHome?: string;
  recorderUser?: string;
  /** root-owned copy of the code the recorder runs from; hooks point there */
  recorderCode?: string;
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

/** What the policy remembers across events and sessions. */
export interface PolicyState {
  sessions: Record<string, SessionState>;
  /** instruction/memory documents written by a session that had read untrusted content */
  docs?: Record<string, { session: string; at: string; why: string }>;
}

/** What the daemon keeps in state.json. */
export interface DaemonState extends PolicyState {
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

export type Severity = 'high' | 'medium' | 'low' | 'info' | 'none';

export interface Finding {
  severity: Severity;
  rule: string;
  message: string;
  detail?: string | null;
  file?: string;
  line?: number;
  excerpt?: string | null;
}

export interface Counts { high: number; medium: number; low: number }

/** One configured MCP server, audited (src/mcp.js). */
export interface McpAudit {
  name: string; client: string; scope: string; transport: string;
  command?: string | null; args: string[]; url?: string | null;
  findings: Finding[]; counts: Counts; risk: Severity;
  /** set by auditServers once pins are compared */
  pin?: 'new' | 'pinned' | 'changed';
  pinKey?: string;
  file?: string;
  plugin?: string;
  hash?: string;
  [extra: string]: unknown;
}

/** One installed skill, audited (src/skills.js). */
export interface SkillAudit {
  name: string; source: string; fileCount: number;
  risk: Severity; counts: Counts;
  pin: { status: 'new' | 'pinned' | 'changed'; [extra: string]: unknown };
  findings: Finding[];
  [extra: string]: unknown;
}

/** What scan() returns and the renderers (terminal, HTML, share kit) take. */
export type ScanSummary = ReturnType<typeof import('./scan').scan>;
