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
  /** for agents that cannot ask the human: what an "ask" becomes */
  askFallback?: 'deny' | 'allow';
  /** erase sessions older than this many days (crypto-erase); null or 0 keeps everything */
  retainDays?: number | null;
  /** opt-in automatic anchoring: where to publish the chain head and Merkle root */
  anchor?: { file?: string; webhook?: string; every?: number; minutes?: number };
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
  /** hooks installed into other agents (`blackbox install --agent`) */
  installedAgents?: Record<string, { file: string; at: string }>;
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
  /** which agent sent it; absent for Claude Code */
  agent?: string;
  [extra: string]: unknown;
}

/** What the recorder decided about one event, in the agent-neutral form adapters encode. */
export interface Verdict {
  /** "ask" and "deny" gate a tool call; null only informs */
  permission: 'ask' | 'deny' | null;
  /** the detail for the human */
  reason: string;
  /** the (deliberately uninformative) text the model may see when the call is blocked, including an "ask" an agent cannot show */
  agentMessage: string;
  /** a notice for the human that gates nothing */
  notice: string | null;
}

/** What an adapter hands the hook process to print and exit with. */
export interface HookOutput { stdout?: object | null; stderr?: string; exit?: number }

/** What the agent can do at its hook points; documented per adapter in docs/AGENTS.md. */
export interface AdapterCapabilities {
  /** a hook can stop a tool call before it runs */
  preTool: boolean;
  /** a hook can hand the decision to the human instead of the model */
  ask: boolean;
  /** tool results reach a hook (needed to learn what the session has read) */
  postTool: boolean;
  prompt: boolean;
  session: boolean;
}

/** Where and how an agent is told to call the hook script. */
export interface AgentHooksFile {
  file(): string;
  /** add our hooks to the parsed file; returns the events registered */
  add(json: Record<string, any>, command: string): string[];
  /** remove only our entries */
  remove(json: Record<string, any>): void;
  /** what the human must still do, if anything */
  note?: string;
}

/** The one place that knows an agent's own hook format. */
export interface Adapter {
  id: string;
  name: string;
  capabilities: AdapterCapabilities;
  /** the agent's payload to a canonical event; null for events nothing is recorded for */
  decode(native: Record<string, any>): HookEvent | null;
  /** the recorder's reply to what the agent expects on stdout/exit; res is null when it said nothing */
  encode(res: { stdout?: object | null; verdict?: Verdict } | null, native: Record<string, any>, opts?: { askFallback?: 'deny' | 'allow' }): HookOutput;
  /** the reply when the recorder is down and failMode is "closed" */
  failClosed(ev: HookEvent, reason: string, native: Record<string, any>): HookOutput | null;
  /** how `blackbox install --agent <id>` wires the hooks; absent when there is nothing to install */
  hooksFile?: AgentHooksFile;
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
  decision?: string;
  rule?: string;
  reason?: string;
  flag?: string;
  why?: string;
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
