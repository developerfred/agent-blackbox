'use strict';
// Where agent-blackbox keeps its evidence, keys and config.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const HOME = process.env.BLACKBOX_HOME || path.join(os.homedir(), '.blackbox');
const PORT = Number(process.env.BLACKBOX_PORT || 7071);

const P = {
  home: HOME,
  port: PORT,
  ledger: path.join(HOME, 'ledger.jsonl'),
  blobs: path.join(HOME, 'blobs'),
  keys: path.join(HOME, 'keys'),
  privKey: path.join(HOME, 'keys', 'ed25519.key'),
  pubKey: path.join(HOME, 'keys', 'ed25519.pub'),
  token: path.join(HOME, 'keys', 'token'),
  config: path.join(HOME, 'config.json'),
  state: path.join(HOME, 'state.json'),
  spool: path.join(HOME, 'spool.jsonl'),
  pid: path.join(HOME, 'daemon.pid'),
  log: path.join(HOME, 'daemon.log'),
  bodies: path.join(HOME, 'api-bodies'),
  anchors: path.join(HOME, 'anchors.jsonl'),
};

const DEFAULT_CONFIG = {
  // ask = make Claude Code prompt the human; deny = block; monitor = log only
  mode: 'ask',
  // encrypt payloads at rest with one key per session (purge = crypto-erasure)
  encrypt: true,
  // running code the policy cannot inspect (scripts the agent wrote, inline or
  // heredoc code, test runners after risky edits) while the lethal trifecta is
  // active: 'ask' (default) or 'alert' (record and tell the human, do not prompt)
  opaqueCode: 'ask',
  // what the hook does for PreToolUse when the daemon is unreachable
  failMode: 'open',
  // hosts considered safe destinations for outbound traffic (suffix match)
  allowHosts: [
    'github.com', 'githubusercontent.com', 'registry.npmjs.org', 'npmjs.com',
    'pypi.org', 'files.pythonhosted.org', 'crates.io', 'static.crates.io',
    'anthropic.com', 'claude.ai', 'claude.com', 'localhost', '127.0.0.1',
  ],
  // MCP tools count as untrusted input unless their server is listed here
  trustedMcpServers: [],
  // MCP servers whose results are private data (e.g. gmail, drive, slack)
  privateMcpServers: [],
};

function ensureDirs() {
  for (const d of [P.home, P.keys]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  for (const d of [P.blobs, P.bodies]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(P.token)) {
    fs.writeFileSync(P.token, crypto.randomBytes(24).toString('hex'), { mode: 0o600 });
  }
}

function readToken() {
  try { return fs.readFileSync(P.token, 'utf8').trim(); } catch { return ''; }
}

function loadConfig() {
  let user = {};
  try { user = JSON.parse(fs.readFileSync(P.config, 'utf8')); } catch { /* defaults */ }
  return { ...DEFAULT_CONFIG, ...user };
}

function saveConfig(cfg) {
  fs.writeFileSync(P.config, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
}

module.exports = { P, DEFAULT_CONFIG, ensureDirs, readToken, loadConfig, saveConfig };
