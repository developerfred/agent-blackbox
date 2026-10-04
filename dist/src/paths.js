'use strict';
// Where agent-blackbox keeps its evidence, keys and config.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const HOME = process.env.BLACKBOX_HOME || path.join(os.homedir(), '.blackbox');
const PORT = Number(process.env.BLACKBOX_PORT || 7071);
/** @type {import('./types').Paths} */
const P = {
    home: HOME,
    port: PORT,
    ledger: path.join(HOME, 'ledger.jsonl'),
    blobs: path.join(HOME, 'blobs'),
    keys: path.join(HOME, 'keys'),
    privKey: path.join(HOME, 'keys', 'ed25519.key'),
    pubKey: path.join(HOME, 'keys', 'ed25519.pub'),
    // ingest token: lets hooks and telemetry add events (and read /health) only
    token: path.join(HOME, 'keys', 'token'),
    // admin token: everything else (timeline, payloads, verify, purge)
    adminToken: path.join(HOME, 'keys', 'admin-token'),
    config: path.join(HOME, 'config.json'),
    state: path.join(HOME, 'state.json'),
    spool: path.join(HOME, 'spool.jsonl'),
    pid: path.join(HOME, 'daemon.pid'),
    log: path.join(HOME, 'daemon.log'),
    bodies: path.join(HOME, 'api-bodies'),
    anchors: path.join(HOME, 'anchors.jsonl'),
};
/** @type {import('./types').Config} */
const DEFAULT_CONFIG = {
    // ask = make Claude Code prompt the human; deny = block; monitor = log only
    mode: 'ask',
    // encrypt payloads at rest with one key per session (purge = crypto-erasure)
    encrypt: true,
    // running code the policy cannot inspect (scripts the agent wrote, inline or
    // heredoc code, test runners after risky edits) while the lethal trifecta is
    // active: 'ask' (default) or 'alert' (record and tell the human, do not prompt)
    opaqueCode: 'ask',
    // signing or broadcasting a transaction (cast send, forge script --broadcast,
    // solana transfer, key material on a command line): 'ask' (default), 'alert' or 'off'
    web3: 'ask',
    // a session that read untrusted content changing AGENTS.md, CLAUDE.md, editor rules,
    // agent commands or skills (files later sessions trust): 'ask' (default), 'alert' or 'off'
    memoryWrites: 'ask',
    // what the hook does for PreToolUse when the daemon is unreachable
    failMode: 'open',
    // erase sessions older than this many days, automatically (same as `blackbox purge --days N`); null keeps everything
    retainDays: null,
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
    for (const d of [P.home, P.keys])
        fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    for (const d of [P.blobs, P.bodies])
        fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    // with the recorder as its own user, the admin token lives with the recorder, not here
    for (const f of loadConfig().remoteDaemon ? [P.token] : [P.token, P.adminToken]) {
        if (!fs.existsSync(f))
            fs.writeFileSync(f, crypto.randomBytes(24).toString('hex'), { mode: 0o600 });
    }
}
function readToken() {
    try {
        return fs.readFileSync(P.token, 'utf8').trim();
    }
    catch {
        return '';
    }
}
// With the recorder running as a dedicated user, only the ingest token is
// in the human's folder and this returns ''; reads then go through sudo.
function readAdminToken() {
    try {
        return fs.readFileSync(P.adminToken, 'utf8').trim();
    }
    catch { /* not ours to read */ }
    return '';
}
// With the recorder as a dedicated user, the admin token is read through sudo,
// which asks the human for a password the agent cannot type. Only the CLI
// calls this, and only for commands that read, verify or erase.
/** @type {string | null} */
let sudoToken = null;
function readAdminTokenViaSudo() {
    if (sudoToken !== null)
        return sudoToken;
    const cfg = loadConfig();
    if (!cfg.remoteDaemon || !cfg.recorderHome || !cfg.recorderUser)
        return (sudoToken = '');
    try {
        const out = require('child_process').execFileSync('sudo', ['-u', cfg.recorderUser, 'cat', path.join(cfg.recorderHome, 'keys', 'admin-token')], { stdio: ['inherit', 'pipe', 'inherit'] });
        return (sudoToken = out.toString('utf8').trim());
    }
    catch {
        return (sudoToken = '');
    }
}
/** @returns {import('./types').Config} */
/**
 * The token the CLI presents to the recorder. Recorder as the same user: the
 * admin token if there is one, else the ingest token. Recorder as its own user:
 * a leftover admin-token file in this folder belongs to a recorder that is gone
 * and would be refused, so reads use the admin token fetched through sudo and
 * everything else the ingest token.
 * @param {boolean} [admin] does this call read, verify or erase?
 */
function cliToken(admin = true) {
    if (loadConfig().remoteDaemon)
        return (admin ? readAdminTokenViaSudo() : '') || readToken();
    return readAdminToken() || readToken();
}
function loadConfig() {
    let user = {};
    try {
        user = JSON.parse(fs.readFileSync(P.config, 'utf8'));
    }
    catch { /* defaults */ }
    return { ...DEFAULT_CONFIG, ...user };
}
/** @param {import('./types').Config} cfg */
function saveConfig(cfg) {
    fs.writeFileSync(P.config, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
}
module.exports = { P, DEFAULT_CONFIG, ensureDirs, readToken, readAdminToken, readAdminTokenViaSudo, cliToken, loadConfig, saveConfig };
