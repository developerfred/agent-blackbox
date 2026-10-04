'use strict';
// "Lethal trifecta" policy: an agent session becomes dangerous when it has
// (1) touched private data, (2) ingested untrusted content, and (3) tries to
// send something out. Each condition alone is normal; together they are the
// shape of a prompt-injection exfiltration.
const crypto = require('crypto');
const path = require('path');
const { baseName, pushCapped } = require('./util');
const SENSITIVE_PATH = [
    /(^|[\/\s'"=@<])\.env(\.[\w-]+)?(\b|$)/i,
    /\.ssh\//, /\bid_(rsa|dsa|ecdsa|ed25519)\b/,
    /\.aws\/(credentials|config)/, /\.netrc\b/, /\.npmrc\b/, /\.pypirc\b/,
    /\.git-credentials\b/, /\.docker\/config\.json/, /\.kube\/config/,
    /\.gnupg\//, /\.(pem|p12|pfx|key)\b/, /credentials?\.json/i,
    /keystores?\//i, /\bmnemonic\b/i, /seed[_-]?phrase/i,
    // wallets: Foundry/Geth keystores, Solana and Sui keypairs, Bitcoin wallets, Hardhat secrets
    /\.foundry\/keystores/, /(^|\/)UTC--\d{4}-\d\d-\d\dT/, /\.config\/solana\//,
    /\.sui\/sui_config\//, /\.aptos\/config/, /\.(?:ethereum|bitcoin)\/(?:keystore|wallets?|wallet\.dat)/, /(^|\/)wallet\.dat\b/,
    /\.(?:keystore|wallet)\b/, /(^|\/)\.secret\b/, /\bwallet[_-]?(?:backup|keys?)\b/i, /\bseed\.(?:txt|json)\b/i,
    /\.blackbox\//, /Library\/Keychains/,
];
const SECRET_PATTERNS = [
    /\bAKIA[0-9A-Z]{16}\b/g,
    /\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}/g,
    /\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}/g,
    /\bglpat-[A-Za-z0-9_\-]{20,}/g,
    /\bnpm_[A-Za-z0-9]{36}\b/g,
    /\bgh[pousr]_[A-Za-z0-9]{30,}/g,
    /\bgithub_pat_[A-Za-z0-9_]{40,}/g,
    /\bxox[abpr]-[A-Za-z0-9-]{10,}/g,
    /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g, // Bitcoin WIF private key
    /\[(?:\s*\d{1,3}\s*,){63}\s*\d{1,3}\s*\]/g, // Solana keypair file (64 bytes as a JSON array)
];
// Secrets only recognizable by what they are labelled as: a 64-hex value is a
// transaction hash unless it is called a private key, and a mnemonic is a run
// of ordinary words. group 1 is the value.
const CONTEXT_SECRETS = [
    { re: /\b(?:private[ _-]?key|priv[ _-]?key|secret[ _-]?key|signing[ _-]?key|deployer[ _-]?key)\b["'\]]?\s*[:=]?\s*["']?((?:0x)?[0-9a-fA-F]{64})\b/gi, phrase: false },
    { re: /\b(?:mnemonic|seed[ _-]?phrase|recovery[ _-]?phrase|secret recovery phrase)\b["']?\s*[:=]?\s*["']?((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})\b/gi, phrase: true },
];
const PHRASE_LENGTHS = [24, 21, 18, 15, 12];
/** @param {string} p @returns {string | null} */
const normPhrase = (p) => {
    const w = p.toLowerCase().split(/\s+/).filter(Boolean);
    const n = PHRASE_LENGTHS.find((l) => l <= w.length);
    return n ? w.slice(0, n).join(' ') : null;
};
// A web3 keystore file (encrypted private key): its presence means wallet material
const KEYSTORE_JSON = /"kdf"\s*:\s*"(?:scrypt|pbkdf2)"|"ciphertext"\s*:\s*"[0-9a-f]{64,}"/i;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const PRIVATE_KEY_FULL = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const TOKEN = /[A-Za-z0-9_\-+\/=.:]{8,}/g;
// KEY=value lines in .env-style content
const ENV_SECRET_LINE = /^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PRIVATE|MNEMONIC|SEED|CREDENTIAL|AUTH)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'#]{8,})/gim;
const NET_TOOL = /(?:^|[\s;&|(`$])(curl|curl\.exe|wget|wget2|nc|ncat|netcat|socat|telnet|ftp|tftp|sftp|scp|rsync|ssh|http|https|xh|aria2c|nslookup|dig|host|lftp|websocat|grpcurl)(?=\s|$)/;
// Network code inside a command: interpreters with inline networking, Node
// built-ins, PowerShell web cmdlets, raw TLS.
const NET_CODE = new RegExp([
    String.raw `\b(?:python3?|node|ruby|perl|deno|bun|php)\b[^|;]*(?:requests\.|urllib|http\.client|httpx|aiohttp|fetch\(|net\/http|socket|axios|XMLHttpRequest|Net::HTTP|https?\.(?:request|get)|LWP|IO::Socket|file_get_contents\(\s*['"]https?:)`,
    String.raw `require\(\s*['"](?:node:)?(?:https?|http2|net|tls|dgram)['"]\s*\)`,
    String.raw `\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b`, String.raw `Net\.WebClient`, String.raw `\bopenssl\s+s_client\b`,
].join('|'), 'i');
const DEV_TCP = /\/dev\/(tcp|udp)\//;
// Commands that publish data to a service. They count as egress even toward
// allowlisted hosts (a secret pasted into a public gist is still a leak): the
// allowlist is for downloads, not uploads.
/** @type {[RegExp, string][]} */
const PUBLISH = [
    [/\bgit\s+push\b/, 'git push'],
    [/\bgh\s+gist\s+(?:create|new|edit)\b/, 'gh gist (publishes content)'],
    [/\bgh\s+(?:issue|pr|discussion)\s+(?:create|new|comment|edit|review)\b/, 'gh posts to an issue or pull request'],
    [/\bgh\s+release\s+(?:create|upload|edit)\b/, 'gh release upload'],
    [/\bgh\s+api\b.*\s(?:-f|-F|--field|--raw-field|--input|-X\s*(?:POST|PUT|PATCH|DELETE)|--method\s+(?:POST|PUT|PATCH|DELETE))\b/i, 'gh api write request'],
    [/\b(?:npm|pnpm|yarn)\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b|\bgem\s+push\b|\bdocker\s+push\b/, 'publishes a package or image'],
    [/\baws\s+s3\s+(?:cp|sync|mv)\b|\bgsutil\s+(?:cp|rsync|mv)\b|\brclone\s+(?:copy|sync|move|copyto)\b|\baz\s+storage\s+blob\s+upload/, 'cloud storage upload'],
    [/(?:^|[\s;&|(])(?:sendmail|mailx?|mutt|swaks|msmtp)(?=\s|$)/, 'sends email'],
];
// Commands that reach a host named in their arguments (downloads that can
// still carry data out in the URL): git remotes, package installs from URLs,
// browsers opened on a URL.
const FETCH_CMD = /\bgit\s+(?:clone|fetch|pull|ls-remote|submodule|remote\s+(?:add|set-url))\b|\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b|\bpip3?\s+(?:install|download)\b|\buv\s+(?:pip\s+install|add)\b|\bcargo\s+install\b|\bgo\s+(?:get|install)\b|\bgem\s+install\b|\bcomposer\s+require\b|(?:^|[\s;&|(])(?:open|xdg-open|start|explorer)(?=\s)|\bgh\s+api\b/;
// Code the agent can run without a network tool in sight.
const HEREDOC_CODE = /\b(?:python3?|node|ruby|perl|php|deno|bun|bash|sh|zsh)\s+(?:-\s+|-s\s+)?(?:[^\s|;&<>]+\s+)*<<-?\s*['"]?\w+/;
const INLINE_CODE = /\b(?:python3?|node|ruby|perl|php|deno|bun|pwsh|powershell)\s+(?:-[\w-]+\s+)*(?:-c|-e|--eval|-r|-Command|eval)\b|\b(?:bash|sh|zsh|dash|ksh)\s+(?:-\w+\s+)*-c\b|(?:^|[\s;&|(])eval(?=\s)|\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:python3?|node|perl|ruby)\b|\bsource\s+<\(|<\(\s*curl/;
const SCRIPT_RUNNER = /\b(?:npm|pnpm|yarn|bun)\s+(?:run|test|start|exec|x)\b|\bnpx\b|\bbunx\b|(?:^|[\s;&|(])make(?=\s|$)|\bpytest\b|\bcargo\s+(?:run|test)\b|\bgo\s+(?:run|test)\b|(?:^|[\s;&|(])just(?=\s|$)|\bgradlew?\b|\bmvn\b|\btox\b|\bnox\b|\buv\s+run\b|\bpoetry\s+run\b/;
const INTERP_FILE = /(?:^|[;&|(]\s*|&&\s*|\|\|\s*|\s)(?:bash|sh|zsh|dash|ksh|fish|source|(?<=^|[;&|(]\s*)\.|python3?|node|deno(?:\s+run)?|bun(?:\s+run)?|ruby|perl|php|tsx|ts-node|osascript|pwsh|powershell)\s+(?:-[\w-]+\s+)*([^\s;&|<>]+)/g;
const DIRECT_EXEC = /(?:^|[;&|(]\s*)((?:\.{1,2}|~)?\/[^\s;&|<>]+)/g;
const NET_SOURCE = /\b(?:fetch\(|XMLHttpRequest|axios|requests\.|urllib|http\.client|httpx|aiohttp|socket\.|net\/http|Net::HTTP|https?\.request|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls)['"]|from\s+['"]node:(?:https?|net|dgram|tls)['"]|curl\s|wget\s|Invoke-WebRequest|WebSocket\(|\/dev\/tcp\/)/;
// Source code that can reach the network or the shell indirectly.
const DYNAMIC_SOURCE = /\b(?:child_process|execSync|spawnSync|exec\(|spawn\(|subprocess|os\.system|os\.popen|Runtime\.getRuntime|eval\(|new Function\(|ProcessBuilder|system\(|`[^`]*\$\()/;
// Files that tell an agent how to behave in LATER sessions: project instructions,
// agent memory, editor rules, commands and skills. A session that read untrusted
// content must not be able to plant text there: the next session would trust it.
/** @type {RegExp[]} */
const MEMORY_DOC = [
    /(^|\/)(?:AGENTS|CLAUDE|CLAUDE\.local|GEMINI|CONVENTIONS)\.md$/i,
    /(^|\/)\.claude\/(?:CLAUDE\.md|commands\/|agents\/|rules\/|memory\/|output-styles\/|skills\/)/,
    /(^|\/)\.(?:cursorrules|windsurfrules|clinerules)$/,
    /(^|\/)\.cursor\/rules\//,
    /(^|\/)\.github\/(?:copilot-instructions\.md|instructions\/)/,
    /(^|\/)\.continue\/rules\//,
];
/** @param {string} p */
const isMemoryDoc = (p) => MEMORY_DOC.some((re) => re.test(String(p).replace(/\\/g, '/')));
// Files the agent loads on its own at the start of a session (no Read call involved).
const AUTOLOADED = /(?:^|\/)(?:AGENTS|CLAUDE|CLAUDE\.local|GEMINI)\.md$|(?:^|\/)\.(?:cursorrules|windsurfrules|clinerules)$|(?:^|\/)\.github\/copilot-instructions\.md$/i;
/**
 * A stable key for a file. Home folders collapse to ~ (the recorder may run as another
 * user, and a write seen as ~/x must match a read of /Users/me/x), relative paths resolve
 * against the session's folder.
 * @param {string} file @param {string} [cwd]
 */
function docKey(file, cwd) {
    const home = (/** @type {string} */ p) => p.replace(/^\/(?:Users|home)\/[^/]+(?=\/|$)/, '~').replace(/^\/root(?=\/|$)/, '~');
    let p = String(file).replace(/\\/g, '/');
    if (!p.startsWith('/') && !p.startsWith('~'))
        p = path.posix.join(home(String(cwd || '').replace(/\\/g, '/')), p);
    return path.posix.normalize(home(p));
}
// A copy of a shell command with the usual obfuscations undone, so c''url,
// "curl", \curl, cu$'r'l, $'\x63url' and curl${IFS}x all read as curl.
/** @param {unknown} cmd @returns {string} */
function normalizeCmd(cmd) {
    let s = String(cmd || '');
    s = s.replace(/\\\n/g, '');
    s = s.replace(/\$'((?:[^'\\]|\\.)*)'/g, (m, /** @type {string} */ body) => body
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\(.)/g, '$1'));
    s = s.replace(/\$\{IFS\}|\$IFS\b/g, ' ');
    s = s.replace(/["']/g, '');
    s = s.replace(/\\(?=[A-Za-z0-9._\/-])/g, '');
    s = s.replace(/\$\{?[A-Za-z_][A-Za-z0-9_]*:?-?\}?(?=[A-Za-z])/g, ''); // c${x}url → curl (empty vars)
    return s;
}
const HEREDOC_BODY = /<<-?\s*(['"]?)(\w+)\1[^\n]*\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g;
/** @param {unknown} cmd @returns {string} */
function stripHeredocs(cmd) {
    return String(cmd || '').replace(HEREDOC_BODY, (m) => m.split('\n')[0]);
}
// The command words only: heredoc bodies and quoted strings removed, so code
// or text inside them is not read as commands, files or redirections.
/** @param {unknown} cmd @returns {string} */
function shellSkeleton(cmd) {
    let s = String(cmd || '');
    s = stripHeredocs(s);
    s = s.replace(/'[^'\n]*'|"(?:[^"\\\n]|\\.)*"/g, '""');
    return s;
}
// Glob tokens in a command (e.g. ~/.bl*box, .b?ackbox/*) as regexes.
/** @param {unknown} cmd @returns {RegExp[]} */
function globsIn(cmd) {
    /** @type {RegExp[]} */
    const out = [];
    for (const tok of String(cmd).split(/[\s;&|()<>]+/)) {
        if (!/[*?[]/.test(tok))
            continue;
        for (const seg of tok.split('/')) {
            if (!/[*?[]/.test(seg) || seg.replace(/[*?]/g, '').length < 2)
                continue;
            try {
                out.push(new RegExp('^' + seg.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$'));
            }
            catch { /* skip */ }
        }
    }
    return out;
}
// Commands whose output is credentials: environment dumps and CLI token getters.
// Debug output fed back to the model was the main credential leak channel in
// "How Your Credentials Are Leaked by LLM Agent Skills" (arXiv:2604.03070).
const CREDENTIAL_CMD = new RegExp([
    String.raw `(?:^|[\s;&|(])(?:printenv|env)(?=\s*(?:$|[;&|>)]))`,
    String.raw `(?:^|[\s;&|(])set(?=\s*(?:$|[;&|>)]))`,
    String.raw `\bexport\s+-p\b`, String.raw `\bdeclare\s+-[xp]\b`, String.raw `\/proc\/[^\s]*\/environ\b`,
    String.raw `\bgh\s+auth\s+(?:token|status\s+--show-token)`, String.raw `\bgcloud\s+auth\s+(?:print-access-token|print-identity-token)`,
    String.raw `\baws\s+(?:configure\s+(?:get|export-credentials)|sts\s+get-session-token|secretsmanager\s+get-secret-value|ssm\s+get-parameters?)`,
    String.raw `\bkubectl\s+get\s+secrets?\b`, String.raw `\bsecurity\s+find-(?:generic|internet)-password\b`,
    String.raw `\bop\s+(?:read|item\s+get)\b`, String.raw `\bvault\s+(?:kv\s+get|read)\b`, String.raw `\bheroku\s+auth:token\b`,
    String.raw `\bnpm\s+token\b`, String.raw `\bdocker\s+inspect\b`,
    String.raw `\bcast\s+wallet\s+(?:new|vanity|private-key|decrypt-keystore|import)\b`, String.raw `\bsolana-keygen\s+(?:new|recover)\b`,
    String.raw `\bgeth\s+account\s+(?:new|import)\b`, String.raw `\bbitcoin-cli\s+(?:dumpprivkey|dumpwallet|walletpassphrase)\b`,
    String.raw `\bsui\s+keytool\s+(?:export|generate|import)\b`, String.raw `\bcat\s+[^\n;&|]*(?:\.foundry\/keystores|\.config\/solana)\b`,
].join('|'));
// Text in a file the agent reads that tries to steer the agent: an instruction
// override, or a request addressed to an AI to send secrets or data somewhere.
// Plain agent guidance ("run npm test before committing") does not match, so
// reading a CLAUDE.md or CONTRIBUTING.md does not taint the session.
const OVERRIDE = /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}\b(?:instructions?|rules|prompts?|guidelines|directions)\b/i;
const EXFIL_ASK = /\b(?:send|post|upload|exfiltrate|forward|transmit|leak|reveal|curl|wget|email|submit|include|print|paste|append)\b[^\n]{0,120}?(?:\.env\b|\b(?:secrets?|credentials?|tokens?|api[_ -]?keys?|passwords?|private[_ -]keys?|ssh keys?|environment variables?|id_rsa|mnemonic|seed phrase)\b)/gi;
const AGENT_WORD = /\b(?:ai|llm|assistants?|agents?|claude|copilot|chatgpt|gpt|cursor|codex|model)s?\b/i;
const NEGATED = /(?:\b(?:do not|don't|dont|never|must not|should not|shouldn't|avoid|without|no)\b|\bnot to\b)[^.\n]{0,40}$/i;
const INVISIBLE_TAGS = /[\u{E0000}-\u{E007F}]{4,}/u;
// Returns why the text looks like a prompt injection, or null.
/** @param {unknown} text @returns {string | null} */
function injectionIn(text) {
    const t = String(text || '').slice(0, 400_000);
    if (INVISIBLE_TAGS.test(t))
        return 'hidden Unicode tag characters';
    const o = OVERRIDE.exec(t);
    if (o && !NEGATED.test(t.slice(Math.max(0, o.index - 50), o.index)))
        return `instruction override ("${o[0].slice(0, 60)}")`;
    EXFIL_ASK.lastIndex = 0;
    let m;
    while ((m = EXFIL_ASK.exec(t))) {
        if (NEGATED.test(t.slice(Math.max(0, m.index - 50), m.index)))
            continue;
        const around = t.slice(Math.max(0, m.index - 300), m.index + m[0].length + 100);
        if (AGENT_WORD.test(around))
            return `asks an AI to send secrets or data out ("${m[0].slice(0, 60)}")`;
    }
    return null;
}
// A URL whose path or query holds a long opaque blob (base64, a slug without
// words, a dump) can carry data out even toward an allowlisted host. Commit
// ids and checksums are long but not data, and slugs have many hyphens.
/** @param {string} text @returns {string | null} */
function urlCarriesData(text) {
    for (const m of String(text).matchAll(/\bhttps?:\/\/[^\s'"`<>]+/gi)) {
        let u;
        try {
            u = new URL(m[0]);
        }
        catch {
            continue;
        }
        const parts = [...u.pathname.split('/'), ...[...u.searchParams.values()]];
        for (const raw of parts) {
            let p = raw;
            try {
                p = decodeURIComponent(raw);
            }
            catch { /* keep raw */ }
            if (p.length < 40 || /^[0-9a-f]{40}$|^[0-9a-f]{64}$|^sha\d+-/i.test(p))
                continue;
            if ((p.match(/-/g) || []).length > 2 || /\s/.test(p))
                continue;
            return `URL to ${u.hostname} carries a long opaque value in its path or query`;
        }
    }
    return null;
}
const FILE_READER_CMD = /\b(?:cat|head|tail|less|more|bat|sed|awk|grep|rg|ag|xxd|strings)\b/;
// Commands that sign or broadcast a transaction, or move keys. A broadcast
// cannot be undone, so these ask even outside the lethal trifecta (cfg.web3).
/** @type {[RegExp, string][]} */
const WEB3 = [
    [/\bcast\s+(?:send|publish|mktx|rpc\s+eth_send\w*)\b/, 'cast signs or broadcasts a transaction'],
    [/\bcast\s+wallet\s+sign\b/, 'cast signs a message with a wallet key'],
    [/\bforge\s+script\b[^;&|]*--broadcast\b|\bforge\s+create\b|\bforge\s+verify-contract\b/, 'forge broadcasts a deployment'],
    [/\bhardhat\s+(?:run|deploy|ignition\s+deploy|verify)\b[^;&|]*--network\s+(?!hardhat\b|localhost\b|local\b|anvil\b)\S+/i, 'hardhat deploys to a live network'],
    [/\bsolana\s+(?:transfer|program\s+(?:deploy|write-buffer|close|set-upgrade-authority)|deploy|airdrop|stake-account|withdraw-stake|delegate-stake|close-vote-account)\b|\bspl-token\s+(?:transfer|burn|close|approve|authorize|mint)\b|\banchor\s+(?:deploy|migrate|upgrade)\b/, 'solana sends a transaction or deploys a program'],
    [/\bsui\s+client\s+(?:transfer|transfer-sui|pay|pay-sui|call|publish|upgrade)\b|\baptos\s+(?:move\s+(?:publish|run)|account\s+transfer)\b|\bnear\s+(?:send|call|deploy|contract\s+deploy)\b|\bstarkli\s+(?:invoke|deploy|declare)\b|\bbitcoin-cli\s+(?:sendtoaddress|sendmany|sendrawtransaction|send|walletpassphrase|dumpprivkey)\b|\blncli\s+(?:sendpayment|sendcoins|payinvoice)\b|\bdfx\s+(?:canister\s+call|ledger\s+transfer)\b/, 'a chain CLI sends a transaction or opens a wallet'],
    [/\b(?:eth_(?:sendRawTransaction|sendTransaction|sign|signTransaction|signTypedData\w*)|personal_(?:sign|sendTransaction|unlockAccount)|sendrawtransaction|sendTransaction|signTransaction)\b/, 'JSON-RPC signs or sends a transaction'],
    [/--(?:private-key|mnemonic|mnemonic-passphrase|keystore-password)\b|\bPRIVATE_KEY=["']?(?:0x)?[0-9a-fA-F]{64}/, 'key material on the command line'],
];
const WEB3_MCP_SERVER = /(?:wallet|web3|ethereum|evm|solana|crypto|chain|defi|safe|metamask|phantom|uniswap|bitcoin)/i;
const WEB3_MCP_TOOL = /(?:sign|send|broadcast|transfer|swap|approve|deploy|withdraw|bridge|stake|mint|burn)/i;
const MCP_OUTBOUND = /(send|post|create|write|upload|publish|email|mail|message|comment|reply|push|share|invite|request|fetch|http)/i;
/** @param {string} text @returns {string[]} */
function hostsIn(text) {
    /** @type {string[]} */
    const hosts = [];
    const re = /\b(?:https?|wss?|ftp):\/\/(?:[^@\/\s'"`]+@)?([^\/\s'"`:?#]+)/gi;
    let m;
    while ((m = re.exec(text)))
        hosts.push(m[1].toLowerCase());
    const scp = /(?:^|\s)[\w.-]+@([\w.-]+):/g;
    while ((m = scp.exec(text)))
        hosts.push(m[1].toLowerCase());
    return hosts;
}
// Files edited in place by sed -i or perl -i (writtenBy covers redirects, tee, cp, mv).
/** @param {string} cmd @returns {string[]} */
function editedInPlace(cmd) {
    const n = normalizeCmd(shellSkeleton(cmd));
    if (!/\b(?:sed|perl)\s+(?:-[A-Za-z]*\s+)*-[A-Za-z]*i/.test(n))
        return [];
    return n.split(/[\s;&|()<>]+/).filter((t) => t && !t.startsWith('-'));
}
// Paths a tool call writes (the ones the memory guard looks at).
/** @param {string} tool @param {Record<string, any>} input @returns {string[]} */
function writeTargets(tool, input) {
    // an adapter may send one call that touches several files (file_paths)
    if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool))
        return [input.file_path || input.notebook_path || '', ...(Array.isArray(input.file_paths) ? input.file_paths : [])].filter(Boolean);
    if (tool === 'Bash' || tool === 'PowerShell')
        return [...writtenBy(input.command || ''), ...editedInPlace(input.command || '')];
    return [];
}
// Files written or downloaded by a shell command (redirects, tee, curl -o).
/** Files written or downloaded by a shell command.
 * @param {string} cmd @returns {string[]} */
function writtenBy(cmd) {
    /** @type {string[]} */
    const out = [];
    const n = normalizeCmd(shellSkeleton(cmd));
    for (const re of [/(?:^|[^<>&\d])>{1,2}\s*([^\s;&|<>]+)/g, /\btee\s+(?:-a\s+)?([^\s;&|<>]+)/g, /\b(?:curl|wget)\b[^;&|]*?\s-(?:o|O|-output|-output-document)[\s=]+([^\s;&|<>]+)/g, /\b(?:cp|mv|install)\s+(?:-\w+\s+)*[^\s;&|]+\s+([^\s;&|<>]+)/g, /\bchmod\s+\+?[0-7]*x?\s+([^\s;&|<>]+)/g]) {
        let m;
        while ((m = re.exec(n)))
            if (!/^\/dev\/|^&/.test(m[1]))
                out.push(m[1]);
    }
    return out;
}
/** @param {string} host @param {string[]} allow */
const allowed = (host, allow) => allow.some((a) => host === a || host.endsWith('.' + a));
// All string leaves of a value, one per line. Tool results arrive as nested
// JSON (e.g. Read returns { file: { content } }); JSON.stringify would turn the
// newlines inside them into "\\n" and hide KEY=value lines from the scanner.
/** @param {unknown} v @param {string[]} [out] @param {{ left: number }} [budget] @returns {string[]} */
function stringsOf(v, out = [], budget = { left: 2_000_000 }) {
    if (budget.left <= 0 || v == null)
        return out;
    if (typeof v === 'string') {
        out.push(v.slice(0, budget.left));
        budget.left -= v.length;
    }
    else if (Array.isArray(v))
        for (const x of v)
            stringsOf(x, out, budget);
    else if (typeof v === 'object')
        for (const x of Object.values(v))
            stringsOf(x, out, budget);
    return out;
}
/** @param {unknown} v @param {number} [max] */
function textOf(v, max = 2_000_000) {
    if (v == null)
        return '';
    const s = typeof v === 'string' ? v : JSON.stringify(v);
    return s.length > max ? s.slice(0, max) : s;
}
// Only the fields that name a target (a path, a command, a URL). File
// contents being written are not targets: a README that mentions ~/.env
// must not look like an access to it.
/** @param {Record<string, any> | undefined} toolInput */
function inputText(toolInput) {
    if (!toolInput)
        return '';
    const t = toolInput;
    return [t.command, t.file_path, t.notebook_path, t.path, t.url, t.pattern, t.glob, t.skill]
        .filter((x) => typeof x === 'string').join('\n');
}
// Where each supported agent keeps the hooks that record it.
const AGENT_HOOK_CONFIG = /(^|\/)(\.claude\/settings(\.local)?\.json|\.codex\/(hooks\.json|config\.toml))/;
class Policy {
    /**
     * protect: extra paths (the real data folder) the agent may never touch.
     * @param {import('./types').Config} cfg
     * @param {import('./types').PolicyState} state
     * @param {string | Buffer} salt
     * @param {{ protect?: string[], readFile?: ((file: string, cwd?: string) => string | null) | null }} [opts]
     */
    constructor(cfg, state, salt, { protect = [], readFile = null } = {}) {
        this.cfg = cfg;
        // readFile(path, cwd) -> text | null: lets the policy look inside a script
        // that existed before the session before it is run
        this.readFile = readFile;
        this.protect = protect.filter(Boolean);
        this.state = state; // { sessions: { id: { private, untrusted, secrets: [] } } }
        this.salt = salt;
    }
    /** Rules that ask: 'alert' (record and tell, no prompt) in monitor mode or when that rule is set to alert. @param {string | undefined} setting @returns {'ask' | 'alert'} */
    softDecision(setting) {
        return this.cfg.mode === 'monitor' || setting === 'alert' ? 'alert' : 'ask';
    }
    /** Has the human declared this document reviewed (config trustedDocs: a path, or its tail)? @param {string} key */
    trustedDoc(key) {
        return (this.cfg.trustedDocs || []).some((t) => { const k = docKey(t); return key === k || key.endsWith('/' + k.replace(/^~?\//, '')); });
    }
    /**
     * Documents a past tainted session wrote that this session loads at its start:
     * the agent reads them without a tool call, so the session begins untrusted.
     * @param {import('./types').HookEvent} ev
     * @returns {{ taints: { flag: string, why: string }[], secretsSeen: number }}
     */
    sessionStart(ev) {
        const sess = this.session(ev.session_id);
        if (ev.cwd)
            sess.cwd = ev.cwd;
        const cwd = docKey(ev.cwd || '', '');
        const hit = Object.entries(this.state.docs || {}).find(([key]) => {
            if (!AUTOLOADED.test(key) || this.trustedDoc(key))
                return false;
            const dir = path.posix.dirname(key);
            return key.startsWith('~/.claude/') || cwd === dir || cwd.startsWith(dir + '/');
        });
        if (!hit || sess.untrusted)
            return { taints: [], secretsSeen: 0 };
        const why = `${hit[0]} loads at start and was written by a session that had read untrusted content (${hit[1].why})`;
        sess.untrusted = { why, at: new Date().toISOString() };
        return { taints: [{ flag: 'untrusted', why }], secretsSeen: 0 };
    }
    /**
     * If this tool call reads a document a tainted session wrote, why that is untrusted (else null).
     * @param {string} tool @param {Record<string, any>} input @param {import('./types').SessionState} sess
     */
    poisonedDocRead(tool, input, sess) {
        const docs = this.state.docs;
        if (!docs)
            return null;
        /** @type {string[]} */
        let files = [];
        if (tool === 'Read' || tool === 'NotebookRead')
            files = [input.file_path || input.notebook_path || ''];
        else if ((tool === 'Bash' || tool === 'PowerShell') && FILE_READER_CMD.test(input.command || ''))
            files = normalizeCmd(shellSkeleton(input.command)).split(/[\s;&|()<>]+/);
        for (const f of files.filter((x) => x && isMemoryDoc(x))) {
            const key = docKey(f, sess.cwd);
            const d = docs[key];
            if (d && !this.trustedDoc(key))
                return `${key} was written by a session that had read untrusted content (${d.why})`;
        }
        return null;
    }
    /** @param {string} id @returns {import('./types').SessionState} */
    session(id) {
        const s = (this.state.sessions[id] ||= { private: null, untrusted: null, secrets: [], secretLens: [], written: [], netFiles: [] });
        s.secrets ||= [];
        if (!s.secrets.length)
            s.secretLens ||= []; // sessions saved before this field existed keep no filter
        s.written ||= []; // files the agent wrote or downloaded this session
        s.netFiles ||= []; // ...of which contain network code
        return s;
    }
    /** @param {string} value */
    mac(value) {
        return crypto.createHmac('sha256', this.salt).update(value).digest('hex').slice(0, 32);
    }
    /** @param {string} text @returns {string[]} */
    extractSecrets(text) {
        const found = new Set();
        for (const re of SECRET_PATTERNS)
            for (const m of text.matchAll(re))
                found.add(m[0]);
        for (const m of text.matchAll(ENV_SECRET_LINE))
            found.add(m[2]);
        for (const { re, phrase } of CONTEXT_SECRETS) {
            for (const m of text.matchAll(re)) {
                const v = phrase ? normPhrase(m[1]) : m[1];
                if (v)
                    found.add(v);
            }
        }
        return [...found];
    }
    // Runs of ordinary words that contain a known mnemonic, as [start, end, phrase].
    /** @param {import('./types').SessionState | null | undefined} sess @param {string} text @returns {[number, number, string][]} */
    phraseHits(sess, text) {
        const lens = (sess && sess.phraseLens) || [];
        if (!sess || !lens.length || !text)
            return [];
        const known = new Set(sess.secrets);
        /** @type {[number, number, string][]} */
        const hits = [];
        for (const run of text.matchAll(/[A-Za-z]{3,8}(?:[ \t]+[A-Za-z]{3,8}){11,}/g)) {
            const words = [...run[0].matchAll(/[A-Za-z]+/g)];
            for (const n of lens) {
                for (let i = 0; i + n <= words.length; i++) {
                    const phrase = words.slice(i, i + n).map((w) => w[0].toLowerCase()).join(' ');
                    if (known.has(this.mac(phrase)))
                        hits.push([run.index + words[i].index, run.index + words[i + n - 1].index + words[i + n - 1][0].length, phrase]);
                }
            }
        }
        return hits;
    }
    // Short public id for a secret: lets the ledger say "secret a91f… was read
    // at #5 and tried to leave at #12" without ever storing the secret.
    /** @param {string} value */
    fingerprint(value) { return this.mac(value).slice(0, 12); }
    // Returns the fingerprint of the first known secret found in text, or null.
    /** @param {import('./types').SessionState} sess @param {string} text @returns {string | null} */
    containsKnownSecret(sess, text) {
        if (!sess.secrets.length || !text)
            return null;
        const ph = this.phraseHits(sess, text)[0];
        if (ph)
            return this.fingerprint(ph[2]);
        const hit = this.knownMatcher(sess);
        for (const m of text.matchAll(TOKEN)) {
            const tok = m[0];
            if (hit(tok))
                return this.fingerprint(tok);
            // also catch the value inside KEY=value or key:value
            for (const part of tok.split(/[=:]/))
                if (hit(part))
                    return this.fingerprint(part);
        }
        return null;
    }
    // Is this token a secret the session already learned? An HMAC per token is
    // the cost of scanning text, so tokens whose length no known secret has are
    // skipped (secretLens is a superset of the lengths, never a subset).
    /** @param {import('./types').SessionState} sess @returns {(t: string) => boolean} */
    knownMatcher(sess) {
        const known = new Set(sess.secrets);
        const lens = sess.secretLens ? new Set(sess.secretLens) : null;
        return (t) => t.length >= 8 && (!lens || lens.has(t.length)) && known.has(this.mac(t));
    }
    // Replace secrets with [secret:<fingerprint>] before anything is written to
    // disk: pattern matches, KEY=value lines, private key blocks, and any value
    // this session already learned is a secret.
    /** @param {string} text @param {import('./types').SessionState | null | undefined} sess */
    scrubText(text, sess) {
        let out = text.replace(PRIVATE_KEY_FULL, (m) => `[private-key:${this.fingerprint(m)}]`);
        for (const re of SECRET_PATTERNS)
            out = out.replace(re, (m) => `[secret:${this.fingerprint(m)}]`);
        for (const { re, phrase } of CONTEXT_SECRETS) {
            out = out.replace(re, (m, v) => {
                const val = phrase ? normPhrase(v) : v;
                return val ? m.replace(v, `[secret:${this.fingerprint(val)}]`) : m;
            });
        }
        if (sess && (sess.phraseLens || []).length) {
            const hits = this.phraseHits(sess, out);
            for (const [a, b, ph] of hits.sort((x, y) => y[0] - x[0]))
                out = out.slice(0, a) + `[secret:${this.fingerprint(ph)}]` + out.slice(b);
        }
        out = out.replace(ENV_SECRET_LINE, (m, k, v) => (v.startsWith('[secret:') || v.startsWith('[private-key:') ? m : m.replace(v, `[secret:${this.fingerprint(v)}]`)));
        if (sess && sess.secrets && sess.secrets.length) {
            const hit = this.knownMatcher(sess);
            out = out.replace(TOKEN, (tok) => {
                if (hit(tok))
                    return `[secret:${this.fingerprint(tok)}]`;
                if (!/[=:]/.test(tok))
                    return tok;
                return tok.split(/([=:])/).map((p) => (hit(p) ? `[secret:${this.fingerprint(p)}]` : p)).join('');
            });
        }
        return out;
    }
    // Deep copy of any JSON value with every string scrubbed.
    /** @param {any} value @param {string} [sessionId] @returns {any} */
    scrub(value, sessionId) {
        const sess = sessionId ? this.state.sessions[sessionId] : null;
        /** @param {any} v @returns {any} */
        const walk = (v) => {
            if (typeof v === 'string')
                return this.scrubText(v, sess);
            if (Array.isArray(v))
                return v.map(walk);
            if (v && typeof v === 'object')
                return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
            return v;
        };
        return walk(value);
    }
    // Hosts the human named in their own prompt count as intended destinations
    // for this session (least privilege that follows the user's request, after
    // Progent, arXiv:2504.11703). Pasted text and turns Claude Code starts on its
    // own are not the human's intent, so they never widen the list.
    /** @param {import('./types').HookEvent} ev @returns {string[]} */
    userPrompt(ev) {
        const sess = this.session(ev.session_id);
        let text = String(ev.prompt || '');
        if (/<(task-notification|system-reminder|teammate-message)\b/.test(text))
            return [];
        text = text.replace(/<pasted_content\b[^>]*>[\s\S]*?<\/pasted_content\b[^>]*>/g, ' ');
        const found = [];
        const re = /\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[\/:\s'"`)>,]|$)/gi;
        let m;
        while ((m = re.exec(text))) {
            const host = m[1].toLowerCase();
            if (/\.(js|ts|json|md|py|sh|txt|env|yml|yaml|toml|lock|log|html|css)$/.test(host))
                continue; // file names
            found.push(host);
        }
        sess.intentHosts = [...new Set([...(sess.intentHosts || []), ...found])].slice(-200);
        return found;
    }
    /** @param {string | undefined} tool @returns {string | null} */
    mcpServer(tool) {
        const m = /^mcp__(.+?)__/.exec(tool || '');
        return m ? m[1] : null;
    }
    /**
     * Is this tool call an attempt to send data out of the machine?
     * @param {string} tool
     * @param {Record<string, any>} input
     * @param {import('./types').SessionState} [sess]
     * @returns {import('./types').Egress}
     */
    egress(tool, input, sess) {
        const allow = this.cfg.allowHosts;
        const sessIntent = (sess && sess.intentHosts) || [];
        if (tool === 'Bash' || tool === 'PowerShell') {
            const full = (input && input.command) || '';
            // Heredoc text written to a file is data, not a command, unless the
            // heredoc is fed to an interpreter (bash <<EOF … EOF runs it).
            const raw = HEREDOC_CODE.test(full) ? full : stripHeredocs(full);
            const cmd = normalizeCmd(raw);
            /** @param {RegExp} re */
            const both = (re) => re.test(raw) || re.test(cmd);
            const hosts = [...new Set([...hostsIn(raw), ...hostsIn(cmd)])];
            const external = hosts.filter((h) => !allowed(h, allow));
            const intended = external.length > 0 && external.every((h) => allowed(h, sessIntent));
            for (const [re, why] of WEB3)
                if (both(re))
                    return { yes: true, intended, why, web3: true };
            for (const [re, why] of PUBLISH)
                if (both(re))
                    return { yes: true, intended, why };
            const net = both(NET_TOOL) || both(NET_CODE) || both(DEV_TCP);
            // a known downloader with a URL in it, or an unresolvable command word next to a URL ($C https://…)
            const fetchy = hosts.length && (both(FETCH_CMD) || /(?:^|[;&|(]\s*)(?:\$\{?\w+\}?|\$\(|`)/.test(raw.trim()));
            if (net || fetchy) {
                if (hosts.length && !external.length) {
                    const carries = urlCarriesData(raw) || urlCarriesData(cmd);
                    return carries ? { yes: true, why: carries } : { yes: false, why: 'allowlisted hosts only' };
                }
                return { yes: true, intended, why: external.length ? `network call to ${external.join(', ')}` : 'network call to an unparsed destination' };
            }
            // No network tool in sight, but the command runs code that could do anything.
            const run = this.runsCode(full, cmd, sess);
            if (run)
                return { yes: true, opaque: !run.net, why: run.why };
            return { yes: false };
        }
        if (tool === 'WebFetch') {
            let u;
            try {
                u = new URL(input.url);
            }
            catch {
                return { yes: false };
            }
            if (allowed(u.hostname, allow)) {
                const carries = urlCarriesData(input.url);
                return carries ? { yes: true, why: carries } : { yes: false };
            }
            const longSegment = u.pathname.split('/').some((p) => p.length > 40);
            if (u.search.length > 1 || longSegment) {
                return { yes: true, intended: allowed(u.hostname.toLowerCase(), sessIntent), why: `URL to ${u.hostname} carries data in its path or query` };
            }
            return { yes: false };
        }
        const server = this.mcpServer(tool);
        if (server && WEB3_MCP_SERVER.test(server) && WEB3_MCP_TOOL.test(tool.slice(tool.lastIndexOf('__') + 2))) {
            return { yes: true, why: `MCP tool ${tool} signs or sends a transaction`, web3: true };
        }
        if (server && MCP_OUTBOUND.test(tool.slice(tool.lastIndexOf('__') + 2))) {
            return { yes: true, why: `MCP tool ${tool} sends data out` };
        }
        return { yes: false };
    }
    // Does this command run code whose behavior the policy cannot see? Scripts
    // the agent wrote or downloaded this session, inline interpreter code, and
    // (once the agent has written files) test runners and package scripts.
    // Writing a script first must not be a way around the network rules.
    /** @param {string} raw @param {string} cmd @param {import('./types').SessionState} [sess] @returns {{ net: boolean, why: string } | null} */
    runsCode(raw, cmd, sess) {
        const written = (sess && sess.written) || [];
        const netFiles = (sess && sess.netFiles) || [];
        /** @param {string} f */
        const base = (f) => baseName(f.replace(/^~\//, ''), f);
        /** @param {string} arg @param {string[]} list */
        const match = (arg, list) => list.find((w) => w === arg || base(w) === base(arg) || w.endsWith('/' + arg.replace(/^\.\//, '')));
        const targets = [];
        const sk = normalizeCmd(shellSkeleton(raw));
        for (const re of [INTERP_FILE, DIRECT_EXEC]) {
            re.lastIndex = 0;
            let m;
            while ((m = re.exec(sk)))
                if (!/^-|^""$/.test(m[1]))
                    targets.push(m[1]);
        }
        for (const t of targets) {
            const hit = match(t, written);
            if (!hit && this.readFile) {
                let body = null;
                try {
                    body = this.readFile(t, sess && sess.cwd);
                }
                catch { /* unreadable: treated as before */ }
                if (body && NET_SOURCE.test(body))
                    return { net: true, why: `runs ${t}, an existing script with network code` };
            }
            if (hit)
                return { net: !!match(t, netFiles), why: match(t, netFiles) ? `runs ${t}, which the agent wrote this session with network code` : `runs ${t}, which the agent wrote or downloaded this session` };
        }
        if (INLINE_CODE.test(sk) || INLINE_CODE.test(normalizeCmd(sk)))
            return { net: false, why: 'runs inline or piped code' };
        if (HEREDOC_CODE.test(raw))
            return { net: false, why: 'runs a script passed inline (heredoc)' };
        // git runs hooks the agent may have planted in .git/hooks
        if (written.some((w) => /(^|\/)\.git\/hooks\/|(^|\/)\.husky\//.test(w)) && /\bgit\s+(?:commit|merge|rebase|checkout|switch|pull|push|am)\b/.test(cmd))
            return { net: false, why: 'git runs a hook the agent wrote this session' };
        // Test runners and package scripts run whatever the agent edited; they
        // count once it wrote code that does networking or runs commands itself.
        if (netFiles.length && (SCRIPT_RUNNER.test(raw) || SCRIPT_RUNNER.test(cmd)))
            return { net: false, why: `runs project scripts after the agent wrote ${base(netFiles[netFiles.length - 1])}, which has network or shell code` };
        return null;
    }
    // Is this target the evidence store? Normalized, with globs expanded.
    /** @param {string} text */
    touchesEvidence(text) {
        const n = normalizeCmd(text);
        const names = ['.blackbox', ...this.protect.map((p) => baseName(p))];
        if (/\.blackbox(\/|\b)/.test(text) || /\.blackbox(\/|\b)/.test(n))
            return true;
        if (this.protect.some((p) => text.includes(p) || n.includes(p)))
            return true;
        return globsIn(n).some((re) => names.some((name) => re.test(name)));
    }
    /**
     * PreToolUse: decide. Null means no opinion.
     * @param {import('./types').HookEvent} ev
     * @returns {import('./types').PolicyDecision | null}
     */
    preToolUse(ev) {
        const tool = ev.tool_name || '';
        const input = ev.tool_input || {};
        const text = inputText(input);
        const sess = this.session(ev.session_id);
        if (ev.cwd)
            sess.cwd = ev.cwd;
        // 1. Self-protection: the agent must not read or alter its own evidence.
        if (this.touchesEvidence(text)) {
            sess.denied = { rule: 'self-protection', at: new Date().toISOString() };
            return { decision: 'deny', rule: 'self-protection', reason: 'Access to the agent-blackbox evidence store (~/.blackbox) is blocked for the agent.' };
        }
        if ((AGENT_HOOK_CONFIG.test(text) || AGENT_HOOK_CONFIG.test(normalizeCmd(text)) || /managed-settings\.json|\.claude\/plugins\//.test(normalizeCmd(text))) && /^(Edit|Write|MultiEdit|Bash|PowerShell|NotebookEdit)$/.test(tool)) {
            return { decision: 'ask', rule: 'hook-tamper', reason: 'The agent wants to change the settings where the agent-blackbox hooks live.' };
        }
        // 1c. A session that read untrusted content must not plant text in files later sessions trust.
        if (sess.untrusted && this.cfg.memoryWrites !== 'off') {
            const doc = writeTargets(tool, input).find(isMemoryDoc);
            if (doc) {
                return { decision: this.softDecision(this.cfg.memoryWrites), rule: 'memory-write', reason: `This session read untrusted content (${sess.untrusted.why}) and now wants to change ${doc}, a file later sessions will trust as instructions.` };
            }
        }
        const out = this.egress(tool, input, sess);
        const secretOut = this.containsKnownSecret(sess, stringsOf(input).join('\n'));
        const readsSensitive = SENSITIVE_PATH.some((re) => re.test(text));
        /** @param {string} rule @param {string} reason @param {{ secret?: string }} [extra] @returns {import('./types').PolicyDecision} */
        const deny = (rule, reason, extra = {}) => {
            // A denial teaches an attacker what is protected. Record it, and make
            // every later outbound call in this session ask (counterfactual edge,
            // after "Causality Laundering", arXiv:2604.04035).
            sess.denied = { rule, at: new Date().toISOString() };
            return { decision: 'deny', rule, reason, ...extra };
        };
        // 2. A secret value seen earlier in this session is about to leave.
        //    Denied even toward a host the user named: secrets are never sent by the agent.
        if (secretOut && out.opaque) {
            return { decision: 'ask', rule: 'secret-to-code', reason: `A secret this session read earlier (fingerprint ${secretOut}) is passed to code the policy cannot inspect (${out.why}).`, secret: secretOut };
        }
        if (secretOut && (out.yes || tool === 'WebSearch' || tool === 'WebFetch' || this.mcpServer(tool))) {
            return deny('secret-egress', `A secret this session read earlier (fingerprint ${secretOut}) appears in an outbound ${tool} call (${out.why || tool}).`, { secret: secretOut });
        }
        // 3. One command that both reads a sensitive file and sends data out.
        if (out.yes && readsSensitive && out.opaque) {
            return { decision: 'ask', rule: 'sensitive-to-code', reason: `This command reads a sensitive file and runs code the policy cannot inspect (${out.why}).` };
        }
        if (out.yes && readsSensitive) {
            return deny('sensitive-egress', `This command reads a sensitive file and sends data out (${out.why}).`);
        }
        if (out.yes && out.intended) {
            return { decision: 'note', rule: 'egress-intended', reason: `${out.why} (destination named by the user)` };
        }
        // 4. The lethal trifecta.
        if (out.yes && sess.private && sess.untrusted) {
            const mode = this.cfg.mode;
            const reason = `Lethal trifecta: this session read private data (${sess.private.why}) and untrusted content (${sess.untrusted.why}), and now wants to send data out (${out.why}).`;
            if (mode === 'monitor' || (out.opaque && this.cfg.opaqueCode === 'alert'))
                return { decision: 'alert', rule: 'lethal-trifecta', reason };
            if (mode === 'deny' && !out.opaque)
                return deny('lethal-trifecta', reason);
            return { decision: 'ask', rule: 'lethal-trifecta', reason };
        }
        // 4b. Signing or broadcasting a transaction moves value and cannot be undone.
        if (out.web3 && this.cfg.web3 !== 'off') {
            const reason = `${out.why}. Transactions cannot be undone.`;
            return { decision: this.softDecision(this.cfg.web3), rule: 'web3-transaction', reason };
        }
        // 5. After a denial, any outbound call needs the human.
        if (out.yes && sess.denied && this.cfg.mode !== 'monitor') {
            return { decision: 'ask', rule: 'post-denial', reason: `An earlier call in this session was blocked (${sess.denied.rule}); this one sends data out (${out.why}).` };
        }
        if (out.yes)
            return { decision: 'note', rule: out.opaque ? 'runs-code' : 'egress', reason: out.why || '' };
        return null;
    }
    // PostToolUse: update the session's taint. Returns a list of new taints.
    /** @param {import('./types').HookEvent} ev */
    postToolUse(ev) {
        const tool = ev.tool_name || '';
        const input = ev.tool_input || {};
        const sess = this.session(ev.session_id);
        if (ev.cwd)
            sess.cwd = ev.cwd;
        const taints = [];
        const respText = stringsOf(ev.tool_response).join('\n');
        const inText = inputText(input);
        const server = this.mcpServer(tool);
        // untrusted content entered the context
        let untrusted = null;
        if (tool === 'WebFetch')
            untrusted = `WebFetch ${input.url || ''}`.trim();
        else if (tool === 'WebSearch')
            untrusted = `WebSearch "${(input.query || '').slice(0, 60)}"`;
        else if (server && !this.cfg.trustedMcpServers.includes(server))
            untrusted = `MCP ${tool}`;
        else if ((tool === 'Bash' || tool === 'PowerShell') && (NET_TOOL.test(input.command || '') || NET_CODE.test(input.command || ''))) {
            untrusted = `network output of: ${(input.command || '').slice(0, 80)}`;
        }
        // files the agent reads can carry planted instructions (a README, an issue
        // export, a dependency); only text that reads like an attack taints the session
        if (!untrusted && (tool === 'Read' || tool === 'Grep' || ((tool === 'Bash' || tool === 'PowerShell') && FILE_READER_CMD.test(input.command || '')))) {
            const why = injectionIn(respText);
            if (why)
                untrusted = `${tool} ${(input.file_path || input.path || input.pattern || input.command || '').slice(0, 60)}: ${why}`;
        }
        if (untrusted && !sess.untrusted) {
            sess.untrusted = { why: untrusted, at: new Date().toISOString(), tool_use_id: ev.tool_use_id };
            taints.push({ flag: 'untrusted', why: untrusted });
        }
        // private data entered the context
        const secrets = this.extractSecrets(respText);
        const pathHit = SENSITIVE_PATH.find((re) => re.test(inText));
        let priv = null;
        const credCmd = (tool === 'Bash' || tool === 'PowerShell') && CREDENTIAL_CMD.test(input.command || '');
        if (pathHit)
            priv = `${tool} ${(input.file_path || input.command || input.path || '').slice(0, 80)}`;
        else if (credCmd)
            priv = `credential output of: ${(input.command || '').slice(0, 80)}`;
        else if (secrets.length || PRIVATE_KEY_BLOCK.test(respText) || KEYSTORE_JSON.test(respText))
            priv = `secret-looking value in ${tool} output`;
        else if (server && this.cfg.privateMcpServers.includes(server))
            priv = `MCP ${tool}`;
        if (priv && !sess.private) {
            sess.private = { why: priv, at: new Date().toISOString(), tool_use_id: ev.tool_use_id };
            taints.push({ flag: 'private', why: priv });
        }
        // remember what the agent wrote, so running it later is not a blind spot
        /** @type {string[]} */
        const wrote = [];
        if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool))
            wrote.push(input.file_path || input.notebook_path || '');
        if (tool === 'Bash' || tool === 'PowerShell')
            wrote.push(...writtenBy(input.command || ''));
        const body = [input.content, input.new_string, input.new_source, ...((input.edits || []).map((/** @type {{ new_string?: string }} */ e) => e.new_string)), tool === 'Bash' ? input.command : null].filter((x) => typeof x === 'string').join('\n');
        // a session that had read untrusted content wrote text a later session will trust
        if (sess.untrusted) {
            for (const f of writeTargets(tool, input).filter(isMemoryDoc)) {
                const docs = (this.state.docs ||= {});
                docs[docKey(f, sess.cwd)] = { session: ev.session_id, at: new Date().toISOString(), why: sess.untrusted.why };
                const keys = Object.keys(docs);
                if (keys.length > 500)
                    delete docs[keys[0]];
            }
        }
        // this session read such a text
        if (!sess.untrusted) {
            const why = this.poisonedDocRead(tool, input, sess);
            if (why) {
                sess.untrusted = { why, at: new Date().toISOString(), tool_use_id: ev.tool_use_id };
                taints.push({ flag: 'untrusted', why });
            }
        }
        for (const f of wrote.filter(Boolean)) {
            sess.written = pushCapped(sess.written, f);
            if (NET_SOURCE.test(body) || DYNAMIC_SOURCE.test(body) || /\b(?:curl|wget)\b[^;&|]*\s-(?:o|O)\b/.test(input.command || ''))
                sess.netFiles = pushCapped(sess.netFiles, f);
        }
        if (secrets.length) {
            const set = new Set(sess.secrets);
            for (const s of secrets)
                set.add(this.mac(s));
            sess.secrets = [...set].slice(-500);
            if (sess.secretLens)
                sess.secretLens = [...new Set([...sess.secretLens, ...secrets.map((x) => x.length)])];
            const lens = new Set(sess.phraseLens || []);
            for (const s of secrets)
                if (s.includes(' '))
                    lens.add(s.split(' ').length);
            sess.phraseLens = [...lens];
        }
        return { taints, secretsSeen: secrets.length };
    }
}
// What the agent itself is told when a call is denied: no rule name, no
// fingerprint, no hint about what was detected (see Causality Laundering).
const AGENT_DENY_MESSAGE = 'Blocked by the local security policy. Do not retry or work around this; tell the user what you were trying to do and let them decide.';
// Mask secret-looking values so the human-readable ledger never holds them.
// Full payloads still live in the blob store (mode 0600) as the evidence.
/** @param {unknown} text @returns {string} */
function redact(text) {
    let out = String(text == null ? '' : text);
    for (const re of SECRET_PATTERNS)
        out = out.replace(re, (m) => m.slice(0, 6) + '…[redacted]');
    for (const { re } of CONTEXT_SECRETS)
        out = out.replace(re, (m, v) => m.replace(v, '[redacted]'));
    out = out.replace(ENV_SECRET_LINE, (m, k, v) => m.replace(v, '[redacted]'));
    out = out.replace(/\b([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|MNEMONIC|SEED|CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*["'`]?)([^\s"'`#]{6,})/g, '$1[redacted]');
    // (?<!\[) keeps our own [secret:<fingerprint>] markers: the fingerprint is how a ledger line is tied to an event
    out = out.replace(/(?<!\[)((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*["']?)([^\s"'&]{4,})/gi, '$1[redacted]');
    return out;
}
module.exports = { Policy, injectionIn, isMemoryDoc, docKey, inputText, textOf, stringsOf, hostsIn, normalizeCmd, writtenBy, redact, AGENT_DENY_MESSAGE };
