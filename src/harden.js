'use strict';
// `blackbox harden`: run the recorder as a dedicated OS user, so an agent
// running as the human can write evidence but not read, rewrite or erase it.
//
// This module only builds a shell script. Nothing is changed until a person
// reads that script and runs it as root. It is plain POSIX sh so it can be
// reviewed line by line.
const os = require('os');
const path = require('path');
const { defined, stablePath } = require('./util');

/**
 * @typedef {{ platform?: string, user?: string, data?: string, code?: string, node?: string, port?: number, human?: string, humanHome?: string, pkgRoot?: string }} HardenOptions
 * @typedef {Required<HardenOptions>} Resolved
 */

/** Single-quote a value for sh. @param {string} s */
const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
/** @param {string} s */
const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const SERVICE = 'agent-blackbox';
const LABEL = 'dev.agent-blackbox.recorder';

/** @param {string} [platform] */
function defaults(platform = process.platform) {
  const mac = platform === 'darwin';
  return {
    platform,
    user: mac ? '_blackbox' : 'blackbox',
    data: mac ? '/Library/Application Support/agent-blackbox' : '/var/lib/agent-blackbox',
    code: '/usr/local/lib/agent-blackbox',
  };
}

/** @param {Pick<Resolved, 'platform' | 'user'>} o */
function userCreation({ platform, user }) {
  if (platform === 'darwin') {
    return `if ! dscl . -read /Users/${user} >/dev/null 2>&1; then
  ID=$(dscl . -list /Users UniqueID | awk '$2>=300 && $2<400 {used[$2]=1} END {for (i=300;i<400;i++) if (!used[i]) {print i; exit}}')
  [ -n "$ID" ] || { echo "no free id between 300 and 399" >&2; exit 1; }
  dscl . -create /Groups/${user}
  dscl . -create /Groups/${user} PrimaryGroupID "$ID"
  dscl . -create /Users/${user}
  dscl . -create /Users/${user} UniqueID "$ID"
  dscl . -create /Users/${user} PrimaryGroupID "$ID"
  dscl . -create /Users/${user} UserShell /usr/bin/false
  dscl . -create /Users/${user} NFSHomeDirectory /var/empty
  dscl . -create /Users/${user} IsHidden 1
  echo "created user ${user} (id $ID)"
fi
GROUP=${user}`;
  }
  return `if ! id -u ${user} >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ${user}
  echo "created user ${user}"
fi
GROUP=${user}`;
}

/** @param {Resolved} o */
function serviceInstall(o) {
  const exec = `${o.node} ${o.code}/dist/bin/blackbox.js daemon`;
  if (o.platform === 'darwin') {
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>UserName</key><string>${xml(o.user)}</string>
  <key>ProgramArguments</key><array><string>${xml(o.node)}</string><string>${xml(o.code)}/dist/bin/blackbox.js</string><string>daemon</string></array>
  <key>EnvironmentVariables</key><dict><key>BLACKBOX_HOME</key><string>${xml(o.data)}</string><key>BLACKBOX_PORT</key><string>${o.port}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${xml(o.data)}/daemon.log</string>
  <key>StandardErrorPath</key><string>${xml(o.data)}/daemon.log</string>
</dict></plist>`;
    return `PLIST=/Library/LaunchDaemons/${LABEL}.plist
launchctl bootout system/${LABEL} 2>/dev/null || true
cat > "$PLIST" <<'PLIST_EOF'
${plist}
PLIST_EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootstrap system "$PLIST"`;
  }
  const unit = `[Unit]
Description=agent-blackbox recorder
After=network.target

[Service]
User=${o.user}
Environment=BLACKBOX_HOME=${o.data}
Environment=BLACKBOX_PORT=${o.port}
ExecStart=${exec}
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${o.data}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target`;
  return `cat > /etc/systemd/system/${SERVICE}.service <<'UNIT_EOF'
${unit}
UNIT_EOF
systemctl daemon-reload
systemctl enable ${SERVICE}.service
systemctl restart ${SERVICE}.service`;
}

// The script that moves the recorder to its own user.
/** @param {HardenOptions} [opts] */
function hardenScript(opts = {}) {
  const d = defaults(opts.platform);
  /** @type {Resolved} */
  const o = {
    ...d,
    ...defined(opts),
    node: opts.node || stablePath(process.execPath),
    port: opts.port || 7071,
    human: opts.human || os.userInfo().username,
    humanHome: opts.humanHome || path.join(os.homedir(), '.blackbox'),
    pkgRoot: opts.pkgRoot || path.resolve(__dirname, '..'),
  };
  if (!['darwin', 'linux'].includes(o.platform)) throw new Error(`harden supports macOS (launchd) and Linux (systemd), not ${o.platform}`);
  for (const [k, v] of Object.entries({ user: o.user, human: o.human })) {
    if (!/^[A-Za-z_][A-Za-z0-9_-]{0,31}$/.test(v)) throw new Error(`invalid ${k} name: ${v}`);
  }
  if (o.human === o.user) throw new Error('the recorder user must differ from the human user');
  // A node inside a home folder (nvm, fnm, asdf) cannot be run by the recorder user:
  // stop before anything is created. Overridable for a home folder that is world-readable.
  const homeNode = /^\/(home|Users)\//.test(o.node)
    ? `if [ "\${BLACKBOX_ALLOW_HOME_NODE:-}" != 1 ]; then
  echo "node lives under a home folder (${o.node}), which the recorder user ${o.user} cannot enter." >&2
  echo "Install node system-wide (macOS: brew install node), then generate the script again with that node:" >&2
  echo "  /opt/homebrew/bin/node bin/blackbox.js harden --out harden.sh   (or pass --node PATH)" >&2
  exit 1
fi
`
    : '';
  // After the user exists: it must really be able to run node, or the service would die at start.
  const runCheck = `# the recorder user must be able to run node (checked now, not discovered when the service fails)
if command -v sudo >/dev/null 2>&1; then AS="sudo -n -u ${o.user}"; else AS="runuser -u ${o.user} --"; fi
$AS "$NODE" -e 0 >/dev/null 2>&1 || {
  echo "the user ${o.user} cannot run $NODE. Use a system-wide node (macOS: brew install node) and generate the script again." >&2
  exit 1
}
`;

  return `#!/bin/sh
# agent-blackbox harden: run the recorder as its own OS user.
#
# Read this before running it. It needs root and does exactly this:
#   1. creates the user ${o.user} (no login, no home)
#   2. copies agent-blackbox to ${o.code}, owned by root, so the agent cannot edit the recorder's code
#   3. creates ${o.data}, owned by ${o.user}, mode 700: ledger, keys, config and the admin token live there
#   4. gives the recorder the ingest token ${o.human} already has, so hooks keep working
#   5. makes ${o.human}'s hooks forward to the service instead of starting their own recorder
#   6. installs and starts the ${o.platform === 'darwin' ? 'launchd daemon' : 'systemd unit'}
# Undo: blackbox harden --undo
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo sh <this file>" >&2; exit 1; }

NODE=${q(o.node)}
PKG=${q(o.pkgRoot)}
CODE=${q(o.code)}
DATA=${q(o.data)}
HUMAN=${q(o.human)}
HUMAN_HOME=${q(o.humanHome)}

${homeNode}[ -d "$PKG/dist/bin" ] || { echo "no compiled code in $PKG/dist: run 'npm run build' there, or generate this script from a release" >&2; exit 1; }
[ -f "$HUMAN_HOME/keys/token" ] || { echo "no ingest token in $HUMAN_HOME/keys: run 'blackbox install' as ${o.human} first" >&2; exit 1; }

${userCreation(o)}

${runCheck}
# 1. code the agent cannot change
rm -rf "$CODE"
mkdir -p "$CODE"
for f in dist package.json; do cp -R "$PKG/$f" "$CODE/"; done
chown -R root:$(id -gn root) "$CODE"
chmod -R go-w "$CODE"

# 2. data the agent cannot read
mkdir -p "$DATA/keys"
chown -R ${o.user}:$GROUP "$DATA"
chmod 700 "$DATA" "$DATA/keys"

# 3. same ingest token as the human's hooks; the admin token is created here and never leaves
cp "$HUMAN_HOME/keys/token" "$DATA/keys/token"
chown ${o.user}:$GROUP "$DATA/keys/token"
chmod 600 "$DATA/keys/token"

# 4. policy settings move with the recorder, so the agent cannot switch the mode to monitor
if [ -f "$HUMAN_HOME/config.json" ] && [ ! -f "$DATA/config.json" ]; then
  "$NODE" -e 'const fs=require("fs");const c=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));delete c.remoteDaemon;c.hardened=true;fs.writeFileSync(process.argv[2],JSON.stringify(c,null,2)+"\\n")' "$HUMAN_HOME/config.json" "$DATA/config.json"
  chown ${o.user}:$GROUP "$DATA/config.json"
  chmod 600 "$DATA/config.json"
fi

# 5. the human's hooks now forward to the service and never start a recorder of their own
"$NODE" -e 'const fs=require("fs");const f=process.argv[1];let c={};try{c=JSON.parse(fs.readFileSync(f,"utf8"))}catch{}c.remoteDaemon=true;c.recorderHome=process.argv[2];c.recorderUser=process.argv[3];c.recorderCode=process.argv[4];fs.writeFileSync(f,JSON.stringify(c,null,2)+"\\n")' "$HUMAN_HOME/config.json" "$DATA" ${o.user} "$CODE"
chown "$HUMAN" "$HUMAN_HOME/config.json"

# the human's own recorder must not keep running next to the service
if [ -f "$HUMAN_HOME/daemon.pid" ]; then kill "$(cat "$HUMAN_HOME/daemon.pid")" 2>/dev/null || true; fi

# 6. the service
${serviceInstall(o)}

echo
echo "recorder now runs as ${o.user}. Check it as ${o.human}:"
echo "  blackbox status        (shows the recorder's user id, which must not be yours)"
echo "  blackbox harden --check"
echo "Reading, verifying and purging now ask for sudo: the agent cannot type your password."
echo "Now run 'blackbox install' as ${o.human}: the hooks will point at $CODE/dist/bin/hook.js, which the agent cannot edit."
echo "The ledger from before stays in $HUMAN_HOME and is readable by the agent: anchor it, then purge what you do not need."
`;
}

/** @param {HardenOptions} [opts] */
function undoScript(opts = {}) {
  const d = defaults(opts.platform);
  const o = { ...d, ...defined(opts), humanHome: opts.humanHome || path.join(os.homedir(), '.blackbox') };
  if (!['darwin', 'linux'].includes(o.platform)) throw new Error(`harden supports macOS (launchd) and Linux (systemd), not ${o.platform}`);
  const stop = o.platform === 'darwin'
    ? `launchctl bootout system/${LABEL} 2>/dev/null || true\nrm -f /Library/LaunchDaemons/${LABEL}.plist`
    : `systemctl disable --now ${SERVICE}.service 2>/dev/null || true\nrm -f /etc/systemd/system/${SERVICE}.service\nsystemctl daemon-reload`;
  return `#!/bin/sh
# agent-blackbox harden --undo: stop the service and hand the recorder back to your own user.
# The service's data (${o.data}) is kept: copy it back by hand if you want the history.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo sh <this file>" >&2; exit 1; }
${stop}
rm -rf ${q(o.code)}
HUMAN_CONFIG=${q(path.join(o.humanHome, 'config.json'))}
if [ -f "$HUMAN_CONFIG" ]; then
  ${q(opts.node || process.execPath)} -e 'const fs=require("fs");const f=process.argv[1];const c=JSON.parse(fs.readFileSync(f,"utf8"));delete c.remoteDaemon;delete c.recorderHome;delete c.recorderUser;delete c.recorderCode;fs.writeFileSync(f,JSON.stringify(c,null,2)+"\\n")' "$HUMAN_CONFIG"
fi
echo "service removed. The user ${o.user} and ${o.data} are kept; remove them by hand when you no longer need the history."
`;
}

// Is the recorder running as someone other than the human? health is the
// body of GET /health.
/**
 * @param {{ uid?: number | null } | null} health body of GET /health
 * @param {{ uid?: number | null, cfg?: Partial<import('./types').Config>, legacyKeys?: string[], hookScripts?: string[] }} [opts]
 *   legacyKeys: key files still in the human's own folder; hookScripts: where the installed hooks run from
 */
function checkHardened(health, { uid = typeof process.getuid === 'function' ? process.getuid() : null, cfg = {}, legacyKeys = [], hookScripts = [] } = {}) {
  /** @type {string[]} */
  const lines = [];
  let ok = true;
  /** @param {string} m */
  const bad = (m) => { ok = false; lines.push(`✘ ${m}`); };
  if (!health) { bad('the recorder is not running'); return { ok, lines }; }
  if (health.uid == null || uid == null) lines.push('· cannot compare user ids on this platform');
  else if (health.uid === uid) bad(`the recorder runs as your own user (uid ${uid}): the agent can read and rewrite its evidence. Run: blackbox harden`);
  else lines.push(`✔ the recorder runs as uid ${health.uid}, not yours (${uid})`);
  if (!cfg.remoteDaemon) bad('hooks are not set to forward to a separate recorder (remoteDaemon is off)');
  else lines.push('✔ hooks forward to the service and never start a recorder of their own');
  // warnings: not a failure of the setup, but evidence or code the agent can still reach
  if (legacyKeys.length) lines.push(`! your own recorder folder still holds ${legacyKeys.join(', ')} from before harden: an agent running as you can read them. Run blackbox anchor, then move that folder away.`);
  const outside = cfg.recorderCode ? hookScripts.find((s) => !s.startsWith(cfg.recorderCode + '/')) : undefined;
  if (outside) lines.push(`! the hooks still run from ${outside}, which an agent running as you can edit. Run: blackbox install`);
  return { ok, lines };
}

module.exports = { hardenScript, undoScript, checkHardened, defaults };
