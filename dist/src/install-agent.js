"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.installAgent = installAgent;
exports.uninstallAgent = uninstallAgent;
// Wire agent-blackbox into an agent other than Claude Code (`blackbox install --agent <id>`).
// Only hooks: Claude Code's OpenTelemetry stream has no counterpart there.
const fs = require("fs");
const path = require("path");
const paths_1 = require("./paths");
const adapters_1 = require("./adapters");
const shared_1 = require("./adapters/shared");
const install_1 = require("./install");
function readJsonFile(file) {
    if (!fs.existsSync(file))
        return {};
    const text = fs.readFileSync(file, 'utf8');
    if (!text.trim())
        return {};
    return JSON.parse(text); // throws on invalid JSON: never overwrite a file we cannot parse
}
function hooksFileOf(id) {
    const a = (0, adapters_1.getAdapter)(id);
    if (!a.hooksFile)
        throw new Error(`${a.name}: nothing to install (no hook file support yet)`);
    return { a, hf: a.hooksFile };
}
function installAgent(id, { mode, log = console.log } = {}) {
    const { a, hf } = hooksFileOf(id);
    (0, paths_1.ensureDirs)();
    const file = hf.file();
    const json = readJsonFile(file);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (fs.existsSync(file)) {
        const backup = `${file}.blackbox-backup-${Date.now()}`;
        fs.copyFileSync(file, backup);
        log(`  backup  ${backup}`);
    }
    hf.remove(json);
    const events = hf.add(json, `"${(0, install_1.nodePath)()}" "${(0, install_1.hookScriptPath)()}" --agent ${id} ${shared_1.MARKER}`);
    fs.writeFileSync(file, JSON.stringify(json, null, 2) + '\n');
    const cfg = (0, paths_1.loadConfig)();
    if (mode)
        cfg.mode = mode;
    cfg.installedAgents = { ...cfg.installedAgents, [id]: { file, at: new Date().toISOString() } };
    (0, paths_1.saveConfig)(cfg);
    log(`  hooks   ${events.length} events → ${file}`);
    if (!a.capabilities.preTool)
        log(`  note    ${a.name} cannot be blocked before a tool runs: its sessions are recorded, not enforced`);
    else if (!a.capabilities.ask)
        log(`  note    ${a.name} cannot ask you: where the policy would ask, the call is blocked (config askFallback: "allow" lets it run with a notice)`);
    if (hf.note)
        log(`  note    ${hf.note}`);
    return { file, events };
}
function uninstallAgent(id, { log = console.log } = {}) {
    const { hf } = hooksFileOf(id);
    const file = hf.file();
    if (fs.existsSync(file)) {
        const json = readJsonFile(file);
        hf.remove(json);
        fs.writeFileSync(file, JSON.stringify(json, null, 2) + '\n');
    }
    const cfg = (0, paths_1.loadConfig)();
    if (cfg.installedAgents) {
        delete cfg.installedAgents[id];
        (0, paths_1.saveConfig)(cfg);
    }
    log(`  removed agent-blackbox hooks from ${file}`);
}
