// Wire agent-blackbox into an agent other than Claude Code (`blackbox install --agent <id>`).
// Only hooks: Claude Code's OpenTelemetry stream has no counterpart there.
import * as fs from 'fs';
import * as path from 'path';
import { ensureDirs, loadConfig, saveConfig } from './paths';
import { getAdapter } from './adapters';
import { MARKER } from './adapters/shared';
import { nodePath, hookScriptPath } from './install';
import type { Adapter, AgentHooksFile, Mode } from './types';

function readJsonFile(file: string): Record<string, any> {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, 'utf8');
  if (!text.trim()) return {};
  return JSON.parse(text); // throws on invalid JSON: never overwrite a file we cannot parse
}

function hooksFileOf(id: string): { a: Adapter; hf: AgentHooksFile } {
  const a = getAdapter(id);
  if (!a.hooksFile) throw new Error(`${a.name}: nothing to install (no hook file support yet)`);
  return { a, hf: a.hooksFile };
}

export function installAgent(id: string, { mode, log = console.log }: { mode?: Mode; log?: (msg: string) => void } = {}): { file: string; events: string[] } {
  const { a, hf } = hooksFileOf(id);
  ensureDirs();
  const file = hf.file();
  const json = readJsonFile(file);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file)) {
    const backup = `${file}.blackbox-backup-${Date.now()}`;
    fs.copyFileSync(file, backup);
    log(`  backup  ${backup}`);
  }
  hf.remove(json);
  const events = hf.add(json, `"${nodePath()}" "${hookScriptPath()}" --agent ${id} ${MARKER}`);
  fs.writeFileSync(file, JSON.stringify(json, null, 2) + '\n');
  const cfg = loadConfig();
  if (mode) cfg.mode = mode;
  cfg.installedAgents = { ...cfg.installedAgents, [id]: { file, at: new Date().toISOString() } };
  saveConfig(cfg);
  log(`  hooks   ${events.length} events → ${file}`);
  if (!a.capabilities.preTool) log(`  note    ${a.name} cannot be blocked before a tool runs: its sessions are recorded, not enforced`);
  else if (!a.capabilities.ask) log(`  note    ${a.name} cannot ask you: where the policy would ask, the call is blocked (config askFallback: "allow" lets it run with a notice)`);
  if (hf.note) log(`  note    ${hf.note}`);
  return { file, events };
}

export function uninstallAgent(id: string, { log = console.log }: { log?: (msg: string) => void } = {}): void {
  const { hf } = hooksFileOf(id);
  const file = hf.file();
  if (fs.existsSync(file)) {
    const json = readJsonFile(file);
    hf.remove(json);
    fs.writeFileSync(file, JSON.stringify(json, null, 2) + '\n');
  }
  const cfg = loadConfig();
  if (cfg.installedAgents) { delete cfg.installedAgents[id]; saveConfig(cfg); }
  log(`  removed agent-blackbox hooks from ${file}`);
}
