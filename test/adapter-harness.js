'use strict';
// Shared by the adapter tests: a real recorder in this process, and the real
// hook script run as a child process, the way an agent runs it.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const HOOK = path.join(__dirname, '..', 'dist', 'bin', 'hook.js');

/** Point the recorder's data folder and port at a throwaway place. Call before requiring dist/. */
function isolate() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-adapter-'));
  process.env.BLACKBOX_HOME = path.join(home, 'bb');
  process.env.BLACKBOX_PORT = String(19000 + Math.floor(Math.random() * 2000));
  process.env.HOME = home; // agent config files an installer touches land here
  return home;
}

/** Run the hook script for one agent with a native payload. @returns {Promise<{ code: number | null, stdout: string, stderr: string }>} */
function runHook(agent, payload, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [HOOK, '--agent', agent, ...args], { env: process.env });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
  });
}

/** Ledger records the recorder wrote, parsed. @param {string} file */
const records = (file) => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

module.exports = { isolate, runHook, records, HOOK };
