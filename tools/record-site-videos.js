#!/usr/bin/env node
// Regenerates the terminal videos on the project site (site/media/*.webm and *.png).
// It runs the real `blackbox demo --tamper`, replays the captured output in a throwaway
// terminal page and records that page with Playwright. Nothing here ships to npm.
//
//   npm i --no-save playwright-core        # once; the repo keeps zero runtime dependencies
//   CHROMIUM=/path/to/chrome node tools/record-site-videos.js
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const out = path.join(root, 'site', 'media');
const chromium = process.env.CHROMIUM || undefined;

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-video-'));
const run = spawnSync(process.execPath, [path.join(root, 'bin', 'blackbox.js'), 'demo', '--tamper'], {
  env: { ...process.env, HOME: home, NO_COLOR: '1' },
  encoding: 'utf8',
});
spawnSync(process.execPath, [path.join(root, 'bin', 'blackbox.js'), 'stop'], { env: { ...process.env, HOME: home } });
if (run.status !== 0) { console.error(run.stderr); process.exit(1); }
const lines = run.stdout.replace(/session demo-\w+/g, 'session demo').replace(/\n+$/, '').split('\n');
const cut = lines.findIndex((l) => l.startsWith('Tamper test'));
const clips = [
  { name: 'attack-denied', cmd: 'blackbox demo', lines: lines.slice(0, cut).filter((l) => !/^\s+timeline:/.test(l)) },
  { name: 'tamper-detected', cmd: 'blackbox demo --tamper', lines: lines.slice(cut) },
];

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
const paint = (s) => esc(s)
  .replace(/\b(allowed)\b/, '<b class=ok>$1</b>').replace(/\b(DENIED)\b/, '<b class=deny>$1</b>')
  .replace(/\b(ASK)\b/, '<b class=ask>$1</b>').replace(/(✘[^<]*)/, '<b class=deny>$1</b>')
  .replace(/^(\s*)(you see:|agent sees:)/, '$1<span class=dim>$2</span>');

const page = (clip) => `<!doctype html><meta charset=utf-8><style>
body{margin:0;background:#0f1113;color:#e9ebed;font:13.5px/1.5 ui-monospace,Menlo,Consolas,monospace}
.bar{height:34px;background:#171a1d;border-bottom:1px solid #2a2f34;display:flex;align-items:center;gap:8px;padding:0 14px;color:#9aa2aa;font-size:12px}
.dot{width:11px;height:11px;border-radius:50%;background:#ff8a4c}
pre{margin:0;padding:18px 22px;white-space:pre-wrap;word-break:break-word}
b{font-weight:700}.ok{color:#7bd69a}.deny{color:#ff8f86}.ask{color:#f3c35c}.dim{color:#9aa2aa}.p{color:#ff8a4c}
.cur{display:inline-block;width:8px;height:15px;background:#e9ebed;vertical-align:-2px}
</style><div class=bar><span class=dot></span>agent-blackbox</div><pre id=t></pre>
<script>
const cmd=${JSON.stringify(clip.cmd)},lines=${JSON.stringify(clip.lines.map(paint))};
const t=document.getElementById('t');let html='<span class=p>$</span> ';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 await sleep(500);
 for(const c of cmd){html+=c;t.innerHTML=html+'<span class=cur></span>';await sleep(55)}
 await sleep(500);html+='\\n';
 for(const l of lines){html+=l+'\\n';t.innerHTML=html+'<span class=cur></span>';
  await sleep(/DENIED|ASK|✘/.test(l)?1100:/^\\d\\./.test(l)||/^Tamper/.test(l)?800:450)}
 document.title='done';await sleep(2500);document.title='end';
})();
</script>`;

(async () => {
  const { chromium: pw } = require('playwright-core');
  const browser = await pw.launch({ executablePath: chromium, args: ['--no-sandbox'] });
  for (const clip of clips) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-rec-'));
    const ctx = await browser.newContext({ viewport: { width: 960, height: 540 }, recordVideo: { dir: tmp, size: { width: 960, height: 540 } } });
    const p = await ctx.newPage();
    await p.setContent(page(clip));
    await p.waitForFunction(() => document.title === 'done', null, { timeout: 120000 });
    await p.screenshot({ path: path.join(out, `${clip.name}.png`) });
    await p.waitForFunction(() => document.title === 'end', null, { timeout: 20000 });
    const video = p.video();
    await ctx.close();
    fs.copyFileSync(await video.path(), path.join(out, `${clip.name}.webm`));
    console.log('wrote', clip.name);
  }
  await browser.close();
})();
