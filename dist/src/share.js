"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.publicNumbers = publicNumbers;
exports.storyHtml = storyHtml;
exports.xCardHtml = xCardHtml;
exports.caption = caption;
exports.findChrome = findChrome;
exports.makeShareKit = makeShareKit;
// `blackbox share`: social assets from a scan, made locally.
//   x-card.png   1200x675  (X, LinkedIn)
//   story.png    1080x1920 (TikTok, Reels, Stories: last frame)
//   story.mp4    1080x1920, 10 s, animated (needs ffmpeg)
//   story.html   the same animation, plays in any browser
//   caption.txt  a suggested post
// Only aggregate numbers and the fixed category labels go in: no project
// names, hosts, skill names, commands or prompts.
// Rendering uses a Chrome/Chromium already on the machine (headless).
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const child_process_1 = require("child_process");
const scan_1 = require("./scan");
const util_1 = require("./util");
// The public subset of a scan summary.
function publicNumbers(S) {
    const skills = S.skills || [];
    return {
        days: S.days, sessions: S.sessions || 0, toolCalls: S.toolCalls || 0,
        privateSessions: S.privateSessions || 0, untrustedSessions: S.untrustedSessions || 0,
        outboundCalls: S.outboundCalls || 0, trifectaSessions: S.trifectaSessions || 0,
        wouldDenyCalls: S.wouldDenyCalls || 0,
        skillsUsed: skills.length, riskySkills: skills.filter((k) => k.risk === 'high' || k.risk === 'medium').length,
        categories: scan_1.CATEGORIES.map((c, i) => ({ label: c.label, value: (S.categories || {})[c.id] || 0, slot: i })),
    };
}
const PALETTE = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#14a114', '#9085e9'];
const FONT = "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
// One page that can draw any moment of the story: render(t) for t in seconds.
// Drawn as SVG so every frame is exact and the layout never depends on fonts loading late.
function storyHtml(S) {
    const data = JSON.stringify(publicNumbers(S));
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=1080">
<title>What my AI coding agent did</title>
<style>html,body{margin:0;background:#0b0e14;overflow:hidden}svg{display:block;width:100vw;height:auto;max-width:1080px;margin:0 auto}
@media (min-aspect-ratio:9/16){svg{width:auto;height:100vh}}</style></head><body>
<svg id="s" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 1920" font-family="${(0, util_1.escHtml)(FONT)}"></svg>
<script>
const D=${data};const P=${JSON.stringify(PALETTE)};const DUR=10;
const clamp=(x)=>Math.max(0,Math.min(1,x));const ease=(x)=>1-Math.pow(1-clamp(x),3);
const seg=(t,a,b)=>ease((t-a)/(b-a));const fmt=(n)=>Math.round(n).toLocaleString('en-US');
const esc=(s)=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const pl=(n,one,many)=>(Math.round(n)===1?one:many);
function txt(x,y,s,size,fill,o={}){return '<text x="'+x+'" y="'+y+'" font-size="'+size+'" fill="'+fill+'" font-weight="'+(o.w||400)+'" text-anchor="'+(o.a||'start')+'" opacity="'+(o.op??1)+'"'+(o.ls?' letter-spacing="'+o.ls+'"':'')+'>'+esc(s)+'</text>';}
function render(t){
  let o='<rect width="1080" height="1920" fill="#0b0e14"/>';
  o+='<circle cx="980" cy="160" r="420" fill="#3987e5" opacity="0.07"/><circle cx="80" cy="1780" r="380" fill="#d55181" opacity="0.06"/>';
  // header (always)
  const h=seg(t,0,0.8);
  o+=txt(80,170+(1-h)*30,'agent-blackbox',34,'#7d8590',{w:600,op:h,ls:1});
  o+=txt(80,270+(1-h)*30,'What my AI coding',76,'#f0f3f6',{w:800,op:h});
  o+=txt(80,360+(1-h)*30,'agent did',76,'#f0f3f6',{w:800,op:h});
  o+=txt(80,430+(1-h)*30,'in the last '+D.days+' days',40,'#7d8590',{op:h});
  // big counter
  const c=seg(t,1,2.6);
  o+=txt(80,640,fmt(D.toolCalls*c),190,'#f0f3f6',{w:800,op:seg(t,1,1.3)});
  o+=txt(84,710,pl(D.toolCalls,'tool call','tool calls')+' · '+fmt(D.sessions)+' '+pl(D.sessions,'session','sessions'),40,'#9da7b3',{op:seg(t,1.3,1.8)});
  // category bars
  const max=Math.max(1,...D.categories.map(x=>x.value));const total=Math.max(1,D.toolCalls);
  D.categories.forEach((k,i)=>{
    const g=seg(t,2.6+i*0.12,3.6+i*0.12);const y=770+i*62;const w=Math.max(6,(560*k.value/max)*g);
    o+=txt(80,y+34,k.label,32,'#c9d1d9',{op:g});
    o+='<path d="M380 '+(y+8)+'h'+(w-8)+'a8 8 0 0 1 8 8v20a8 8 0 0 1 -8 8h-'+(w-8)+'z" fill="'+P[k.slot]+'" opacity="'+g+'"/>';
    o+=txt(380+w+18,y+36,Math.round(100*k.value/total)+'%',30,'#9da7b3',{op:g,w:600});
  });
  // findings
  const cards=[[D.privateSessions,pl(D.privateSessions,'session read secrets or credentials','sessions read secrets or credentials'),'#f0b04a'],
    [D.outboundCalls,pl(D.outboundCalls,'call sent data out of the machine','calls sent data out of the machine'),'#f0b04a'],
    [D.trifectaSessions,pl(D.trifectaSessions,'session hit the lethal trifecta','sessions hit the lethal trifecta'),'#ff7a66'],
    [D.wouldDenyCalls,pl(D.wouldDenyCalls,'call a firewall would have blocked','calls a firewall would have blocked'),'#ff7a66']];
  if(D.skillsUsed) cards.push([D.skillsUsed,pl(D.skillsUsed,'skill loaded','skills loaded')+(D.riskySkills?' · '+D.riskySkills+' flagged by the audit':''),D.riskySkills?'#ff7a66':'#8fd18f']);
  const base=1250;
  cards.forEach((k,i)=>{
    const g=seg(t,5.4+i*0.35,6.1+i*0.35);const y=base+i*88;
    o+='<g opacity="'+g+'" transform="translate('+((1-g)*-40)+',0)"><rect x="80" y="'+y+'" width="920" height="76" rx="18" fill="#141922" stroke="#232a35"/>';
    o+=txt(116,y+52,fmt(k[0]),44,k[2],{w:800});
    o+=txt(116+Math.max(70,String(fmt(k[0])).length*28)+22,y+49,k[1],30,'#c9d1d9');
    o+='</g>';
  });
  // call to action
  const cta=seg(t,8.2,8.9);
  o+='<g opacity="'+cta+'"><rect x="80" y="'+(1840-118)+'" width="920" height="96" rx="22" fill="#f0f3f6"/>';
  o+=txt(540,1840-56,'Check yours: npx agent-blackbox scan',40,'#0b0e14',{w:700,a:'middle'});
  o+='</g>';
  o+=txt(540,1890,'scanned locally · nothing uploaded',28,'#7d8590',{a:'middle',op:cta});
  document.getElementById('s').innerHTML=o;
}
window.render=render;window.DUR=DUR;
if(!/[?&]driven/.test(location.search)){const t0=performance.now();(function loop(){const t=((performance.now()-t0)/1000)%(DUR+1.5);render(Math.min(t,DUR));requestAnimationFrame(loop);})();}
else render(DUR);
</script></body></html>`;
}
// Static 1200x675 card for X.
function xCardHtml(S) {
    const D = publicNumbers(S);
    const max = Math.max(1, ...D.categories.map((c) => c.value));
    const total = Math.max(1, D.toolCalls);
    const bars = D.categories.map((c, i) => {
        const y = 210 + i * 46, w = Math.max(6, (300 * c.value) / max);
        return `<text x="70" y="${y + 24}" font-size="21" fill="#c9d1d9">${(0, util_1.escHtml)(c.label)}</text>
      <path d="M260 ${y + 6}h${w - 6}a6 6 0 0 1 6 6v12a6 6 0 0 1 -6 6h-${w - 6}z" fill="${PALETTE[c.slot]}"/>
      <text x="${260 + w + 12}" y="${y + 24}" font-size="19" fill="#9da7b3" font-weight="600">${Math.round((100 * c.value) / total)}%</text>`;
    }).join('');
    const stat = (x, y, v, l, col) => `<rect x="${x}" y="${y}" width="250" height="150" rx="16" fill="#141922" stroke="#232a35"/>
    <text x="${x + 24}" y="${y + 76}" font-size="54" font-weight="800" fill="${col}">${(0, util_1.escHtml)((0, util_1.num)(v))}</text>
    <text x="${x + 24}" y="${y + 116}" font-size="18" fill="#9da7b3">${(0, util_1.escHtml)(l)}</text>`;
    return `<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;background:#0b0e14}svg{display:block}</style></head><body>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="675" viewBox="0 0 1200 675" font-family="${(0, util_1.escHtml)(FONT)}">
<rect width="1200" height="675" fill="#0b0e14"/><circle cx="1150" cy="40" r="300" fill="#3987e5" opacity="0.07"/>
<text x="70" y="96" font-size="44" font-weight="800" fill="#f0f3f6">What my AI coding agent did</text>
<text x="70" y="140" font-size="24" fill="#7d8590">${(0, util_1.escHtml)(`last ${D.days} days · ${(0, util_1.num)(D.toolCalls)} ${plural(D.toolCalls, 'tool call', 'tool calls')} · ${(0, util_1.num)(D.sessions)} ${plural(D.sessions, 'session', 'sessions')}`)}</text>
${bars}
${stat(640, 200, D.privateSessions, plural(D.privateSessions, 'session read secrets', 'sessions read secrets'), '#f0b04a')}${stat(910, 200, D.outboundCalls, plural(D.outboundCalls, 'call sent data out', 'calls sent data out'), '#f0b04a')}
${stat(640, 370, D.trifectaSessions, plural(D.trifectaSessions, 'lethal-trifecta session', 'lethal-trifecta sessions'), '#ff7a66')}${stat(910, 370, D.wouldDenyCalls, plural(D.wouldDenyCalls, 'call would be blocked', 'calls would be blocked'), '#ff7a66')}
<text x="70" y="630" font-size="22" fill="#7d8590">npx agent-blackbox scan · scanned locally, nothing uploaded</text>
</svg></body></html>`;
}
const plural = (x, one, many) => (Number(x) === 1 ? one : many);
function caption(S) {
    const D = publicNumbers(S);
    const p = (x, one, many) => `${(0, util_1.num)(x)} ${plural(x, one, many)}`;
    const lines = [
        `I audited what my AI coding agent did in the last ${D.days} days: ${p(D.toolCalls, 'tool call', 'tool calls')} across ${p(D.sessions, 'session', 'sessions')}.`,
        D.privateSessions ? `It read secrets or credentials in ${p(D.privateSessions, 'session', 'sessions')} and sent data out ${p(D.outboundCalls, 'time', 'times')}.` : `It sent data out of my machine ${p(D.outboundCalls, 'time', 'times')}.`,
        D.wouldDenyCalls || D.trifectaSessions ? `${p(D.trifectaSessions, 'session', 'sessions')} hit the "lethal trifecta" and ${p(D.wouldDenyCalls, 'call', 'calls')} would have been blocked.` : 'Nothing would have been blocked this time.',
        'Check yours in seconds, 100% local: npx agent-blackbox scan',
        '#AI #AIagents #ClaudeCode #cybersecurity #devtools',
    ];
    return lines.join('\n') + '\n';
}
// ---------- rendering with a local headless Chrome ----------
function findChrome() {
    if (process.env.BLACKBOX_CHROME && fs.existsSync(process.env.BLACKBOX_CHROME))
        return process.env.BLACKBOX_CHROME;
    const mac = ['Google Chrome', 'Chromium', 'Brave Browser', 'Microsoft Edge', 'Google Chrome Canary']
        .map((a) => `/Applications/${a}.app/Contents/MacOS/${a}`);
    const linux = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge']
        .map((b) => { const r = (0, child_process_1.spawnSync)('sh', ['-c', `command -v ${b}`], { encoding: 'utf8' }); return r.stdout.trim(); });
    const extra = ['/opt/pw-browsers/chromium', ...fs.existsSync('/opt/pw-browsers') ? fs.readdirSync('/opt/pw-browsers').filter((d) => /^chromium-\d+$/.test(d)).map((d) => `/opt/pw-browsers/${d}/chrome-linux/chrome`) : []];
    return [...mac, ...linux, ...extra].find((p) => p && fs.existsSync(p) && fs.statSync(p).isFile()) || null;
}
// Chrome refuses to run as root without --no-sandbox (containers, CI). Only then.
const rootFlags = () => (typeof process.getuid === 'function' && process.getuid() === 0 ? ['--no-sandbox'] : []);
const hasFfmpeg = () => (0, child_process_1.spawnSync)('ffmpeg', ['-version'], { stdio: 'ignore' }).status === 0;
async function withChrome(chrome, fn) {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-chrome-'));
    const proc = (0, child_process_1.spawn)(chrome, [...rootFlags(), '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--hide-scrollbars',
        '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--force-device-scale-factor=1',
        // the window must be at least as large as every capture, or Chrome tiles the image
        '--window-size=1280,2000', 'about:blank'], { stdio: 'ignore' });
    try {
        let port = null;
        for (let i = 0; i < 100 && !port; i++) {
            await new Promise((r) => setTimeout(r, 100));
            try {
                port = fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0].trim();
            }
            catch { /* not yet */ }
        }
        if (!port)
            throw new Error('Chrome did not start');
        const targets = await new Promise((resolve, reject) => {
            http.get({ host: '127.0.0.1', port, path: '/json/list' }, (res) => {
                const c = [];
                res.on('data', (d) => c.push(d));
                res.on('end', () => { try {
                    resolve(JSON.parse(Buffer.concat(c).toString('utf8')));
                }
                catch (e) {
                    reject(e);
                } });
            }).on('error', reject);
        });
        const page = targets.find((t) => t.type === 'page');
        const ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((r, j) => { ws.onopen = () => r(); ws.onerror = j; });
        let id = 0;
        const waiting = new Map();
        const events = [];
        ws.onmessage = (m) => {
            const msg = JSON.parse(m.data);
            if (msg.id && waiting.has(msg.id)) {
                const { res, rej } = waiting.get(msg.id);
                waiting.delete(msg.id);
                msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
            }
            else if (msg.method)
                events.push(msg.method);
        };
        const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; waiting.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
        await send('Page.enable');
        const result = await fn({ send, events });
        ws.close();
        return result;
    }
    finally {
        proc.kill('SIGKILL');
        try {
            fs.rmSync(profile, { recursive: true, force: true });
        }
        catch { /* best effort */ }
    }
}
async function openPage(send, events, file, w, h) {
    await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
    events.length = 0;
    await send('Page.navigate', { url: 'file://' + file + '?driven=1' });
    for (let i = 0; i < 100 && !events.includes('Page.loadEventFired'); i++)
        await new Promise((r) => setTimeout(r, 50));
    // Apply the size again once the document exists, then wait for two painted
    // frames: a capture taken before layout settles comes out tiled.
    await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
    await send('Runtime.evaluate', { expression: 'new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))', awaitPromise: true });
}
const shot = async (send, w, h) => Buffer.from((await send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: w, height: h, scale: 1 } })).data, 'base64');
// Fallback without WebSocket: one headless screenshot per call.
function screenshotOnce(chrome, file, w, h, out) {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-chrome-'));
    const r = (0, child_process_1.spawnSync)(chrome, [...rootFlags(), '--headless=new', '--disable-gpu', '--hide-scrollbars', `--user-data-dir=${profile}`, `--window-size=${w},${h}`,
        '--force-device-scale-factor=1', `--screenshot=${out}`, 'file://' + file + '?driven=1'], { stdio: 'ignore', timeout: 60000 });
    try {
        fs.rmSync(profile, { recursive: true, force: true });
    }
    catch { /* ignore */ }
    return r.status === 0 && fs.existsSync(out);
}
async function makeShareKit(S, outDir, { video = true, log = () => { } } = {}) {
    fs.mkdirSync(outDir, { recursive: true });
    const made = [];
    const storyFile = path.join(outDir, 'story.html');
    const xFile = path.join(outDir, 'x-card.html');
    fs.writeFileSync(storyFile, storyHtml(S));
    fs.writeFileSync(xFile, xCardHtml(S));
    fs.writeFileSync(path.join(outDir, 'caption.txt'), caption(S));
    made.push('story.html', 'caption.txt');
    const chrome = findChrome();
    if (!chrome) {
        log('no Chrome/Chromium found: open story.html in a browser and screen-record it, or set BLACKBOX_CHROME');
        return { made, chrome: null };
    }
    const xPng = path.join(outDir, 'x-card.png');
    const storyPng = path.join(outDir, 'story.png');
    const wantVideo = video && hasFfmpeg();
    if (video && !wantVideo)
        log('ffmpeg not found: skipping story.mp4 (macOS: brew install ffmpeg)');
    if (typeof WebSocket === 'function') {
        await withChrome(chrome, async ({ send, events }) => {
            await openPage(send, events, xFile, 1200, 675);
            fs.writeFileSync(xPng, await shot(send, 1200, 675));
            await openPage(send, events, storyFile, 1080, 1920);
            await send('Runtime.evaluate', { expression: 'render(DUR)' });
            fs.writeFileSync(storyPng, await shot(send, 1080, 1920));
            if (wantVideo) {
                const frames = fs.mkdtempSync(path.join(os.tmpdir(), 'bb-frames-'));
                const fps = 30, total = Math.round((10 + 1) * fps); // 10 s of motion + 1 s hold
                for (let i = 0; i < total; i++) {
                    const t = Math.min(i / fps, 10);
                    await send('Runtime.evaluate', { expression: `render(${t})` });
                    fs.writeFileSync(path.join(frames, `f${String(i).padStart(4, '0')}.png`), await shot(send, 1080, 1920));
                    if (i % 60 === 0)
                        log(`  rendering video ${Math.round((100 * i) / total)}%`);
                }
                const r = (0, child_process_1.spawnSync)('ffmpeg', ['-y', '-loglevel', 'error', '-framerate', String(fps), '-i', path.join(frames, 'f%04d.png'),
                    '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '20', '-movflags', '+faststart', path.join(outDir, 'story.mp4')], { stdio: 'inherit' });
                fs.rmSync(frames, { recursive: true, force: true });
                if (r.status === 0)
                    made.push('story.mp4');
            }
        });
    }
    else {
        // older Node: still produce the images (no frame-by-frame video)
        screenshotOnce(chrome, xFile, 1200, 675, xPng);
        screenshotOnce(chrome, storyFile, 1080, 1920, storyPng);
        if (wantVideo)
            log('story.mp4 needs Node 22+ (global WebSocket); images were still made');
    }
    if (fs.existsSync(xPng))
        made.push('x-card.png');
    if (fs.existsSync(storyPng))
        made.push('story.png');
    fs.unlinkSync(xFile);
    return { made, chrome };
}
