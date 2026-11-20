// Browser-extension test: real Chrome (temporary profile) with the unpacked extension, real server, real crypto.
// Needs a server on an EMPTY data dir: KASA_URL=http://localhost:8099 node tests/extension.mjs
import { spawn } from 'node:child_process';
import { mkdtempSync, cpSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import * as C from '../web/crypto.js';
import assert from 'node:assert/strict';

const here = dirname(fileURLToPath(import.meta.url));
const B = (process.env.KASA_URL || 'http://localhost:8099').replace(/\/$/, '');
const ok = (m) => console.log('ok', m);
assert.equal(readFileSync(join(here, '../extension/crypto.js'), 'utf8'), readFileSync(join(here, '../web/crypto.js'), 'utf8')); ok('extension crypto.js is identical to the web app copy');

// account + vault + login item, made with the real crypto module
const call = async (m, p, body, tok) => { const r = await fetch(B + '/api' + p, { method: m, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined }); return r.json(); };
const PW = 'extension test passphrase 42', salt = C.randomSalt();
const { masterKey, auth } = await C.deriveKeys(PW, salt, C.ITERS); const id = await C.newIdentity(masterKey);
const reg = await call('POST', '/register', { email: 'ext@t.org', name: 'Ext', salt, iters: C.ITERS, auth, ...id });
if (!reg.token) { console.error('Use an empty data dir.', reg); process.exit(1); }
const vk = await C.newVaultKey();
const vid = (await call('POST', '/vaults', { enc_name: await C.encJSON(vk, { name: 'Team' }), wrapped_key: await C.wrapVaultKey(vk, reg.user.public_key) }, reg.token)).id;
const SITE = 'http://127.0.0.1:8098';
await call('POST', `/vaults/${vid}/items`, { data: await C.encJSON(vk, { type: 'login', title: 'Test site', username: 'anna@t.org', password: 'S3cret-from-vault', urls: SITE, totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' }) }, reg.token);
await call('POST', `/vaults/${vid}/items`, { data: await C.encJSON(vk, { type: 'login', title: 'Other site', username: 'x', password: 'y', urls: 'https://example.org' }) }, reg.token);

// the page to fill
const site = http.createServer((q, r) => { r.setHeader('Content-Type', 'text/html'); r.end(readFileSync(join(here, 'fixtures/login.html'))); }).listen(8098, '127.0.0.1');

// unpacked extension; the test copy also gets host permissions for the local servers (no permission prompt in headless)
const ext = mkdtempSync(join(tmpdir(), 'vaultly-ext-')); cpSync(join(here, '../extension'), ext, { recursive: true });
const man = JSON.parse(readFileSync(join(ext, 'manifest.json'), 'utf8')); man.host_permissions = ['http://127.0.0.1/*', 'http://localhost/*']; writeFileSync(join(ext, 'manifest.json'), JSON.stringify(man));
const prof = mkdtempSync(join(tmpdir(), 'vaultly-prof-'));
// Branded Chrome ignores --load-extension since v137: load it over the DevTools pipe (Extensions.loadUnpacked) instead.
const ch = spawn('google-chrome', ['--headless=new', '--no-sandbox', '--remote-debugging-port=9334', '--remote-debugging-pipe', '--enable-unsafe-extension-debugging', `--user-data-dir=${prof}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
const pipeOut = ch.stdio[3], pipeIn = ch.stdio[4]; let pbuf = ''; const ppend = new Map(); let pid = 0;
pipeIn.on('data', (d) => { pbuf += d.toString(); let i; while ((i = pbuf.indexOf('\0')) >= 0) { const j = JSON.parse(pbuf.slice(0, i)); pbuf = pbuf.slice(i + 1); if (ppend.has(j.id)) ppend.get(j.id)(j); } });
const pipeSend = (method, params = {}) => new Promise((r) => { const i = ++pid; ppend.set(i, r); pipeOut.write(JSON.stringify({ id: i, method, params }) + '\0'); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let fail = 0;
try {
  await sleep(3000);
  const loaded = await pipeSend('Extensions.loadUnpacked', { path: ext });
  assert.ok(loaded.result?.id, 'loadUnpacked: ' + JSON.stringify(loaded.error || loaded)); const EXT = loaded.result.id; ok('extension loaded ' + EXT);
  await sleep(1000);
  const page = async (url) => { const t = await (await fetch('http://127.0.0.1:9334/json/new?' + url, { method: 'PUT' })).json(); const ws = new WebSocket(t.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r)); let n = 0; const pend = new Map(); ws.onmessage = (m) => { const j = JSON.parse(m.data); if (pend.has(j.id)) pend.get(j.id)(j); }; const send = (method, params = {}) => new Promise((r) => { const i = ++n; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); }); const ev = async (expr) => { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true, userGesture: true }); if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'eval error'); return r.result.result.value; }; return { ev, send, nav: (u) => send('Page.navigate', { url: u }), close: () => ws.close() }; };
  const waitFor = async (pg, expr, ms = 20000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await pg.ev(expr)) return; } catch { /* page loading */ } await sleep(200); } let body = ''; try { body = await pg.ev(`document.body.innerText.slice(0,300) + ' | ' + location.href`); } catch (e) { body = 'eval failed: ' + e.message; } throw new Error('timeout: ' + expr + '\n  page: ' + body); };
  const site1 = await page(SITE + '/login'); await waitFor(site1, `!!document.getElementById('pw')`);
  const pop = await page('about:blank'); await pop.nav(`chrome-extension://${EXT}/popup.html`);
  await waitFor(pop, `document.querySelector('h1')?.textContent==='Connect to Vaultly'`);
  const tabId = await pop.ev(`chrome.tabs.query({url:'${SITE}/*'}).then(t=>t[0].id)`);
  await pop.ev(`(()=>{const i=[...document.querySelectorAll('input')];i[0].value=${JSON.stringify(B)};i[1].value='ext@t.org';[...document.querySelectorAll('button')].find(b=>b.textContent==='Connect').click();return 1})()`);
  await waitFor(pop, `document.querySelector('h1')?.textContent==='Unlock Vaultly'`); ok('connect screen -> unlock screen');
  await pop.nav(`chrome-extension://${EXT}/popup.html?tab=${tabId}`); await sleep(800);
  await waitFor(pop, `document.querySelector('h1')?.textContent==='Unlock Vaultly'`);
  await pop.ev(`(()=>{document.querySelector('input[type=password]').value='wrong password 123';[...document.querySelectorAll('button')].find(b=>b.textContent==='Unlock').click();return 1})()`);
  await waitFor(pop, `/Incorrect/.test(document.querySelector('.err')?.textContent||'')`); ok('wrong master password refused');
  await pop.ev(`(()=>{document.querySelector('input[type=password]').value=${JSON.stringify(PW)};[...document.querySelectorAll('button')].find(b=>b.textContent==='Unlock').click();return 1})()`);
  await waitFor(pop, `document.querySelector('h1')?.textContent==='Vaultly'`, 30000);
  const shown = await pop.ev(`[...document.querySelectorAll('.it b')].map(b=>b.textContent)`);
  assert.deepEqual(shown, ['Test site']); ok('only the login for this site is offered');
  await pop.ev(`[...document.querySelectorAll('button')].find(b=>b.textContent==='Fill').click()`);
  await waitFor(pop, `[...document.querySelectorAll('button')].some(b=>b.textContent==='Filled ✓')`);
  const vals = await site1.ev(`[document.getElementById('email').value, document.getElementById('pw').value, document.getElementById('otp').value]`);
  assert.deepEqual(vals, ['anna@t.org', 'S3cret-from-vault', '']); ok('page filled with decrypted username + password (nothing else)');
  await pipeSend('Browser.grantPermissions', { origin: `chrome-extension://${EXT}`, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  await pop.send('Emulation.setFocusEmulationEnabled', { enabled: true });   // headless pages are never focused; the clipboard API needs focus
  await pop.ev(`[...document.querySelectorAll('button')].find(b=>b.textContent==='Password').click()`); await sleep(800);
  const pwBtn = await pop.ev(`[...document.querySelectorAll('button')].map(b=>b.textContent).filter(t=>/Copied|Blocked|Password/.test(t)).join(',')`);
  if (!/Copied/.test(pwBtn)) console.log('  (clipboard state: ' + pwBtn + ')');
  assert.ok(await pop.ev(`chrome.alarms.get('clear-clipboard').then(a=>!!a)`)); ok('copying a password schedules clipboard clearing in the service worker');
  assert.equal(await pop.ev(`navigator.clipboard.readText()`), 'S3cret-from-vault');
  await sleep(33000);
  assert.notEqual((await pop.ev(`navigator.clipboard.readText()`)).trim(), 'S3cret-from-vault'.trim()); ok('the password is gone from the clipboard after 30 s');
  // the tab navigates to another host after the popup read its URL: the fill must refuse
  await site1.ev(`location.href='http://localhost:8098/login'`); await sleep(1200);
  await pop.ev(`(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent==='Filled ✓');b.textContent='Fill';b.click();return 1})()`);
  await waitFor(pop, `[...document.querySelectorAll('button')].some(b=>b.textContent==='Page changed, not filled')`);
  assert.equal(await site1.ev(`document.getElementById('pw').value`), ''); ok('a tab that moved to another site gets nothing');
  const stored = await pop.ev(`chrome.storage.session.get('sess').then(x=>JSON.stringify(x))`);
  assert.ok(!stored.includes(PW) && !stored.includes('S3cret')); ok('session storage holds no master password or item secrets');
  const local = await pop.ev(`chrome.storage.local.get(null).then(x=>JSON.stringify(x))`);
  assert.ok(!local.includes(PW) && !local.includes('S3cret') && !local.includes('token')); ok('persistent storage holds only server + email');
  await pop.ev(`(()=>{const s=document.querySelector('input');s.value='other';s.dispatchEvent(new Event('input'));return 1})()`); await sleep(300);
  assert.deepEqual(await pop.ev(`[...document.querySelectorAll('.it b')].map(b=>b.textContent)`), ['Other site']); ok('search finds logins of other sites');
  await pop.ev(`location.reload()`); await waitFor(pop, `document.querySelector('h1')?.textContent==='Vaultly'`); ok('stays unlocked while the browser runs (session storage)');
  await pop.ev(`[...document.querySelectorAll('button')].find(b=>b.textContent.includes('Lock')).click()`);
  await waitFor(pop, `document.querySelector('h1')?.textContent==='Unlock Vaultly'`);
  assert.equal(await pop.ev(`chrome.storage.session.get('sess').then(x=>!!x.sess)`), false);
  assert.equal((await fetch(B + '/api/vaults', { headers: { Authorization: 'Bearer ' + JSON.parse(stored).sess.token } })).status, 401); ok('Lock clears the keys and ends the server session');
  // two-factor sign-in through the extension
  const tok = (await call('POST', '/login', { email: 'ext@t.org', auth })).token;
  const su = await call('POST', '/2fa/setup', { auth }, tok); await call('POST', '/2fa/enable', { code: (await C.totp(su.secret)).code }, tok);
  await pop.ev(`(()=>{document.querySelector('input[type=password]').value=${JSON.stringify(PW)};[...document.querySelectorAll('button')].find(b=>b.textContent==='Unlock').click();return 1})()`);
  await waitFor(pop, `[...document.querySelectorAll('button')].some(b=>b.textContent==='Verify')`, 30000); ok('extension asks for the 2FA code');
  const code = (await C.totp(su.secret, Date.now() + 30000)).code;
  await pop.ev(`(()=>{const c=document.querySelector('input[autocomplete=one-time-code]');c.value='${code}';[...document.querySelectorAll('button')].find(b=>b.textContent==='Verify').click();return 1})()`);
  await waitFor(pop, `document.querySelector('h1')?.textContent==='Vaultly'`, 30000); ok('unlocked with 2FA');
} catch (e) { fail++; console.error('FAIL', e.message); }
ch.kill(); site.close();
console.log(fail ? '\nEXTENSION TEST FAILED' : '\nALL EXTENSION TESTS PASSED'); process.exit(fail ? 1 : 0);
