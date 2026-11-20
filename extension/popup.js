// Vaultly browser extension popup. Same zero-knowledge model as the web app:
// the master password derives the keys here; the server only sees the "auth" half and ciphertext.
// After unlocking, the session token and the vault keys stay in chrome.storage.session (memory only).
import * as C from './crypto.js';
import { fillForm } from './fill.js';
import { urlMatches, parseUrl } from './match.js';

const m = document.getElementById('m');
const st = chrome.storage.local, ss = chrome.storage.session;
const DEFAULT_SERVER = 'https://vaultly-team.fly.dev';
let tab = null, items = [];

function h(tag, a = {}, ...kids) {   // DOM builder: text is always set as text, never parsed as HTML
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(a || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value' || k === 'disabled' || k === 'hidden') e[k] = v; else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
const msg = (e) => (e && e.message) || String(e);

async function call(server, method, path, body, token) {
  const r = await fetch(server + '/api' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let j = null; try { j = await r.json(); } catch { /* empty */ }
  if (!r.ok) { const err = new Error(j && typeof j.detail === 'string' ? j.detail : 'Server error ' + r.status); err.status = r.status; throw err; }
  return j;
}

async function main() {
  const forced = +new URLSearchParams(location.search).get('tab');   // automated tests open the popup as a page and name the target tab
  [tab] = forced ? [await chrome.tabs.get(forced)] : await chrome.tabs.query({ active: true, currentWindow: true });
  const { cfg } = await st.get('cfg');
  if (!cfg) return setup();
  const { sess } = await ss.get('sess');
  if (sess && sess.server === cfg.server) {
    try { return await open(cfg, sess); } catch (e) { await ss.remove('sess'); return unlock(cfg, e.status === 401 ? 'Session ended, unlock again.' : msg(e)); }
  }
  unlock(cfg);
}

function setup(err = '') {
  const srv = h('input', { value: DEFAULT_SERVER, placeholder: 'https://your-vaultly-server' });
  const email = h('input', { type: 'email', placeholder: 'Your Vaultly email', autocomplete: 'username' });
  const go = h('button', { class: 'pri', onclick: async () => {
    go.disabled = true;
    try {
      const u = new URL(srv.value.trim());
      if (u.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(u.hostname)) throw new Error('The server address must start with https://');
      if (!(await chrome.permissions.request({ origins: [u.origin + '/*'] }))) throw new Error('Permission to reach the server was denied.');
      await call(u.origin, 'GET', '/status');
      if (!email.value.includes('@')) throw new Error('Enter your email.');
      await st.set({ cfg: { server: u.origin, email: email.value.trim().toLowerCase() } }); main();
    } catch (e) { setup(msg(e)); }
  } }, 'Connect');
  m.replaceChildren(h('h1', {}, 'Connect to Vaultly'), srv, email, go, err && h('span', { class: 'err' }, err),
    h('span', { class: 'mut' }, 'Your master password is asked when you unlock and is never stored.'));
  email.focus();
}

function unlock(cfg, err = '') {
  const pw = h('input', { type: 'password', placeholder: 'Master password', autocomplete: 'current-password' });
  const code = h('input', { placeholder: '2FA code or recovery code', autocomplete: 'one-time-code', hidden: true });
  const out = h('span', { class: 'err' }, err);
  let pending = null;
  const go = h('button', { class: 'pri' }, 'Unlock');
  const run = async () => {
    go.disabled = true; out.textContent = '';
    try {
      let masterKey, auth;
      if (pending) ({ masterKey, auth } = pending);
      else {
        go.textContent = 'Deriving keys…';
        const pre = await call(cfg.server, 'GET', '/prelogin?email=' + encodeURIComponent(cfg.email));
        ({ masterKey, auth } = await C.deriveKeys(pw.value, pre.salt, pre.iters));
      }
      let r;
      try { r = await call(cfg.server, 'POST', '/login', { email: cfg.email, auth, ...(pending ? { code: code.value.trim() } : {}) }); }
      catch (e) {
        if (msg(e) !== '2FA_REQUIRED') throw e;
        pending = { masterKey, auth }; pw.hidden = true; code.hidden = false; code.focus(); go.disabled = false; go.textContent = 'Verify'; return;
      }
      const priv = await C.loadPrivate(masterKey, r.user.enc_private_key);
      const vaults = [];
      for (const v of await call(cfg.server, 'GET', '/vaults', null, r.token)) {
        if (v.status === 'pending') continue;
        try {
          const key = await C.unwrapVaultKey(v.wrapped_key, priv);
          vaults.push({ id: v.id, name: (await C.decJSON(key, v.enc_name)).name, key: C.b64(await crypto.subtle.exportKey('raw', key)) });
        } catch { /* undecryptable vault: skipped */ }
      }
      const sess = { server: cfg.server, token: r.token, vaults };
      await ss.set({ sess }); await open(cfg, sess);
    } catch (e) { out.textContent = msg(e); go.disabled = false; go.textContent = pending ? 'Verify' : 'Unlock'; }
  };
  go.addEventListener('click', run);
  [pw, code].forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); }));
  m.replaceChildren(h('h1', {}, 'Unlock Vaultly'), h('span', { class: 'mut' }, cfg.email), pw, code, go, out,
    h('button', { class: 'link', onclick: async () => { await st.remove('cfg'); await ss.remove('sess'); setup(); } }, 'Change server or account'));
  pw.focus();
}

async function open(cfg, sess) {
  items = [];
  for (const v of sess.vaults) {
    const key = await crypto.subtle.importKey('raw', C.unb64(v.key), 'AES-GCM', false, ['decrypt']);
    for (const it of await call(cfg.server, 'GET', `/vaults/${v.id}/items`, null, sess.token)) {
      if (it.trashed) continue;
      try { const d = await C.decJSON(key, it.data); if (d.type === 'login' && (d.username || d.password)) items.push({ d, vault: v.name }); } catch { /* skip */ }
    }
  }
  items.sort((a, b) => (a.d.title || '').localeCompare(b.d.title || ''));
  show('');
}

const urlsOf = (d) => String(d.urls || '').split(/[\s,]+/).filter(Boolean);
const matches = (d) => !!tab?.url && urlsOf(d).some((u) => urlMatches(tab.url, u));

async function copyFor(text, btn, label, clearAfter) {
  try { await navigator.clipboard.writeText(text); } catch { btn.textContent = 'Blocked'; return; }
  btn.textContent = label;
  if (clearAfter) setTimeout(async () => { try { if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText(''); } catch { /* popup closed */ } }, 30000);
}

function show(q) {
  const host = parseUrl(tab?.url || '')?.hostname || '';
  const ql = q.trim().toLowerCase();
  const list = ql ? items.filter(({ d, vault }) => [d.title, d.username, d.urls, vault].join(' ').toLowerCase().includes(ql)) : items.filter(({ d }) => matches(d));
  const search = h('input', { placeholder: 'Search all logins…', value: q });
  search.addEventListener('input', () => { show(search.value); });
  const rows = list.slice(0, 40).map(({ d, vault }) => {
    const ok = matches(d);
    return h('div', { class: 'it' }, h('b', {}, d.title || '(untitled)'), h('span', { class: 'mut' }, (d.username || '') + ' · ' + vault),
      h('div', { class: 'row' },
        h('button', { class: 'pri', title: ok ? 'Fill username and password on this page' : 'Saved for a different site', onclick: async (e) => {
          if (!ok && !confirm(`This login is saved for:\n${urlsOf(d)[0] || '(no website)'}\n\nYou are on ${host || 'an unknown page'}. Fill anyway?`)) return;
          try {
            const [r] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: fillForm, args: [d.username || '', d.password || ''] });
            e.target.textContent = r?.result ? 'Filled ✓' : 'No login form found';
          } catch { e.target.textContent = 'Cannot fill this page'; }
        } }, ok ? 'Fill' : 'Fill…'),
        d.username && h('button', { onclick: (e) => copyFor(d.username, e.target, 'Copied', false) }, 'User'),
        d.password && h('button', { onclick: (e) => copyFor(d.password, e.target, 'Copied (30 s)', true) }, 'Password'),
        d.totp && h('button', { onclick: async (e) => { try { copyFor((await C.totp(d.totp)).code, e.target, 'Copied', false); } catch { e.target.textContent = 'Bad 2FA key'; } } }, '2FA code')));
  });
  m.replaceChildren(h('h1', {}, 'Vaultly'), search,
    h('span', { class: 'mut' }, ql ? `${list.length} result(s)` : host ? `Logins for ${host}` : 'No website in this tab'),
    h('div', { class: 'list' }, rows.length ? rows : h('span', { class: 'mut' }, ql ? 'Nothing found.' : 'No saved login matches this site. Search above.')),
    h('div', { class: 'row' },
      h('button', { onclick: async () => {
        const { sess } = await ss.get('sess'); await ss.remove('sess');
        try { if (sess) await call(sess.server, 'POST', '/logout', null, sess.token); } catch { /* already gone */ }
        main();
      } }, '🔒 Lock'),
      h('button', { onclick: async () => { const { cfg } = await st.get('cfg'); chrome.tabs.create({ url: cfg.server + '/' }); } }, 'Open Vaultly')));
  search.focus(); search.setSelectionRange(q.length, q.length);
}

main();
