import * as C from './crypto.js';

const $app = document.getElementById('app');
const S = {
  token: null, user: null, master: null, priv: null,
  vaults: [], items: new Map(), view: { k: 'all' }, sel: null, q: '', edit: null,
  pwned: new Map(), tick: null, idle: null, pending: [],
};
const TYPES = { login: 'Login', note: 'Note', card: 'Card', identity: 'Identity', wifi: 'Wi-Fi', bank: 'Bank account', license: 'Software license', apikey: 'API key', ssh: 'SSH key', server: 'Server / database' };
// field definitions of the structured types; values live in item.data.x
const XFIELDS = {
  identity: [['fullname', 'Full name'], ['email', 'Email'], ['phone', 'Phone'], ['address', 'Address', { area: 1 }], ['birth', 'Date of birth'], ['idnum', 'ID / passport number', { secret: 1 }], ['org', 'Organisation']],
  wifi: [['ssid', 'Network name (SSID)'], ['password', 'Password', { secret: 1, mono: 1 }], ['security', 'Security (WPA2, WPA3…)']],
  bank: [['bank', 'Bank'], ['holder', 'Account holder'], ['iban', 'IBAN', { mono: 1 }], ['bic', 'BIC / SWIFT', { mono: 1 }], ['account', 'Account number', { mono: 1 }], ['ebanking', 'E-banking login'], ['pin', 'PIN / password', { secret: 1, mono: 1 }]],
  license: [['product', 'Product'], ['key', 'License key', { secret: 1, mono: 1 }], ['email', 'Registered to'], ['version', 'Version'], ['expires', 'Valid until'], ['seats', 'Seats']],
  apikey: [['service', 'Service'], ['key', 'Key / token', { secret: 1, mono: 1 }], ['secret', 'Secret', { secret: 1, mono: 1 }], ['url', 'Endpoint / console', { link: 1 }], ['expires', 'Expires']],
  ssh: [['host', 'Host'], ['user', 'User'], ['private', 'Private key', { secret: 1, mono: 1, area: 1 }], ['public', 'Public key', { mono: 1, area: 1 }], ['passphrase', 'Key passphrase', { secret: 1, mono: 1 }]],
  server: [['host', 'Host'], ['port', 'Port'], ['user', 'User'], ['password', 'Password', { secret: 1, mono: 1 }], ['database', 'Database'], ['url', 'Admin URL', { link: 1 }]],
};
const tagsOf = (d) => (Array.isArray(d.tags) ? d.tags.filter((t) => typeof t === 'string' && t) : []);
function subtitle(d) {
  if (d.type === 'login') return d.username || '';
  if (d.type === 'card') return '•••• ' + (d.card?.number || '').slice(-4);
  if (XFIELDS[d.type]) { const f = XFIELDS[d.type].find(([k, , o]) => d.x?.[k] && !o?.secret); return (TYPES[d.type] || '') + (f ? ' · ' + d.x[f[0]] : ''); }
  return 'Note';
}
const ROLES = { owner: 'Owner', editor: 'Editor', viewer: 'Viewer' };

// ------------------------------------------------------------------ helpers
function h(tag, a = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(a || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') e[k] = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
const $ = (s, r = document) => r.querySelector(s);
let toastT;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2200); }
const errMsg = (e) => (e && e.message) || String(e);

async function api(method, path, body) {
  const r = await fetch('/api' + path, {
    method, headers: { 'Content-Type': 'application/json', ...(S.token ? { Authorization: 'Bearer ' + S.token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let j = null; try { j = await r.json(); } catch { /* empty */ }
  if (!r.ok) {
    if (r.status === 401 && S.token) lock('Session expired, please sign in again.');
    throw new Error(j && typeof j.detail === 'string' ? j.detail : 'Invalid request (' + r.status + ')');
  }
  return j;
}

function modal(title, ...body) {
  const d = h('dialog', {}, h('h3', {}, title), ...body);
  d.addEventListener('close', () => d.remove());
  document.body.append(d); d.showModal(); return d;
}
let clipT;
async function copy(text, label = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(label + ' (cleared from clipboard in 30 s)'); }
  catch { toast('Clipboard permission denied'); return; }
  clearTimeout(clipT); clipT = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000);
}
const hue = (s) => { let x = 0; for (const c of s || '?') x = (x * 31 + c.charCodeAt(0)) % 360; return x; };
const fmtDate = (t) => new Date(t * 1000).toLocaleString('en-US');
const safeUrl = (u) => { try { const x = new URL(/^[a-z]+:\/\//i.test(u) ? u : 'https://' + u); return /^https?:$/.test(x.protocol) ? x.href : null; } catch { return null; } };
const vaultById = (id) => S.vaults.find((v) => v.id === id);
const canWrite = (vid) => ['owner', 'editor'].includes(vaultById(vid)?.role);

// ------------------------------------------------------------------ auth
function lock(msg) {
  clearInterval(S.tick); clearTimeout(S.idle);
  Object.assign(S, { token: null, user: null, master: null, priv: null, vaults: [], items: new Map(), sel: null, edit: null, q: '', view: { k: 'all' }, pwned: new Map() });
  document.querySelectorAll('dialog').forEach((d) => d.remove());
  renderAuth(null, msg);
}

async function renderAuth(mode, msg) {
  let invite = '';
  const m = location.hash.match(/invite=([\w-]+)/); if (m) invite = m[1];
  if (!mode) {
    try { mode = (await (await fetch('/api/status')).json()).setup ? 'setup' : (invite ? 'register' : 'login'); } catch { mode = 'login'; }
  }
  const reg = mode === 'register' || mode === 'setup';
  const email = h('input', { type: 'email', autocomplete: 'username', required: true });
  const name = h('input', { autocomplete: 'name' });
  const pw = h('input', { type: 'password', autocomplete: reg ? 'new-password' : 'current-password', required: true });
  const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const inv = h('input', { value: invite, autocomplete: 'off' });
  const meter = h('div', { class: 'bar' }, h('i'));
  const meterT = h('div', { class: 'muted' });
  const out = h('div', { class: 'err' }, msg || '');
  const btn = h('button', { class: 'primary', type: 'submit' }, mode === 'setup' ? 'Create administrator account' : reg ? 'Create account' : 'Sign in');
  let pending2fa = null;
  const code = h('input', { inputmode: 'text', autocomplete: 'one-time-code', placeholder: '6-digit code or a recovery code' });
  const codeBox = h('div', { hidden: true }, h('label', {}, 'Two-factor code'), code, h('p', { class: 'muted' }, 'Open your authenticator app. Lost your phone? Enter one of your recovery codes.'));
  pw.addEventListener('input', () => {
    if (!reg) return; const s = C.strength(pw.value);
    meter.firstChild.className = 's' + s.level; meter.firstChild.style.width = Math.min(100, s.bits) + '%'; meterT.textContent = s.label ? `${s.label} · ~${s.bits} bit` : '';
  });
  const form = h('form', { class: 'auth', onsubmit: async (e) => {
    e.preventDefault(); out.textContent = ''; btn.disabled = true; btn.textContent = 'Deriving keys…';
    try {
      if (reg) {
        if (pw.value.length < 12) throw new Error('Master password must be at least 12 characters (a long sentence works well).');
        if (C.strength(pw.value).level < 2) throw new Error('Master password is too weak.');
        if (pw.value !== pw2.value) throw new Error('Passwords do not match.');
        const salt = C.randomSalt(); const { masterKey, auth } = await C.deriveKeys(pw.value, salt, C.ITERS);
        const ident = await C.newIdentity(masterKey);
        const r = await api('POST', '/register', { email: email.value, name: name.value || email.value, salt, iters: C.ITERS, auth, ...ident, invite: mode === 'setup' ? null : inv.value.trim() });
        history.replaceState(null, '', location.pathname);
        await startSession(r, masterKey);
      } else if (pending2fa) {
        await startSession(await api('POST', '/login', { email: pending2fa.email, auth: pending2fa.auth, code: code.value.trim() }), pending2fa.masterKey);
      } else {
        const pre = await api('GET', '/prelogin?email=' + encodeURIComponent(email.value));
        const { masterKey, auth } = await C.deriveKeys(pw.value, pre.salt, pre.iters);
        try { await startSession(await api('POST', '/login', { email: email.value, auth }), masterKey); }
        catch (ex) {
          if (errMsg(ex) !== '2FA_REQUIRED') throw ex;
          pending2fa = { email: email.value, auth, masterKey };   // keep the derived keys: no second 600k-round derivation
          codeBox.hidden = false; email.disabled = pw.disabled = true; code.focus(); btn.disabled = false; btn.textContent = 'Verify'; return;
        }
      }
    } catch (ex) { out.textContent = errMsg(ex); btn.disabled = false; btn.textContent = 'Try again'; }
  } },
    h('h1', {}, h('img', { class: 'logo', src: 'icon.svg', alt: '' }), 'Vaultly'),
    h('p', { class: 'muted' }, mode === 'setup' ? 'First-time setup: this account will be the system administrator.' : reg ? 'Join the team with your invite code.' : 'Your team\'s password vault. End-to-end encrypted.'),
    h('label', {}, 'Email'), email,
    reg && [h('label', {}, 'Full name'), name],
    reg && mode !== 'setup' && [h('label', {}, 'Invite code'), inv],
    h('label', {}, 'Master password'), pw, !reg && codeBox,
    reg && [meter, meterT, h('label', {}, 'Master password (repeat)'), pw2,
      h('p', { class: 'muted' }, 'Nobody can reset your master password — not even the server. If you forget it your data cannot be recovered; write it down somewhere safe.')],
    out, btn,
    mode !== 'setup' && h('p', { class: 'muted' }, reg ? 'Already have an account? ' : 'Have an invite code? ',
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); renderAuth(reg ? 'login' : 'register'); } }, reg ? 'Sign in' : 'Sign up')));
  $app.replaceChildren(form);
  email.focus();
}

async function startSession(r, masterKey) {
  S.token = r.token; S.user = r.user; S.master = masterKey;
  S.priv = await C.loadPrivate(masterKey, r.user.enc_private_key);
  await loadAll();
  buildShell(); armIdle();
}

async function createVault(name) {
  const key = await C.newVaultKey();
  const r = await api('POST', '/vaults', { enc_name: await C.encJSON(key, { name }), wrapped_key: await C.wrapVaultKey(key, S.user.public_key) });
  return r.id;
}

async function loadAll() {
  let list = await api('GET', '/vaults');
  if (!list.length) { await createVault('Personal'); list = await api('GET', '/vaults'); }
  S.vaults = []; S.items = new Map(); S.pending = list.filter((v) => v.status === 'pending');
  await Promise.all(list.filter((v) => v.status !== 'pending').map(async (v) => {
    try {
      const key = await C.unwrapVaultKey(v.wrapped_key, S.priv);
      const name = (await C.decJSON(key, v.enc_name)).name;
      S.vaults.push({ id: v.id, name, role: v.role, key, member_count: v.member_count, mine: !!v.mine, owners: v.owners });
      for (const it of await api('GET', `/vaults/${v.id}/items`)) {
        try { S.items.set(it.id, { id: it.id, vid: v.id, data: await C.decJSON(key, it.data), trashed: it.trashed, rev: it.rev, updated_at: it.updated_at }); }
        catch { /* undecryptable item: skipped */ }
      }
    } catch { S.vaults.push({ id: v.id, name: '⚠ Undecryptable vault', role: 'viewer', key: null, member_count: v.member_count, broken: true }); }
  }));
  S.vaults.sort((a, b) => a.name.localeCompare(b.name));
}

function armIdle() {
  const mins = +(localStorage.getItem('vaultly.autolock') || 10);
  clearTimeout(S.idle); if (!mins || !S.token) return;
  S.idle = setTimeout(() => lock('Locked due to inactivity.'), mins * 60000);
}
['click', 'keydown', 'mousemove'].forEach((ev) => document.addEventListener(ev, () => { if (S.token) armIdle(); }, { passive: true }));

// ------------------------------------------------------------------ shell
let el = {};
function buildShell() {
  el.side = h('nav', { class: 'side' });
  el.items = h('div', { class: 'items' });
  const search = h('input', { type: 'search', placeholder: 'Search…', 'aria-label': 'Search', oninput: (e) => { S.q = e.target.value; renderList(); } });
  el.list = h('section', { class: 'list' },
    h('div', { class: 'toolbar' }, search, h('button', { class: 'primary', onclick: () => newItem(), title: 'New item' }, '+')), el.items);
  el.detail = h('main', { class: 'detail' });
  el.shell = h('div', { class: 'shell' }, el.side, el.list, el.detail);
  $app.replaceChildren(el.shell); renderAll();
}
function renderAll() { renderSide(); renderList(); renderDetail(); }
function go(view) { S.view = view; S.sel = null; S.edit = null; renderAll(); }

function liveItems() { return [...S.items.values()].filter((i) => !i.trashed); }
function renderSide() {
  const live = liveItems(); const v = S.view;
  const nav = (label, view, count, extra) => h('button', { class: 'nav' + (JSON.stringify(v) === JSON.stringify(view) ? ' active' : ''), onclick: () => go(view) },
    h('span', {}, label), count != null && h('span', { class: 'count' }, count), extra);
  const s = el.side; s.replaceChildren(
    h('div', { class: 'brand' }, h('img', { class: 'logo', src: 'icon.svg', alt: '', width: 24, height: 24 }), 'Vaultly'),
    nav('All items', { k: 'all' }, live.length),
    nav('★ Favorites', { k: 'fav' }, live.filter((i) => i.data.fav).length),
    h('h4', {}, 'Types'),
    ...Object.entries(TYPES).filter(([t]) => t === 'login' || live.some((i) => i.data.type === t)).map(([t, l]) => nav(l, { k: 'type', t }, live.filter((i) => i.data.type === t).length)),
    ...(() => { const tags = new Map(); live.forEach((i) => tagsOf(i.data).forEach((t) => tags.set(t, (tags.get(t) || 0) + 1))); return tags.size ? [h('h4', {}, 'Tags'), ...[...tags].sort((a, b) => a[0].localeCompare(b[0])).map(([t, n]) => nav('#' + t, { k: 'tag', t }, n))] : []; })(),
    h('h4', {}, 'Vaults'),
    ...S.vaults.map((x) => nav(x.name, { k: 'vault', id: x.id }, live.filter((i) => i.vid === x.id).length, x.member_count > 1 || !x.mine ? h('span', { class: 'count', title: (x.mine ? '' : 'Owners: ' + x.owners + ' · ') + x.member_count + ' members' }, '👥') : null)),
    ...S.pending.map((p) => h('div', { class: 'card' }, h('div', {}, '📨 Vault invitation'), h('div', { class: 'muted' }, `Invited by: ${p.creator || '?'} · Role: ${ROLES[p.role]} · Vault owners: ${p.owners || '?'}. Decline invitations from people you don\'t know. The contents stay inaccessible until you accept.`),
      h('div', { class: 'row' }, h('button', { class: 'small primary', onclick: async () => { try { await api('POST', `/vaults/${p.id}/accept`); await loadAll(); renderAll(); toast('Vault added'); } catch (e) { toast(errMsg(e)); } } }, 'Accept'),
        h('button', { class: 'small danger', onclick: async () => { try { await api('DELETE', `/vaults/${p.id}/members/${S.user.id}`); await loadAll(); renderAll(); } catch (e) { toast(errMsg(e)); } } }, 'Decline')))),
    h('button', { class: 'nav', onclick: newVaultDialog }, h('span', { class: 'muted' }, '+ New vault')),
    h('h4', {}, 'Tools'),
    nav('Security Scan', { k: 'monitor' }),
    nav('Trash', { k: 'trash' }, [...S.items.values()].filter((i) => i.trashed).length),
    h('button', { class: 'nav', onclick: () => openGenerator() }, 'Password generator'),
    nav('Send (share a secret)', { k: 'send' }),
    S.user.is_admin && nav('Admin', { k: 'admin' }),
    nav('Settings', { k: 'settings' }),
    h('a', { class: 'nav', href: 'help.html', target: '_blank', rel: 'noopener' }, 'Help'),
    h('div', { class: 'spacer' }),
    h('div', { class: 'muted', style: null }, S.user.email),
    h('button', { onclick: async () => { try { await api('POST', '/logout'); } catch { /* ignore */ } lock('Signed out.'); } }, '🔒 Lock'));
  el.shell.classList.toggle('wide', ['monitor', 'admin', 'settings', 'send'].includes(v.k));
}

function visible() {
  const v = S.view; const q = S.q.trim().toLowerCase();
  let l = [...S.items.values()].filter((i) => (v.k === 'trash' ? i.trashed : !i.trashed));
  if (v.k === 'fav') l = l.filter((i) => i.data.fav);
  if (v.k === 'type') l = l.filter((i) => i.data.type === v.t);
  if (v.k === 'vault') l = l.filter((i) => i.vid === v.id);
  if (v.k === 'tag') l = l.filter((i) => tagsOf(i.data).includes(v.t));
  if (q) l = l.filter((i) => [i.data.title, i.data.username, i.data.urls, i.data.notes, ...tagsOf(i.data).map((t) => '#' + t),
    ...Object.entries(i.data.x || {}).filter(([k]) => !(XFIELDS[i.data.type] || []).find(([f, , o]) => f === k && o?.secret)).map(([, x]) => x)].join(' ').toLowerCase().includes(q));
  return l.sort((a, b) => (a.data.title || '').localeCompare(b.data.title || ''));
}
function renderList() {
  const l = visible();
  el.items.replaceChildren(...(l.length ? l.map((i) => h('div', { class: 'item' + (S.sel === i.id ? ' sel' : ''), tabindex: 0, onclick: () => { S.sel = i.id; S.edit = null; renderList(); renderDetail(); }, onkeydown: (e) => e.key === 'Enter' && e.target.click() },
    h('div', { class: 'ico', style: null, ...{} }, (i.data.title || '?')[0].toUpperCase()),
    h('div', { class: 'grow' }, h('div', { class: 't' }, (i.data.fav ? '★ ' : '') + (i.data.title || '(untitled)')), h('div', { class: 's' }, subtitle(i.data)))))
    : [h('div', { class: 'empty' }, S.q ? 'No results.' : S.view.k === 'trash' ? 'Trash is empty.' : 'No items yet. Add one with +.')]));
  // colour the avatar via CSSOM (CSP forbids inline style attributes)
  [...el.items.querySelectorAll('.ico')].forEach((n, idx) => { n.style.background = `hsl(${hue(l[idx].data.title)} 55% 45%)`; });
}

function renderDetail() {
  clearInterval(S.tick);
  const k = S.view.k, d = el.detail;
  if (k === 'monitor') return d.replaceChildren(monitorView());
  if (k === 'admin') return d.replaceChildren(adminView());
  if (k === 'settings') return d.replaceChildren(settingsView());
  if (k === 'send') return d.replaceChildren(sendView());
  if (S.edit) return d.replaceChildren(editForm(S.edit));
  const it = S.sel && S.items.get(S.sel);
  if (!it) return d.replaceChildren(h('div', { class: 'empty' }, 'Select an item or create a new one.'));
  d.replaceChildren(itemView(it));
}

// ------------------------------------------------------------------ item view
function fieldRow(label, value, { secret = false, link = false, mono = false, area = false } = {}) {
  if (!value) return document.createDocumentFragment();   // empty: appends nothing (append(null) would print "null")
  let shown = !secret; const v = h('div', { class: 'v' + (mono ? ' mono' : '') + (area ? ' pre' : '') });
  const paint = () => { v.replaceChildren(!shown ? '••••••••••' : (link && safeUrl(value) ? h('a', { href: safeUrl(value), target: '_blank', rel: 'noopener noreferrer' }, value) : value)); };
  paint();
  return h('div', { class: 'field' }, h('div', { class: 'grow' }, h('div', { class: 'l' }, label), v),
    secret && h('button', { class: 'small', onclick: () => { shown = !shown; paint(); } }, '👁'),
    h('button', { class: 'small', onclick: () => copy(value, label + ' copied') }, 'Copy'));
}

function itemView(it) {
  const d = it.data, vault = vaultById(it.vid), w = canWrite(it.vid);
  const box = h('div', {},
    h('div', { class: 'row wrap' }, h('h2', { class: 'grow' }, (d.fav ? '★ ' : '') + (d.title || '(untitled)')),
      !it.trashed && w && h('button', { onclick: async () => { d.fav = !d.fav; await persist(it.vid, it, d); renderAll(); } }, d.fav ? '★' : '☆'),
      !it.trashed && w && h('button', { onclick: () => { S.edit = { item: it }; renderDetail(); } }, 'Edit'),
      !it.trashed && h('button', { title: 'Share this item with someone outside the team through an expiring link', onclick: () => { S.sendDraft = itemAsText(d); go({ k: 'send' }); } }, 'Send…'),
      !it.trashed && w && h('button', { class: 'danger', onclick: () => trash(it, true) }, 'Move to trash'),
      it.trashed && w && h('button', { onclick: () => trash(it, false) }, 'Restore'),
      it.trashed && w && h('button', { class: 'danger', onclick: () => hardDelete(it) }, 'Delete forever')),
    h('div', { class: 'muted' }, h('span', { class: 'chip tag' }, TYPES[d.type]), h('span', { class: 'chip tag' }, vault ? vault.name : '?'), !w && h('span', { class: 'chip' }, 'read-only'),
      ...tagsOf(d).map((t) => h('a', { href: '#', class: 'chip', onclick: (e) => { e.preventDefault(); go({ k: 'tag', t }); } }, '#' + t))));
  if (XFIELDS[d.type]) for (const [k, label, o = {}] of XFIELDS[d.type]) box.append(fieldRow(label, d.x?.[k], { secret: !!o.secret, mono: !!o.mono, area: !!o.area, link: !!o.link }));
  if (d.type === 'login') {
    box.append(fieldRow('Username', d.username), fieldRow('Password', d.password, { secret: true, mono: true }));
    if (d.password) { const s = C.strength(d.password); box.append(h('div', { class: 'muted' }, `Strength: ${s.label} (~${s.bits} bit)`, h('button', { class: 'small ghost', onclick: (e) => checkPwned(d.password, e.target) }, 'Breach check'))); }
    box.append(fieldRow('Website', d.urls, { link: true }));
    if (d.totp) box.append(totpBlock(d.totp));
  }
  if (d.type === 'card') {
    const c = d.card || {};
    box.append(fieldRow('Cardholder', c.holder), fieldRow('Card number', c.number, { secret: true, mono: true }), fieldRow('Expiry', c.exp), fieldRow('CVV', c.cvv, { secret: true, mono: true }), fieldRow('PIN', c.pin, { secret: true, mono: true }));
  }
  box.append(fieldRow('Notes', d.notes));
  for (const f of d.fields || []) box.append(fieldRow(f.k, f.v, { secret: f.secret }));
  if (d.history?.length) box.append(h('details', { class: 'card' }, h('summary', {}, `Password history (${d.history.length})`),
    ...d.history.map((x) => h('div', { class: 'row' }, h('span', { class: 'mono grow' }, x.p), h('span', { class: 'muted' }, new Date(x.t).toLocaleDateString('en-GB')), h('button', { class: 'small', onclick: () => copy(x.p) }, 'Copy')))));
  box.append(h('p', { class: 'muted' }, 'Last changed: ' + fmtDate(it.updated_at)));
  return box;
}

function totpBlock(secret) {
  const code = h('span', { class: 'totp' }, '······'), bar = h('i'), raw = { v: '' };
  const tick = async () => {
    try { const r = await C.totp(secret); raw.v = r.code; code.textContent = r.code.slice(0, 3) + ' ' + r.code.slice(3); bar.style.width = (r.remaining / r.period * 100) + '%'; }
    catch { code.textContent = 'Invalid TOTP key'; }
  };
  tick(); S.tick = setInterval(tick, 1000);
  return h('div', { class: 'field' }, h('div', { class: 'grow' }, h('div', { class: 'l' }, 'One-time code (2FA)'), code, h('div', { class: 'bar' }, bar)),
    h('button', { class: 'small', onclick: () => copy(raw.v, 'Code copied') }, 'Copy'));
}

async function checkPwned(pw, btn) {
  btn.textContent = '…';
  try { const n = await C.pwnedCount(pw); btn.replaceWith(h('span', { class: n ? 'err' : 'ok' }, n ? ` ⚠ ${n.toLocaleString('en-US')} breaches — change it!` : ' ✓ Not found in known breaches')); }
  catch { btn.textContent = 'Could not check'; }
}

// ------------------------------------------------------------------ mutations
async function persist(vid, existing, data) {
  const v = vaultById(vid); if (!v?.key) throw new Error('No vault key');
  const blob = await C.encJSON(v.key, data);
  let r;
  try { r = existing ? await api('PUT', `/vaults/${vid}/items/${existing.id}`, { data: blob, rev: existing.rev }) : await api('POST', `/vaults/${vid}/items`, { data: blob }); }
  catch (e) { toast(errMsg(e)); throw e; }
  const it = { id: r.id, vid, data, trashed: r.trashed, rev: r.rev, updated_at: r.updated_at };
  S.items.set(it.id, it); return it;
}
async function trash(it, flag) {
  try {
    const r = await api('PUT', `/vaults/${it.vid}/items/${it.id}`, { data: await C.encJSON(vaultById(it.vid).key, it.data), rev: it.rev, trashed: flag });
    it.trashed = r.trashed; it.rev = r.rev; it.updated_at = r.updated_at; S.sel = null; renderAll(); toast(flag ? 'Moved to trash' : 'Restored');
  } catch (e) { toast(errMsg(e)); }
}
async function hardDelete(it) {
  if (!confirm('This item will be permanently deleted. Are you sure?')) return;
  try { await api('DELETE', `/vaults/${it.vid}/items/${it.id}`); S.items.delete(it.id); S.sel = null; renderAll(); } catch (e) { toast(errMsg(e)); }
}

// ------------------------------------------------------------------ edit form
function newItem(type = 'login') {
  const writable = S.vaults.filter((v) => ['owner', 'editor'].includes(v.role) && v.key);
  if (!writable.length) return toast('You have no vault you can write to');
  if (['monitor', 'admin', 'settings'].includes(S.view.k)) S.view = { k: 'all' };
  S.sel = null; S.edit = { item: null, type, vid: S.view.k === 'vault' && canWrite(S.view.id) ? S.view.id : (writable.find((v) => v.mine) || writable[0]).id }; renderAll();
}

function editForm(ed) {
  const old = ed.item, d = old ? structuredClone(old.data) : { type: ed.type, fields: [], card: {}, created: Date.now() };
  let type = d.type;
  const wrap = h('div'); const refs = {};
  const input = (k, label, o = {}) => { refs[k] = o.area ? h('textarea', { value: o.v ?? '' }) : h('input', { type: o.type || 'text', value: o.v ?? '', autocomplete: 'off', spellcheck: 'false' }); return [h('label', {}, label), refs[k]]; };
  const draw = () => {
    const vaultSel = h('select', { disabled: !!old, onchange: (e) => { ed.vid = e.target.value; } },
      S.vaults.filter((v) => v.key && ['owner', 'editor'].includes(v.role)).map((v) => h('option', { value: v.id, selected: v.id === (old ? old.vid : ed.vid) }, v.name)));
    const typeSel = h('select', { disabled: !!old, onchange: (e) => { snapshot(); type = e.target.value; d.type = type; draw(); } },
      Object.entries(TYPES).map(([t, l]) => h('option', { value: t, selected: t === type }, l)));
    const fieldsBox = h('div'); const rows = [];
    const addRow = (f = { k: '', v: '', secret: false }) => {
      const k = h('input', { placeholder: 'Field name', value: f.k }), v = h('input', { placeholder: 'Value', value: f.v }), s = h('input', { type: 'checkbox', checked: f.secret, title: 'Secret' });
      const row = h('div', { class: 'row' }, k, v, h('label', { class: 'row' }, s, 'secret'), h('button', { type: 'button', class: 'small', onclick: () => { rows.splice(rows.indexOf(r), 1); row.remove(); } }, '✕'));
      const r = { k, v, s }; rows.push(r); fieldsBox.append(row);
    };
    refs.rows = rows;
    const pwBar = h('div', { class: 'bar' }, h('i')), pwTxt = h('div', { class: 'muted' });
    const parts = [h('h2', {}, old ? 'Edit item' : 'New item'),
      h('div', { class: 'kv' }, h('div', {}, h('label', {}, 'Type'), typeSel), h('div', {}, h('label', {}, 'Vault'), vaultSel)),
      input('title', 'Title', { v: d.title })];
    if (type === 'login') {
      parts.push(input('username', 'Username / email', { v: d.username }));
      parts.push(...input('password', 'Password', { v: d.password, type: 'text' }));
      refs.password.classList.add('mono');
      const upd = () => { const s = C.strength(refs.password.value); pwBar.firstChild.className = 's' + s.level; pwBar.firstChild.style.width = Math.min(100, s.bits) + '%'; pwTxt.textContent = s.label ? `${s.label} · ~${s.bits} bit` : ''; };
      refs.password.addEventListener('input', upd); upd();
      parts.push(pwBar, pwTxt, h('button', { type: 'button', class: 'small', onclick: () => openGenerator((p) => { refs.password.value = p; upd(); }) }, '🎲 Generate'));
      parts.push(input('urls', 'Website', { v: d.urls }), input('totp', '2FA key (base32 or otpauth://)', { v: d.totp }));
    }
    if (type === 'card') {
      const c = d.card || {};
      parts.push(input('holder', 'Cardholder', { v: c.holder }), input('number', 'Card number', { v: c.number }), input('exp', 'Expiry (MM/YY)', { v: c.exp }), input('cvv', 'CVV', { v: c.cvv }), input('pin', 'PIN', { v: c.pin }));
    }
    if (XFIELDS[type]) for (const [k, label, o = {}] of XFIELDS[type]) {
      parts.push(input('x_' + k, label, { v: d.x?.[k], area: !!o.area }));
      if (o.mono) refs['x_' + k].classList.add('mono');
      if (o.secret && !o.area && (k === 'password' || k === 'pin' || k === 'passphrase')) parts.push(h('button', { type: 'button', class: 'small', onclick: () => openGenerator((p) => { refs['x_' + k].value = p; }) }, '🎲 Generate'));
    }
    parts.push(input('tags', 'Tags (comma separated, e.g. finance, website)', { v: tagsOf(d).join(', ') }));
    parts.push(input('notes', 'Notes', { v: d.notes, area: true }), h('label', {}, 'Custom fields'), fieldsBox,
      h('button', { type: 'button', class: 'small', onclick: () => addRow() }, '+ Add field'),
      h('div', { class: 'row', class2: null }, h('button', { class: 'primary', type: 'submit' }, 'Save'), h('button', { type: 'button', onclick: () => { S.edit = null; renderDetail(); } }, 'Cancel')));
    (d.fields || []).forEach(addRow);
    const form = h('form', { onsubmit: async (e) => {
      e.preventDefault(); snapshot();
      if (!d.title.trim()) return toast('Title is required');
      try {
        if (type === 'login' && old && old.data.password && old.data.password !== d.password) {
          d.history = [{ p: old.data.password, t: Date.now() }, ...(old.data.history || [])].slice(0, 5); d.pw_changed = Date.now();
        } else if (type === 'login' && !old) d.pw_changed = Date.now();
        const it = await persist(old ? old.vid : ed.vid, old, d);
        S.edit = null; S.sel = it.id; renderAll(); toast('Saved');
      } catch { /* toast shown */ }
    } }, ...parts);
    wrap.replaceChildren(form);
    refs.title.focus();
  };
  const snapshot = () => {
    const g = (k) => (refs[k] ? refs[k].value : undefined);
    d.title = g('title') ?? d.title ?? '';
    if (type === 'login') { d.username = g('username'); d.password = g('password'); d.urls = g('urls'); d.totp = g('totp'); }
    if (type === 'card') d.card = { holder: g('holder'), number: g('number'), exp: g('exp'), cvv: g('cvv'), pin: g('pin') };
    if (XFIELDS[type]) { d.x = {}; for (const [k] of XFIELDS[type]) { const val = g('x_' + k); if (val) d.x[k] = val; } }
    if (refs.tags) d.tags = [...new Set(refs.tags.value.split(',').map((t) => t.trim().replace(/^#/, '').slice(0, 40)).filter(Boolean))].slice(0, 20);
    d.notes = g('notes'); d.fav = !!d.fav;
    d.fields = refs.rows.filter((r) => r.k.value.trim()).map((r) => ({ k: r.k.value.trim(), v: r.v.value, secret: r.s.checked }));
  };
  draw(); return wrap;
}

// ------------------------------------------------------------------ generator
let WORDS = null;
async function words() { if (!WORDS) WORDS = C.parseWordlist(await (await fetch('vendor/eff_large_wordlist.txt')).text()); return WORDS; }
function openGenerator(onUse) {
  const o = { mode: localStorage.getItem('vaultly.genmode') || 'chars', length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true, count: 5, sep: '-', capitalize: true, number: true };
  const out = h('div', { class: 'genout mono' }), meta = h('div', { class: 'muted' }), opts = h('div');
  const gen = async () => {
    const p = o.mode === 'words' ? C.passphrase(await words(), o) : C.generatePassword(o); out.textContent = p;
    const bits = o.mode === 'words' ? Math.round(o.count * Math.log2(7776) + (o.number ? Math.log2(10 * o.count) : 0)) : C.strength(p).bits;
    meta.textContent = `~${bits} bit` + (o.mode === 'words' ? ' · easy to type and remember' : '');
  };
  const cb = (k, l) => h('label', {}, h('input', { type: 'checkbox', checked: o[k], onchange: (e) => { o[k] = e.target.checked; gen(); } }), l);
  const drawOpts = () => {
    if (o.mode === 'words') {
      const cnt = h('b', {}, String(o.count));
      opts.replaceChildren(h('label', {}, 'Words: ', cnt), h('input', { type: 'range', min: 3, max: 10, value: o.count, oninput: (e) => { o.count = +e.target.value; cnt.textContent = o.count; gen(); } }),
        h('div', { class: 'opts' }, h('label', {}, 'Separator ', h('select', { onchange: (e) => { o.sep = e.target.value; gen(); } }, [['-', '-'], [' ', 'space'], ['.', '.'], ['_', '_'], ['', 'none']].map(([v, l]) => h('option', { value: v, selected: o.sep === v }, l)))),
          cb('capitalize', 'Capitalise'), cb('number', 'Add a digit')));
    } else {
      const lenL = h('b', {}, String(o.length));
      opts.replaceChildren(h('label', {}, 'Length: ', lenL), h('input', { type: 'range', min: 8, max: 64, value: o.length, oninput: (e) => { o.length = +e.target.value; lenL.textContent = o.length; gen(); } }),
        h('div', { class: 'opts' }, cb('lower', 'a-z'), cb('upper', 'A-Z'), cb('digits', '0-9'), cb('symbols', '!@#'), cb('avoidAmbiguous', 'Exclude look-alike characters')));
    }
  };
  const modeSel = h('div', { class: 'row' }, ...[['chars', 'Random characters'], ['words', 'Words (passphrase)']].map(([m, l]) => h('label', {}, h('input', { type: 'radio', name: 'genmode', checked: o.mode === m, onchange: () => { o.mode = m; localStorage.setItem('vaultly.genmode', m); drawOpts(); gen(); } }), l)));
  const d = modal('Password generator', modeSel, out, meta, opts,
    h('div', { class: 'row' }, h('button', { onclick: gen }, '↻ Regenerate'), h('button', { onclick: () => copy(out.textContent) }, 'Copy'),
      onUse && h('button', { class: 'primary', onclick: () => { onUse(out.textContent); d.close(); } }, 'Use'), h('button', { onclick: () => d.close() }, 'Close')));
  drawOpts(); gen();
}

// ------------------------------------------------------------------ Send
function itemAsText(d) {
  const lines = [d.title || ''];
  if (d.type === 'login') { if (d.urls) lines.push('Website: ' + d.urls); if (d.username) lines.push('Username: ' + d.username); if (d.password) lines.push('Password: ' + d.password); }
  if (d.type === 'card') { const c = d.card || {}; lines.push(...[['Cardholder', c.holder], ['Number', c.number], ['Expiry', c.exp], ['CVV', c.cvv]].filter((x) => x[1]).map((x) => x.join(': '))); }
  if (XFIELDS[d.type]) for (const [k, label] of XFIELDS[d.type]) if (d.x?.[k]) lines.push(`${label}: ${d.x[k]}`);
  if (d.notes) lines.push('', d.notes);
  return lines.join('\n');
}

function sendView() {
  const text = h('textarea', { rows: 6, value: S.sendDraft || '', placeholder: 'The secret to share, e.g. a password and its username' }); S.sendDraft = '';
  const file = h('input', { type: 'file' });
  const exp = h('select', {}, [[1, '1 hour'], [24, '1 day'], [72, '3 days'], [168, '7 days'], [720, '30 days']].map(([v, l]) => h('option', { value: v, selected: v === 24 }, l)));
  const views = h('select', {}, [[1, '1 view'], [2, '2 views'], [5, '5 views'], [10, '10 views'], [0, 'unlimited']].map(([v, l]) => h('option', { value: v }, l)));
  const pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Optional: tell the recipient separately (phone)' });
  const note = h('input', { placeholder: 'Your own label, e.g. "WiFi for the accountant" (not shown to the recipient)', maxlength: 200 });
  const out = h('div'), list = h('div');
  const drawList = async () => {
    try {
      const rows = await api('GET', '/sends');
      list.replaceChildren(rows.length ? h('table', {}, h('tr', {}, h('th', {}, 'Label'), h('th', {}, 'Created'), h('th', {}, 'Expires'), h('th', {}, 'Views'), h('th')),
        ...rows.map((r) => h('tr', {}, h('td', {}, r.note || h('span', { class: 'muted' }, '(no label)'), r.has_password ? ' 🔑' : ''), h('td', {}, fmtDate(r.created)), h('td', {}, fmtDate(r.expires)),
          h('td', {}, `${r.views}${r.max_views ? ' / ' + r.max_views : ''}`),
          h('td', {}, h('button', { class: 'small danger', onclick: async () => { await api('DELETE', '/sends/' + r.id); drawList(); } }, 'Delete')))))
        : h('p', { class: 'muted' }, 'No active links.'));
    } catch (e) { list.replaceChildren(h('p', { class: 'err' }, errMsg(e))); }
  };
  const create = h('button', { class: 'primary', onclick: async () => {
    out.replaceChildren(); create.disabled = true;
    try {
      let obj;
      if (file.files[0]) {
        const f = file.files[0]; if (f.size > 10 * 1024 * 1024) throw new Error('Files up to 10 MB.');
        obj = { kind: 'file', name: f.name, type: f.type || 'application/octet-stream', data: C.b64big(await f.arrayBuffer()), text: text.value };
      } else {
        if (!text.value.trim()) throw new Error('Write the secret or choose a file.');
        obj = { kind: 'text', text: text.value };
      }
      const { enc, key } = await C.sendEncrypt(obj);
      const r = await api('POST', '/sends', { enc, expire_hours: +exp.value, max_views: +views.value || null, password: pw.value || null, note: note.value });
      const link = `${location.origin}/send.html#${r.id}.${key}`;
      text.value = ''; file.value = ''; pw.value = ''; note.value = '';
      out.replaceChildren(h('div', { class: 'card' }, h('b', {}, 'Link created. Copy it now: it cannot be shown again (the key is not stored anywhere).'),
        h('div', { class: 'row' }, h('input', { value: link, readonly: true, class: 'mono grow' }), h('button', { class: 'primary', onclick: () => copy(link, 'Link copied') }, 'Copy'))));
      drawList();
    } catch (e) { out.replaceChildren(h('p', { class: 'err' }, errMsg(e))); }
    create.disabled = false;
  } }, 'Create link');
  drawList();
  return h('div', {}, h('h2', {}, 'Send'),
    h('p', { class: 'muted' }, 'Share a password, note or file with someone who has no Vaultly account. It is encrypted in your browser; the key is only inside the link, so the server cannot read it. The link stops working after the time or number of views you choose.'),
    h('div', { class: 'card' }, h('label', {}, 'Text'), text, h('label', {}, 'or a file (up to 10 MB)'), file,
      h('div', { class: 'kv' }, h('div', {}, h('label', {}, 'Expires after'), exp), h('div', {}, h('label', {}, 'Can be opened'), views)),
      h('label', {}, 'Password (optional)'), pw, h('label', {}, 'Label'), note, create, out),
    h('div', { class: 'card' }, h('h3', {}, 'Your active links'), list));
}

// ------------------------------------------------------------------ vaults / sharing
function newVaultDialog() {
  const name = h('input', { placeholder: 'e.g. Finance, Social media accounts' });
  const d = modal('New vault', h('p', { class: 'muted' }, 'You can share vaults with your teammates. Every vault has its own encryption key.'), name,
    h('div', { class: 'row' }, h('button', { class: 'primary', onclick: async () => {
      if (!name.value.trim()) return;
      try { const id = await createVault(name.value.trim()); await loadAll(); d.close(); go({ k: 'vault', id }); } catch (e) { toast(errMsg(e)); }
    } }, 'Create'), h('button', { onclick: () => d.close() }, 'Cancel')));
  name.focus();
}

async function rotateVault(v) {
  const members = await api('GET', `/vaults/${v.id}/members`);
  const raw = await api('GET', `/vaults/${v.id}/items`);
  const nk = await C.newVaultKey();
  const items = []; for (const it of raw) items.push({ id: it.id, data: await C.encJSON(nk, await C.decJSON(v.key, it.data)) });
  const wrapped = {}; for (const m of members) wrapped[m.user_id] = await C.wrapVaultKey(nk, m.public_key);
  await api('POST', `/vaults/${v.id}/rotate`, { enc_name: await C.encJSON(nk, { name: v.name }), wrapped_keys: wrapped, items, expect_members: members.map((m) => m.user_id) });
  v.key = nk; await loadAll();
}

async function vaultDialog(v) {
  const d = modal('Vault: ' + v.name); const body = h('div'); d.append(body);
  const draw = async () => {
    let members = []; try { members = await api('GET', `/vaults/${v.id}/members`); } catch (e) { return body.replaceChildren(h('p', { class: 'err' }, errMsg(e))); }
    const owner = v.role === 'owner';
    const email = h('input', { type: 'email', placeholder: 'Teammate\'s email' }); const role = h('select', {}, Object.entries(ROLES).map(([k, l]) => h('option', { value: k, selected: k === 'editor' }, l)));
    const found = h('div', { class: 'muted' });
    const table = h('table', {}, h('tr', {}, h('th', {}, 'Member'), h('th', {}, 'Role'), h('th')),
      ...members.map((m) => h('tr', {}, h('td', {}, m.name, h('div', { class: 'muted' }, m.email + (m.status === 'pending' ? ' · invitation pending' : ''))),
        h('td', {}, owner ? h('select', { onchange: async (e) => { try { await api('PUT', `/vaults/${v.id}/members/${m.user_id}`, { role: e.target.value }); await loadAll(); draw(); renderAll(); } catch (x) { toast(errMsg(x)); draw(); } } },
          Object.entries(ROLES).map(([k, l]) => h('option', { value: k, selected: k === m.role }, l))) : ROLES[m.role]),
        h('td', {}, (owner || m.user_id === S.user.id) && h('button', { class: 'small danger', onclick: async () => {
          if (!confirm(m.user_id === S.user.id ? 'Do you want to leave this vault?' : `Remove ${m.email} from this vault? The vault key will be rotated.`)) return;
          try {
            await api('DELETE', `/vaults/${v.id}/members/${m.user_id}`);
            if (m.user_id === S.user.id) { await loadAll(); d.close(); return go({ k: 'all' }); }
            toast('Rotating key…'); await rotateVault(v); toast('Member removed, key rotated'); draw(); renderAll();
          } catch (x) { toast(errMsg(x)); }
        } }, m.user_id === S.user.id ? 'Leave' : 'Remove')))));
    const parts = [h('h4', {}, 'Members'), table];
    if (owner) parts.push(h('h4', {}, 'Add member'), h('div', { class: 'row' }, email, role), found,
      h('button', { class: 'primary', onclick: async () => {
        try {
          const u = await api('GET', '/users/lookup?email=' + encodeURIComponent(email.value));
          const fp = await C.fingerprint(u.public_key);
          if (!confirm(`${u.name} <${u.email}>\nFingerprint: ${fp}\n\nGrant this person access to the vault? (You can verify the fingerprint with them.)`)) return;
          await api('POST', `/vaults/${v.id}/members`, { user_id: u.id, role: role.value, wrapped_key: await C.wrapVaultKey(v.key, u.public_key) });
          await loadAll(); renderAll(); draw(); toast('Invitation sent; access starts once they accept');
        } catch (e) { found.textContent = errMsg(e); found.className = 'err'; }
      } }, 'Add'),
      h('h4', {}, 'Vault settings'),
      h('div', { class: 'row' }, h('button', { onclick: async () => { const n = prompt('New name', v.name); if (!n) return; await api('PUT', `/vaults/${v.id}`, { enc_name: await C.encJSON(v.key, { name: n }) }); await loadAll(); renderAll(); d.close(); } }, 'Rename'),
        h('button', { onclick: () => snapshotsDialog(v) }, 'Snapshots'),
        h('button', { onclick: async () => { const rows = await api('GET', `/vaults/${v.id}/audit`); const dd = modal('Activity log', h('div', { class: 'items' }, h('table', {}, rows.map((r) => h('tr', {}, h('td', {}, fmtDate(r.ts)), h('td', {}, r.email || '-'), h('td', {}, r.action))))), h('button', { onclick: () => dd.close() }, 'Close')); } }, 'Activity log'),
        h('button', { class: 'danger', onclick: async () => { if (!confirm('The vault and ALL its items will be deleted for every member!')) return; await api('DELETE', `/vaults/${v.id}`); await loadAll(); d.close(); go({ k: 'all' }); } }, 'Delete vault')));
    parts.push(h('div', { class: 'row' }, h('button', { onclick: () => d.close() }, 'Close')));
    body.replaceChildren(...parts);
  };
  draw();
}

async function snapshotsDialog(v) {
  const body = h('div');
  const d = modal('Snapshots: ' + v.name, h('p', { class: 'muted' }, 'The server keeps an encrypted copy of this vault once a day (14 days) and before every restore. Restoring brings every item back to its state at that time, including deleted ones; items added later are kept. Rotating the key (after removing a member) clears older snapshots.'), body,
    h('div', { class: 'row' }, h('button', { onclick: () => d.close() }, 'Close')));
  try {
    const rows = await api('GET', `/vaults/${v.id}/snapshots`);
    body.replaceChildren(rows.length ? h('table', {}, rows.map((r) => h('tr', {}, h('td', {}, fmtDate(r.at)), h('td', { class: 'muted' }, r.reason), h('td', {}, `${r.count} items`),
      h('td', {}, h('button', { class: 'small', onclick: async (e) => {
        if (!confirm(`Restore "${v.name}" to ${fmtDate(r.at)}? Every member sees the change. The current state is saved as a snapshot first.`)) return;
        try { const x = await api('POST', `/vaults/${v.id}/snapshots/${r.id}/restore`); await loadAll(); renderAll(); d.close(); toast(`${x.restored} item(s) restored`); } catch (er) { toast(errMsg(er)); }
      } }, 'Restore'))))) : h('p', { class: 'muted' }, 'No snapshot yet: the first one is made before the first change of the day.'));
  } catch (e) { body.replaceChildren(h('p', { class: 'err' }, errMsg(e))); }
}

// ------------------------------------------------------------------ monitor
function monitorView() {
  const logins = liveItems().filter((i) => i.data.type === 'login' && i.data.password);
  const byPw = new Map(); logins.forEach((i) => byPw.set(i.data.password, [...(byPw.get(i.data.password) || []), i]));
  const weak = logins.filter((i) => C.strength(i.data.password).bits < 50);
  const reused = [...byPw.values()].filter((g) => g.length > 1).flat();
  const old = logins.filter((i) => Date.now() - (i.data.pw_changed || i.data.created || Date.now()) > 365 * 864e5);
  const no2fa = logins.filter((i) => i.data.urls && !i.data.totp);
  const open = (i) => { S.view = { k: 'all' }; S.sel = i.id; renderAll(); };
  const section = (title, hint, list) => h('div', { class: 'card' }, h('h3', {}, `${title} `, h('span', { class: list.length ? 'chip warn' : 'chip ok' }, list.length)), h('div', { class: 'muted' }, hint),
    ...list.slice(0, 50).map((i) => h('div', { class: 'row' }, h('a', { href: '#', onclick: (e) => { e.preventDefault(); open(i); } }, i.data.title), h('span', { class: 'muted' }, i.data.username || ''))));
  const breach = h('div', { class: 'card' }, h('h3', {}, 'Breach check (Have I Been Pwned)'), h('div', { class: 'muted' }, 'Only the first 5 characters of each password\'s SHA-1 hash are sent; your passwords never leave your device.'));
  const res = h('div'); const go1 = h('button', { class: 'primary', onclick: async () => {
    go1.disabled = true; res.replaceChildren(); let n = 0;
    for (const [pw, group] of byPw) {
      go1.textContent = `Checking… ${++n}/${byPw.size}`;
      try { if (!S.pwned.has(pw)) S.pwned.set(pw, await C.pwnedCount(pw)); } catch { go1.textContent = 'Network error'; go1.disabled = false; return; }
      if (S.pwned.get(pw)) group.forEach((i) => res.append(h('div', { class: 'err' }, `⚠ ${i.data.title} — ${S.pwned.get(pw).toLocaleString('en-US')} breaches`)));
    }
    go1.textContent = 'Check again'; go1.disabled = false; if (!res.children.length) res.append(h('div', { class: 'ok' }, '✓ None of your passwords were found in known breaches.'));
  } }, 'Check all passwords');
  breach.append(go1, res);
  return h('div', {}, h('h2', {}, 'Security Scan'), h('p', { class: 'muted' }, `${logins.length} login items scanned (all analysis happens in your browser).`),
    breach, section('Weak passwords', 'Passwords under 50 bits', weak), section('Reused passwords', 'Same password used in several items', reused),
    section('Passwords older than 1 year', 'Not changed for a long time', old), section('No 2FA configured', 'Items with a website but no 2FA code', no2fa));
}

// ------------------------------------------------------------------ admin
function adminView() {
  const box = h('div', {}, h('h2', {}, 'Admin')); const body = h('div'); box.append(body);
  const draw = async () => {
    try {
      const [users, invites, audit] = await Promise.all([api('GET', '/admin/users'), api('GET', '/admin/invites'), api('GET', '/admin/audit')]);
      const email = h('input', { type: 'email', placeholder: 'Optional: only this email may use it' });
      body.replaceChildren(
        h('div', { class: 'card' }, h('h3', {}, 'Invitations'), h('p', { class: 'muted' }, 'Sign-up is by invite code only. Codes are valid for 7 days and single-use.'),
          h('div', { class: 'row' }, email, h('button', { class: 'primary', onclick: async () => {
            const r = await api('POST', '/admin/invites', { email: email.value || null }); const link = `${location.origin}/#invite=${r.code}`;
            await copy(link, 'Invite link copied'); draw();
          } }, 'Create invite')),
          ...invites.map((i) => h('div', { class: 'row' }, h('span', { class: 'mono grow' }, `${location.origin}/#invite=${i.code}`, i.email ? ` (${i.email})` : ''),
            h('button', { class: 'small', onclick: () => copy(`${location.origin}/#invite=${i.code}`) }, 'Copy'), h('button', { class: 'small danger', onclick: async () => { await api('DELETE', '/admin/invites/' + i.code); draw(); } }, 'Cancel')))),
        h('div', { class: 'card' }, h('h3', {}, 'Users'), h('table', {}, users.map((u) => h('tr', {},
          h('td', {}, u.name, h('div', { class: 'muted' }, u.email)), h('td', {}, u.is_admin ? 'Admin' : 'Member', u.disabled ? ' · disabled' : '', u.totp ? ' · 2FA' : ''),
          h('td', {}, u.id !== S.user.id && h('button', { class: 'small', onclick: async () => { await api('POST', `/admin/users/${u.id}/disable?disable=${!u.disabled}`); draw(); } }, u.disabled ? 'Enable' : 'Disable'),
            u.id !== S.user.id && h('button', { class: 'small', onclick: async () => { try { await api('POST', `/admin/users/${u.id}/admin?admin=${!u.is_admin}`); draw(); } catch (e) { toast(errMsg(e)); } } }, u.is_admin ? 'Remove admin' : 'Make admin'),
            u.totp && u.id !== S.user.id && h('button', { class: 'small', title: 'For someone who lost both phone and recovery codes', onclick: () => {
              const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Your master password' }), out = h('div', { class: 'err' });
              const d = modal('Reset 2FA for ' + u.email, h('p', { class: 'muted' }, 'Do this only after confirming their identity (e.g. in person or by phone). They are signed out and can sign in with their master password alone. Their passwords stay protected. The member sees this in their account activity.'), pw, out,
                h('div', { class: 'row' }, h('button', { class: 'danger', onclick: async () => { try { await api('POST', `/admin/users/${u.id}/reset-2fa`, { auth: await masterAuth(pw.value) }); d.close(); toast('2FA reset'); draw(); } catch (e) { out.textContent = errMsg(e); } } }, 'Reset 2FA'), h('button', { onclick: () => d.close() }, 'Cancel')));
              pw.focus();
            } }, 'Reset 2FA'))))),
          h('p', { class: 'muted' }, 'After disabling a user, vault owners should also remove them from shared vaults (this rotates the vault key).')),
        h('div', { class: 'card' }, h('h3', {}, 'Recent activity'), h('table', {}, audit.slice(0, 100).map((r) => h('tr', {}, h('td', {}, fmtDate(r.ts)), h('td', {}, r.email || '-'), h('td', {}, r.action, r.detail && r.action.startsWith('user.') ? ' ' + r.detail : ''))))));
    } catch (e) { body.replaceChildren(h('p', { class: 'err' }, errMsg(e))); }
  };
  draw(); return box;
}

// ------------------------------------------------------------------ settings, import/export
function parseCSV(text) {
  text = text.replace(/^﻿/, ''); const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); f = ''; if (row.some((x) => x)) rows.push(row); row = []; }
    else f += c;
  }
  row.push(f); if (row.some((x) => x)) rows.push(row); return rows;
}
const csvCell = (s) => { s = String(s ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

async function importCSV(file, vid, status) {
  const rows = parseCSV(await file.text()); if (rows.length < 2) throw new Error('Empty file');
  const hd = rows[0].map((x) => x.trim().toLowerCase());
  const col = (...names) => hd.findIndex((x) => names.includes(x));
  const ix = { title: col('name', 'title', 'label'), url: col('url', 'login_uri', 'website', 'uri', 'web site'), user: col('username', 'login_username', 'user', 'login_name', 'email'), pw: col('password', 'login_password'), notes: col('note', 'notes', 'extra'), totp: col('totp', 'login_totp', 'otpauth'), type: col('type') };
  if (ix.title < 0 || ix.pw < 0) throw new Error('Unrecognised columns (Chrome, Bitwarden, Proton Pass and 1Password CSVs are supported).');
  const g = (r, k) => (ix[k] >= 0 ? (r[ix[k]] || '').trim() : '');
  let n = 0; const list = rows.slice(1);
  for (const r of list) {
    const isNote = g(r, 'type') === 'note' || g(r, 'type') === 'securenote';
    const d = { type: isNote ? 'note' : 'login', title: g(r, 'title') || g(r, 'url') || 'Imported', username: g(r, 'user'), password: g(r, 'pw'), urls: g(r, 'url'), totp: g(r, 'totp'), notes: g(r, 'notes'), fields: [], card: {}, created: Date.now(), pw_changed: Date.now() };
    await persist(vid, null, d); status.textContent = `${++n}/${list.length} imported…`;
  }
  return n;
}

async function masterAuth(password) {   // re-derive the server "auth" value to confirm a sensitive change
  const pre = await api('GET', '/prelogin?email=' + encodeURIComponent(S.user.email));
  return (await C.deriveKeys(password, pre.salt, pre.iters)).auth;
}
let qrLoaded = null;
const loadQr = () => (qrLoaded ||= new Promise((ok, no) => { const sc = document.createElement('script'); sc.src = 'vendor/qrcode.min.js'; sc.onload = ok; sc.onerror = no; document.head.append(sc); }));
function codesBox(codes) {
  const txt = 'Vaultly recovery codes for ' + S.user.email + '\nEach code works once, instead of the 6-digit code.\n\n' + codes.join('\n') + '\n';
  return h('div', { class: 'card' }, h('b', {}, 'Recovery codes: save them now, they are shown only once.'), h('div', { class: 'mono pre' }, codes.join('\n')),
    h('div', { class: 'row' }, h('button', { onclick: () => copy(txt, 'Codes copied') }, 'Copy'),
      h('button', { onclick: () => { const a = h('a', { href: URL.createObjectURL(new Blob([txt], { type: 'text/plain' })), download: 'vaultly-recovery-codes.txt' }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); } }, 'Download .txt')));
}
function twofaCard() {
  const box = h('div', { class: 'card' }, h('h3', {}, 'Two-factor sign-in'));
  const body = h('div'); box.append(body);
  const pwIn = () => h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Master password' });
  const draw = async () => {
    const st = await api('GET', '/2fa/status'); const out = h('div', { class: 'err' });
    if (!st.on) {
      const p = pwIn();
      body.replaceChildren(h('p', { class: 'muted' }, 'Off. With it on, signing in also needs a code from an authenticator app (Google Authenticator, Aegis, 2FAS, Microsoft Authenticator…). Recommended: this server is reachable from the internet.'),
        p, out, h('button', { class: 'primary', onclick: async () => {
          try {
            const r = await api('POST', '/2fa/setup', { auth: await masterAuth(p.value) });
            const img = h('img', { alt: 'QR code', class: 'qr' }); loadQr().then(() => { const q = window.qrcode(0, 'M'); q.addData(r.uri); q.make(); img.src = q.createDataURL(5, 8); }).catch(() => img.remove());
            const code = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '6-digit code from the app' }); const o2 = h('div', { class: 'err' });
            body.replaceChildren(h('p', {}, '1. Scan this with your authenticator app (or type the key).'), img, h('div', { class: 'mono' }, r.secret.match(/.{1,4}/g).join(' ')),
              h('p', {}, '2. Enter the code the app shows:'), code, o2,
              h('div', { class: 'row' }, h('button', { class: 'primary', onclick: async () => {
                try { const x = await api('POST', '/2fa/enable', { code: code.value }); S.user.totp = true; body.replaceChildren(h('p', { class: 'ok' }, 'Two-factor sign-in is on.'), codesBox(x.recovery_codes), h('button', { onclick: draw }, 'Done')); }
                catch (e) { o2.textContent = errMsg(e); }
              } }, 'Turn on'), h('button', { onclick: draw }, 'Cancel')));
          } catch (e) { out.textContent = errMsg(e); }
        } }, 'Set up'));
    } else {
      const p = pwIn();
      body.replaceChildren(h('p', { class: 'ok' }, `On. ${st.recovery_left} unused recovery code(s) left.`), p, out,
        h('div', { class: 'row' }, h('button', { onclick: async () => { try { const x = await api('POST', '/2fa/recovery', { auth: await masterAuth(p.value) }); body.replaceChildren(codesBox(x.recovery_codes), h('button', { onclick: draw }, 'Done')); } catch (e) { out.textContent = errMsg(e); } } }, 'New recovery codes'),
          h('button', { class: 'danger', onclick: async () => { if (!confirm('Turn off two-factor sign-in?')) return; try { await api('POST', '/2fa/disable', { auth: await masterAuth(p.value) }); S.user.totp = false; draw(); } catch (e) { out.textContent = errMsg(e); } } }, 'Turn off')),
        h('p', { class: 'muted' }, 'Both actions ask for your master password.'));
    }
  };
  draw().catch((e) => body.replaceChildren(h('p', { class: 'err' }, errMsg(e))));
  return box;
}
function sessionsCard() {
  const box = h('div', { class: 'card' }, h('h3', {}, 'Signed-in devices')), body = h('div'), act = h('div');
  const draw = async () => {
    const rows = await api('GET', '/account/sessions');
    body.replaceChildren(h('table', {}, rows.map((r) => h('tr', {}, h('td', {}, r.agent || 'unknown', r.current ? h('span', { class: 'chip ok' }, 'this device') : null),
      h('td', { class: 'muted' }, r.ip || ''), h('td', { class: 'muted' }, 'active ' + (r.last_seen ? fmtDate(r.last_seen) : '?')),
      h('td', {}, !r.current && h('button', { class: 'small danger', onclick: async () => { await api('DELETE', '/account/sessions/' + r.id); draw(); } }, 'Sign out'))))),
      rows.length > 1 ? h('button', { onclick: async () => { const x = await api('DELETE', '/account/sessions'); toast(`${x.ended} other device(s) signed out`); draw(); } }, 'Sign out all other devices') : null);
    const a = await api('GET', '/account/activity');
    const label = { 'user.login': 'Signed in', 'user.login_failed': '⚠ Failed sign-in', 'user.register': 'Account created', 'user.password_change': 'Master password changed', 'user.2fa_on': '2FA turned on', 'user.2fa_off': '2FA turned off', 'user.2fa_new_codes': 'New recovery codes', 'user.2fa_recovery_used': 'Recovery code used', 'user.2fa_reset_by_admin': '2FA reset by an administrator', 'user.2fa_locked': '⚠ 2FA locked after wrong codes', 'user.sessions_end_all': 'Other devices signed out', 'user.session_end': 'A device was signed out', 'user.send_create': 'Send link created', 'user.send_opened': 'Send link opened' };
    act.replaceChildren(h('details', {}, h('summary', {}, `Account activity (${a.filter((x) => x.action === 'user.login_failed').length} failed sign-ins)`),
      h('table', {}, a.map((x) => h('tr', {}, h('td', {}, fmtDate(x.ts)), h('td', { class: x.action === 'user.login_failed' ? 'err' : '' }, label[x.action] || x.action), h('td', { class: 'muted' }, x.action.startsWith('user.send') ? '' : x.detail || ''))))));
  };
  draw().catch((e) => body.replaceChildren(h('p', { class: 'err' }, errMsg(e))));
  box.append(body, act); return box;
}
function backupCard() {
  const p1 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Backup password (12+ characters)' }), p2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Repeat' });
  const file = h('input', { type: 'file', accept: '.json' }), rpw = h('input', { type: 'password', placeholder: 'Backup password' }), out = h('div');
  const writable = S.vaults.filter((v) => v.key && ['owner', 'editor'].includes(v.role));
  const target = h('select', {}, writable.map((v) => h('option', { value: v.id }, v.name)));
  return h('div', { class: 'card' }, h('h3', {}, 'Encrypted backup'),
    h('p', { class: 'muted' }, 'A file with every item you can see (all vaults), encrypted with a password you choose. Keep it somewhere safe, e.g. a USB stick. It does not depend on this server or your account.'),
    p1, p2, h('button', { class: 'primary', onclick: async () => {
      out.className = 'err'; out.textContent = '';
      try {
        if (p1.value.length < 12) throw new Error('Backup password: at least 12 characters.'); if (p1.value !== p2.value) throw new Error('Passwords do not match.');
        const items = liveItems().map((i) => ({ vault: vaultById(i.vid)?.name || '', data: i.data }));
        const blob = await C.backupEncrypt(p1.value, { app: 'vaultly', at: Date.now(), by: S.user.email, items });
        const a = h('a', { href: URL.createObjectURL(new Blob([blob], { type: 'application/json' })), download: `vaultly-backup-${new Date().toISOString().slice(0, 10)}.json` }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
        p1.value = p2.value = ''; out.className = 'ok'; out.textContent = `Backup of ${items.length} items downloaded.`;
      } catch (e) { out.textContent = errMsg(e); }
    } }, 'Download encrypted backup'),
    h('h4', {}, 'Restore from a backup'), h('p', { class: 'muted' }, 'Adds the items of a backup file to one vault (nothing is overwritten).'),
    file, rpw, h('label', {}, 'Into vault'), target, h('button', { onclick: async () => {
      out.className = 'err'; out.textContent = '';
      try {
        if (!file.files[0]) throw new Error('Choose the backup file.');
        const b = await C.backupDecrypt(rpw.value, await file.files[0].text());
        let n = 0; for (const it of b.items || []) { if (it?.data && typeof it.data === 'object') { const d = { ...it.data }; delete d.history; await persist(target.value, null, d); n++; out.className = 'muted'; out.textContent = `${n}/${b.items.length}…`; } }
        out.className = 'ok'; out.textContent = `${n} items restored.`; renderSide();
      } catch (e) { out.className = 'err'; out.textContent = errMsg(e); }
    } }, 'Restore'), out);
}

function settingsView() {
  const minutes = h('select', { onchange: (e) => { localStorage.setItem('vaultly.autolock', e.target.value); armIdle(); toast('Saved'); } },
    [[1, '1 minute'], [5, '5 minutes'], [10, '10 minutes'], [30, '30 minutes'], [60, '1 hour'], [0, 'Never']].map(([v, l]) => h('option', { value: v, selected: +(localStorage.getItem('vaultly.autolock') || 10) === v }, l)));
  const fp = h('span', { class: 'mono' }, '…'); C.fingerprint(S.user.public_key).then((x) => { fp.textContent = x; });
  const cur = h('input', { type: 'password', autocomplete: 'current-password' }), n1 = h('input', { type: 'password', autocomplete: 'new-password' }), n2 = h('input', { type: 'password', autocomplete: 'new-password' }), pwOut = h('div');
  const file = h('input', { type: 'file', accept: '.csv' }), writable = S.vaults.filter((v) => v.key && ['owner', 'editor'].includes(v.role));
  const target = h('select', {}, writable.map((v) => h('option', { value: v.id }, v.name))), impOut = h('div', { class: 'muted' });
  return h('div', {}, h('h2', {}, 'Settings'),
    h('div', { class: 'card' }, h('h3', {}, 'Account'), h('div', {}, `${S.user.name} · ${S.user.email}`), h('div', { class: 'muted' }, 'Public-key fingerprint (verify it with the other person when sharing): ', fp)),
    h('div', { class: 'card' }, h('h3', {}, 'Auto-lock'), minutes),
    twofaCard(), sessionsCard(),
    h('div', { class: 'card' }, h('h3', {}, 'Vault management'), h('div', { class: 'row wrap' }, S.vaults.filter((v) => !v.broken).map((v) => h('button', { onclick: () => vaultDialog(v) }, `${v.name} (${ROLES[v.role]})`)))),
    h('div', { class: 'card' }, h('h3', {}, 'Change master password'), h('label', {}, 'Current'), cur, h('label', {}, 'New (at least 12 characters)'), n1, h('label', {}, 'New (repeat)'), n2, pwOut,
      h('button', { class: 'primary', onclick: async () => {
        pwOut.className = 'err'; pwOut.textContent = '';
        try {
          if (n1.value.length < 12 || C.strength(n1.value).level < 2) throw new Error('The new password is not strong enough.');
          if (n1.value !== n2.value) throw new Error('Passwords do not match.');
          const pre = await api('GET', '/prelogin?email=' + encodeURIComponent(S.user.email));
          const old = await C.deriveKeys(cur.value, pre.salt, pre.iters);
          const salt = C.randomSalt(), nw = await C.deriveKeys(n1.value, salt, C.ITERS);
          const encPriv = await C.rewrapPrivate(old.masterKey, nw.masterKey, S.user.enc_private_key);
          await api('POST', '/password', { old_auth: old.auth, new_auth: nw.auth, new_salt: salt, new_iters: C.ITERS, enc_private_key: encPriv });
          S.master = nw.masterKey; S.user.enc_private_key = encPriv; [cur, n1, n2].forEach((i) => { i.value = ''; });
          pwOut.className = 'ok'; pwOut.textContent = 'Master password changed. Other sessions were signed out.';
        } catch (e) { pwOut.textContent = errMsg(e); }
      } }, 'Change')),
    h('div', { class: 'card' }, h('h3', {}, 'Import'), h('div', { class: 'muted' }, 'CSV exports from Chrome, Bitwarden, Proton Pass, 1Password and similar.'), h('label', {}, 'Target vault'), target, h('label', {}, 'CSV file'), file, impOut,
      h('button', { onclick: async () => { if (!file.files[0]) return; try { const n = await importCSV(file.files[0], target.value, impOut); impOut.textContent = `${n} items imported.`; renderSide(); } catch (e) { impOut.className = 'err'; impOut.textContent = errMsg(e); } } }, 'Import')),
    backupCard(),
    h('div', { class: 'card' }, h('h3', {}, 'Export'), h('div', { class: 'muted' }, 'The file is UNENCRYPTED plain text. Delete it securely when you are done.'),
      h('button', { onclick: () => {
        if (!confirm('All your passwords will be written to an unencrypted CSV file. Continue?')) return;
        const lines = [['name', 'url', 'username', 'password', 'totp', 'note', 'type', 'vault'].join(',')];
        for (const i of liveItems()) lines.push([i.data.title, i.data.urls, i.data.username, i.data.password, i.data.totp, i.data.notes, i.data.type, vaultById(i.vid)?.name].map(csvCell).join(','));
        const a = h('a', { href: URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' })), download: 'vaultly-export.csv' }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      } }, 'Download CSV')));
}

if (location.hash.includes('invite=')) renderAuth('register'); else renderAuth();
