import * as C from './crypto.js';

const $app = document.getElementById('app');
const S = {
  token: null, user: null, master: null, priv: null,
  vaults: [], items: new Map(), view: { k: 'all' }, sel: null, q: '', edit: null,
  pwned: new Map(), tick: null, idle: null, pending: [],
};
const TYPES = { login: 'Giriş', note: 'Not', card: 'Kart' };
const ROLES = { owner: 'Sahip', editor: 'Düzenleyici', viewer: 'Görüntüleyici' };

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
    if (r.status === 401 && S.token) lock('Oturum süresi doldu, tekrar giriş yapın.');
    throw new Error(j && typeof j.detail === 'string' ? j.detail : 'Geçersiz istek (' + r.status + ')');
  }
  return j;
}

function modal(title, ...body) {
  const d = h('dialog', {}, h('h3', {}, title), ...body);
  d.addEventListener('close', () => d.remove());
  document.body.append(d); d.showModal(); return d;
}
let clipT;
async function copy(text, label = 'Kopyalandı') {
  try { await navigator.clipboard.writeText(text); toast(label + ' (30 sn sonra panodan silinir)'); }
  catch { toast('Kopyalama izni yok'); return; }
  clearTimeout(clipT); clipT = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000);
}
const hue = (s) => { let x = 0; for (const c of s || '?') x = (x * 31 + c.charCodeAt(0)) % 360; return x; };
const fmtDate = (t) => new Date(t * 1000).toLocaleString('tr-TR');
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
  const btn = h('button', { class: 'primary', type: 'submit' }, mode === 'setup' ? 'Yönetici hesabını oluştur' : reg ? 'Hesap oluştur' : 'Kasa\'yı aç');
  pw.addEventListener('input', () => {
    if (!reg) return; const s = C.strength(pw.value);
    meter.firstChild.className = 's' + s.level; meter.firstChild.style.width = Math.min(100, s.bits) + '%'; meterT.textContent = s.label ? `${s.label} · ~${s.bits} bit` : '';
  });
  const form = h('form', { class: 'auth', onsubmit: async (e) => {
    e.preventDefault(); out.textContent = ''; btn.disabled = true; btn.textContent = 'Anahtarlar türetiliyor…';
    try {
      if (reg) {
        if (pw.value.length < 12) throw new Error('Ana parola en az 12 karakter olmalı (uzun bir cümle idealdir).');
        if (C.strength(pw.value).level < 2) throw new Error('Ana parola çok zayıf.');
        if (pw.value !== pw2.value) throw new Error('Parolalar eşleşmiyor.');
        const salt = C.randomSalt(); const { masterKey, auth } = await C.deriveKeys(pw.value, salt, C.ITERS);
        const ident = await C.newIdentity(masterKey);
        const r = await api('POST', '/register', { email: email.value, name: name.value || email.value, salt, iters: C.ITERS, auth, ...ident, invite: mode === 'setup' ? null : inv.value.trim() });
        history.replaceState(null, '', location.pathname);
        await startSession(r, masterKey);
      } else {
        const pre = await api('GET', '/prelogin?email=' + encodeURIComponent(email.value));
        const { masterKey, auth } = await C.deriveKeys(pw.value, pre.salt, pre.iters);
        await startSession(await api('POST', '/login', { email: email.value, auth }), masterKey);
      }
    } catch (ex) { out.textContent = errMsg(ex); btn.disabled = false; btn.textContent = 'Tekrar dene'; }
  } },
    h('h1', {}, h('img', { class: 'logo', src: 'icon.svg', alt: '' }), 'Kasa'),
    h('p', { class: 'muted' }, mode === 'setup' ? 'İlk kurulum: bu hesap sistemin yöneticisi olacak.' : reg ? 'Davet koduyla ekibe katılın.' : 'Ekibinizin şifre kasası. Uçtan uca şifreli.'),
    h('label', {}, 'E-posta'), email,
    reg && [h('label', {}, 'Ad Soyad'), name],
    reg && mode !== 'setup' && [h('label', {}, 'Davet kodu'), inv],
    h('label', {}, 'Ana parola'), pw,
    reg && [meter, meterT, h('label', {}, 'Ana parola (tekrar)'), pw2,
      h('p', { class: 'muted' }, 'Ana parolanızı kimse sıfırlayamaz — sunucu da bilmez. Unutursanız verilerinize erişilemez; güvenli bir yere not alın.')],
    out, btn,
    mode !== 'setup' && h('p', { class: 'muted' }, reg ? 'Hesabın var mı? ' : 'Davet kodunuz var mı? ',
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); renderAuth(reg ? 'login' : 'register'); } }, reg ? 'Giriş yap' : 'Kayıt ol')));
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
  if (!list.length) { await createVault('Kişisel'); list = await api('GET', '/vaults'); }
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
    } catch { S.vaults.push({ id: v.id, name: '⚠ Çözülemeyen kasa', role: 'viewer', key: null, member_count: v.member_count, broken: true }); }
  }));
  S.vaults.sort((a, b) => a.name.localeCompare(b.name, 'tr'));
}

function armIdle() {
  const mins = +(localStorage.getItem('kasa.autolock') || 10);
  clearTimeout(S.idle); if (!mins || !S.token) return;
  S.idle = setTimeout(() => lock('Hareketsizlik nedeniyle kilitlendi.'), mins * 60000);
}
['click', 'keydown', 'mousemove'].forEach((ev) => document.addEventListener(ev, () => { if (S.token) armIdle(); }, { passive: true }));

// ------------------------------------------------------------------ shell
let el = {};
function buildShell() {
  el.side = h('nav', { class: 'side' });
  el.items = h('div', { class: 'items' });
  const search = h('input', { type: 'search', placeholder: 'Ara…', 'aria-label': 'Ara', oninput: (e) => { S.q = e.target.value; renderList(); } });
  el.list = h('section', { class: 'list' },
    h('div', { class: 'toolbar' }, search, h('button', { class: 'primary', onclick: () => newItem(), title: 'Yeni kayıt' }, '+')), el.items);
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
    h('div', { class: 'brand' }, h('img', { class: 'logo', src: 'icon.svg', alt: '', width: 24, height: 24 }), 'Kasa'),
    nav('Tümü', { k: 'all' }, live.length),
    nav('★ Favoriler', { k: 'fav' }, live.filter((i) => i.data.fav).length),
    h('h4', {}, 'Türler'),
    ...Object.entries(TYPES).map(([t, l]) => nav(l, { k: 'type', t }, live.filter((i) => i.data.type === t).length)),
    h('h4', {}, 'Kasalar'),
    ...S.vaults.map((x) => nav(x.name, { k: 'vault', id: x.id }, live.filter((i) => i.vid === x.id).length, x.member_count > 1 || !x.mine ? h('span', { class: 'count', title: (x.mine ? '' : 'Sahipleri: ' + x.owners + ' · ') + x.member_count + ' üye' }, '👥') : null)),
    ...S.pending.map((p) => h('div', { class: 'card' }, h('div', {}, '📨 Kasa daveti'), h('div', { class: 'muted' }, `Davet eden: ${p.creator || '?'} · Rol: ${ROLES[p.role]} · Kasa sahipleri: ${p.owners || '?'}. Tanımadığınız birinden gelen daveti reddedin. Kabul edene kadar içeriğe erişilemez.`),
      h('div', { class: 'row' }, h('button', { class: 'small primary', onclick: async () => { try { await api('POST', `/vaults/${p.id}/accept`); await loadAll(); renderAll(); toast('Kasa eklendi'); } catch (e) { toast(errMsg(e)); } } }, 'Kabul'),
        h('button', { class: 'small danger', onclick: async () => { try { await api('DELETE', `/vaults/${p.id}/members/${S.user.id}`); await loadAll(); renderAll(); } catch (e) { toast(errMsg(e)); } } }, 'Reddet')))),
    h('button', { class: 'nav', onclick: newVaultDialog }, h('span', { class: 'muted' }, '+ Yeni kasa')),
    h('h4', {}, 'Araçlar'),
    nav('Güvenlik Taraması', { k: 'monitor' }),
    nav('Çöp kutusu', { k: 'trash' }, [...S.items.values()].filter((i) => i.trashed).length),
    h('button', { class: 'nav', onclick: () => openGenerator() }, 'Parola üretici'),
    S.user.is_admin && nav('Yönetim', { k: 'admin' }),
    nav('Ayarlar', { k: 'settings' }),
    h('div', { class: 'spacer' }),
    h('div', { class: 'muted', style: null }, S.user.email),
    h('button', { onclick: async () => { try { await api('POST', '/logout'); } catch { /* ignore */ } lock('Çıkış yapıldı.'); } }, '🔒 Kilitle'));
  el.shell.classList.toggle('wide', ['monitor', 'admin', 'settings'].includes(v.k));
}

function visible() {
  const v = S.view; const q = S.q.trim().toLowerCase();
  let l = [...S.items.values()].filter((i) => (v.k === 'trash' ? i.trashed : !i.trashed));
  if (v.k === 'fav') l = l.filter((i) => i.data.fav);
  if (v.k === 'type') l = l.filter((i) => i.data.type === v.t);
  if (v.k === 'vault') l = l.filter((i) => i.vid === v.id);
  if (q) l = l.filter((i) => [i.data.title, i.data.username, i.data.urls, i.data.notes].join(' ').toLowerCase().includes(q));
  return l.sort((a, b) => (a.data.title || '').localeCompare(b.data.title || '', 'tr'));
}
function renderList() {
  const l = visible();
  el.items.replaceChildren(...(l.length ? l.map((i) => h('div', { class: 'item' + (S.sel === i.id ? ' sel' : ''), tabindex: 0, onclick: () => { S.sel = i.id; S.edit = null; renderList(); renderDetail(); }, onkeydown: (e) => e.key === 'Enter' && e.target.click() },
    h('div', { class: 'ico', style: null, ...{} }, (i.data.title || '?')[0].toUpperCase()),
    h('div', { class: 'grow' }, h('div', { class: 't' }, (i.data.fav ? '★ ' : '') + (i.data.title || '(adsız)')), h('div', { class: 's' }, i.data.type === 'login' ? i.data.username || '' : i.data.type === 'card' ? '•••• ' + (i.data.card?.number || '').slice(-4) : 'Not'))))
    : [h('div', { class: 'empty' }, S.q ? 'Sonuç yok.' : S.view.k === 'trash' ? 'Çöp kutusu boş.' : 'Henüz kayıt yok. + ile ekleyin.')]));
  // colour the avatar via CSSOM (CSP forbids inline style attributes)
  [...el.items.querySelectorAll('.ico')].forEach((n, idx) => { n.style.background = `hsl(${hue(l[idx].data.title)} 55% 45%)`; });
}

function renderDetail() {
  clearInterval(S.tick);
  const k = S.view.k, d = el.detail;
  if (k === 'monitor') return d.replaceChildren(monitorView());
  if (k === 'admin') return d.replaceChildren(adminView());
  if (k === 'settings') return d.replaceChildren(settingsView());
  if (S.edit) return d.replaceChildren(editForm(S.edit));
  const it = S.sel && S.items.get(S.sel);
  if (!it) return d.replaceChildren(h('div', { class: 'empty' }, 'Bir kayıt seçin veya yeni ekleyin.'));
  d.replaceChildren(itemView(it));
}

// ------------------------------------------------------------------ item view
function fieldRow(label, value, { secret = false, link = false, mono = false } = {}) {
  if (!value) return null;
  let shown = secret; const v = h('div', { class: 'v' + (mono ? ' mono' : '') });
  const paint = () => { v.replaceChildren(secret && !shown ? '••••••••••' : (link && safeUrl(value) ? h('a', { href: safeUrl(value), target: '_blank', rel: 'noopener noreferrer' }, value) : value)); };
  paint();
  return h('div', { class: 'field' }, h('div', { class: 'grow' }, h('div', { class: 'l' }, label), v),
    secret && h('button', { class: 'small', onclick: () => { shown = !shown; paint(); } }, '👁'),
    h('button', { class: 'small', onclick: () => copy(value, label + ' kopyalandı') }, 'Kopyala'));
}

function itemView(it) {
  const d = it.data, vault = vaultById(it.vid), w = canWrite(it.vid);
  const box = h('div', {},
    h('div', { class: 'row wrap' }, h('h2', { class: 'grow' }, (d.fav ? '★ ' : '') + (d.title || '(adsız)')),
      !it.trashed && w && h('button', { onclick: async () => { d.fav = !d.fav; await persist(it.vid, it, d); renderAll(); } }, d.fav ? '★' : '☆'),
      !it.trashed && w && h('button', { onclick: () => { S.edit = { item: it }; renderDetail(); } }, 'Düzenle'),
      !it.trashed && w && h('button', { class: 'danger', onclick: () => trash(it, true) }, 'Çöpe at'),
      it.trashed && w && h('button', { onclick: () => trash(it, false) }, 'Geri yükle'),
      it.trashed && w && h('button', { class: 'danger', onclick: () => hardDelete(it) }, 'Kalıcı sil')),
    h('div', { class: 'muted' }, h('span', { class: 'chip tag' }, TYPES[d.type]), h('span', { class: 'chip tag' }, vault ? vault.name : '?'), !w && h('span', { class: 'chip' }, 'salt okunur')));
  if (d.type === 'login') {
    box.append(fieldRow('Kullanıcı adı', d.username), fieldRow('Parola', d.password, { secret: true, mono: true }));
    if (d.password) { const s = C.strength(d.password); box.append(h('div', { class: 'muted' }, `Güç: ${s.label} (~${s.bits} bit)`, h('button', { class: 'small ghost', onclick: (e) => checkPwned(d.password, e.target) }, 'Sızıntı kontrolü'))); }
    box.append(fieldRow('Adres', d.urls, { link: true }));
    if (d.totp) box.append(totpBlock(d.totp));
  }
  if (d.type === 'card') {
    const c = d.card || {};
    box.append(fieldRow('Kart sahibi', c.holder), fieldRow('Kart numarası', c.number, { secret: true, mono: true }), fieldRow('Son kullanma', c.exp), fieldRow('CVV', c.cvv, { secret: true, mono: true }), fieldRow('PIN', c.pin, { secret: true, mono: true }));
  }
  box.append(fieldRow('Notlar', d.notes));
  for (const f of d.fields || []) box.append(fieldRow(f.k, f.v, { secret: f.secret }));
  if (d.history?.length) box.append(h('details', { class: 'card' }, h('summary', {}, `Parola geçmişi (${d.history.length})`),
    ...d.history.map((x) => h('div', { class: 'row' }, h('span', { class: 'mono grow' }, x.p), h('span', { class: 'muted' }, new Date(x.t).toLocaleDateString('tr-TR')), h('button', { class: 'small', onclick: () => copy(x.p) }, 'Kopyala')))));
  box.append(h('p', { class: 'muted' }, 'Son değişiklik: ' + fmtDate(it.updated_at)));
  return box;
}

function totpBlock(secret) {
  const code = h('span', { class: 'totp' }, '······'), bar = h('i'), raw = { v: '' };
  const tick = async () => {
    try { const r = await C.totp(secret); raw.v = r.code; code.textContent = r.code.slice(0, 3) + ' ' + r.code.slice(3); bar.style.width = (r.remaining / r.period * 100) + '%'; }
    catch { code.textContent = 'Geçersiz TOTP anahtarı'; }
  };
  tick(); S.tick = setInterval(tick, 1000);
  return h('div', { class: 'field' }, h('div', { class: 'grow' }, h('div', { class: 'l' }, 'Tek kullanımlık kod (2FA)'), code, h('div', { class: 'bar' }, bar)),
    h('button', { class: 'small', onclick: () => copy(raw.v, 'Kod kopyalandı') }, 'Kopyala'));
}

async function checkPwned(pw, btn) {
  btn.textContent = '…';
  try { const n = await C.pwnedCount(pw); btn.replaceWith(h('span', { class: n ? 'err' : 'ok' }, n ? ` ⚠ ${n.toLocaleString('tr-TR')} sızıntıda bulundu — değiştirin!` : ' ✓ Bilinen sızıntıda yok')); }
  catch { btn.textContent = 'Kontrol edilemedi'; }
}

// ------------------------------------------------------------------ mutations
async function persist(vid, existing, data) {
  const v = vaultById(vid); if (!v?.key) throw new Error('Kasa anahtarı yok');
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
    it.trashed = r.trashed; it.rev = r.rev; it.updated_at = r.updated_at; S.sel = null; renderAll(); toast(flag ? 'Çöp kutusuna taşındı' : 'Geri yüklendi');
  } catch (e) { toast(errMsg(e)); }
}
async function hardDelete(it) {
  if (!confirm('Bu kayıt kalıcı olarak silinecek. Emin misiniz?')) return;
  try { await api('DELETE', `/vaults/${it.vid}/items/${it.id}`); S.items.delete(it.id); S.sel = null; renderAll(); } catch (e) { toast(errMsg(e)); }
}

// ------------------------------------------------------------------ edit form
function newItem(type = 'login') {
  const writable = S.vaults.filter((v) => ['owner', 'editor'].includes(v.role) && v.key);
  if (!writable.length) return toast('Yazma yetkiniz olan kasa yok');
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
      const k = h('input', { placeholder: 'Alan adı', value: f.k }), v = h('input', { placeholder: 'Değer', value: f.v }), s = h('input', { type: 'checkbox', checked: f.secret, title: 'Gizli' });
      const row = h('div', { class: 'row' }, k, v, h('label', { class: 'row' }, s, 'gizli'), h('button', { type: 'button', class: 'small', onclick: () => { rows.splice(rows.indexOf(r), 1); row.remove(); } }, '✕'));
      const r = { k, v, s }; rows.push(r); fieldsBox.append(row);
    };
    refs.rows = rows;
    const pwBar = h('div', { class: 'bar' }, h('i')), pwTxt = h('div', { class: 'muted' });
    const parts = [h('h2', {}, old ? 'Kaydı düzenle' : 'Yeni kayıt'),
      h('div', { class: 'kv' }, h('div', {}, h('label', {}, 'Tür'), typeSel), h('div', {}, h('label', {}, 'Kasa'), vaultSel)),
      input('title', 'Başlık', { v: d.title })];
    if (type === 'login') {
      parts.push(input('username', 'Kullanıcı adı / e-posta', { v: d.username }));
      parts.push(...input('password', 'Parola', { v: d.password, type: 'text' }));
      refs.password.classList.add('mono');
      const upd = () => { const s = C.strength(refs.password.value); pwBar.firstChild.className = 's' + s.level; pwBar.firstChild.style.width = Math.min(100, s.bits) + '%'; pwTxt.textContent = s.label ? `${s.label} · ~${s.bits} bit` : ''; };
      refs.password.addEventListener('input', upd); upd();
      parts.push(pwBar, pwTxt, h('button', { type: 'button', class: 'small', onclick: () => openGenerator((p) => { refs.password.value = p; upd(); }) }, '🎲 Üret'));
      parts.push(input('urls', 'Web adresi', { v: d.urls }), input('totp', '2FA anahtarı (base32 veya otpauth://)', { v: d.totp }));
    }
    if (type === 'card') {
      const c = d.card || {};
      parts.push(input('holder', 'Kart sahibi', { v: c.holder }), input('number', 'Kart numarası', { v: c.number }), input('exp', 'Son kullanma (AA/YY)', { v: c.exp }), input('cvv', 'CVV', { v: c.cvv }), input('pin', 'PIN', { v: c.pin }));
    }
    parts.push(input('notes', 'Notlar', { v: d.notes, area: true }), h('label', {}, 'Özel alanlar'), fieldsBox,
      h('button', { type: 'button', class: 'small', onclick: () => addRow() }, '+ Alan ekle'),
      h('div', { class: 'row', class2: null }, h('button', { class: 'primary', type: 'submit' }, 'Kaydet'), h('button', { type: 'button', onclick: () => { S.edit = null; renderDetail(); } }, 'İptal')));
    (d.fields || []).forEach(addRow);
    const form = h('form', { onsubmit: async (e) => {
      e.preventDefault(); snapshot();
      if (!d.title.trim()) return toast('Başlık gerekli');
      try {
        if (type === 'login' && old && old.data.password && old.data.password !== d.password) {
          d.history = [{ p: old.data.password, t: Date.now() }, ...(old.data.history || [])].slice(0, 5); d.pw_changed = Date.now();
        } else if (type === 'login' && !old) d.pw_changed = Date.now();
        const it = await persist(old ? old.vid : ed.vid, old, d);
        S.edit = null; S.sel = it.id; renderAll(); toast('Kaydedildi');
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
    d.notes = g('notes'); d.fav = !!d.fav;
    d.fields = refs.rows.filter((r) => r.k.value.trim()).map((r) => ({ k: r.k.value.trim(), v: r.v.value, secret: r.s.checked }));
  };
  draw(); return wrap;
}

// ------------------------------------------------------------------ generator
function openGenerator(onUse) {
  const o = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true };
  const out = h('div', { class: 'genout mono' }), meta = h('div', { class: 'muted' });
  const gen = () => { const p = C.generatePassword(o); out.textContent = p; const s = C.strength(p); meta.textContent = `${s.label} · ~${s.bits} bit`; };
  const len = h('input', { type: 'range', min: 8, max: 64, value: 20, oninput: (e) => { o.length = +e.target.value; lenL.textContent = o.length; gen(); } });
  const lenL = h('b', {}, '20');
  const cb = (k, l) => h('label', {}, h('input', { type: 'checkbox', checked: o[k], onchange: (e) => { o[k] = e.target.checked; gen(); } }), l);
  const d = modal('Parola üretici', out, meta, h('label', {}, 'Uzunluk: ', lenL), len,
    h('div', { class: 'opts' }, cb('lower', 'a-z'), cb('upper', 'A-Z'), cb('digits', '0-9'), cb('symbols', '!@#'), cb('avoidAmbiguous', 'Benzer karakterleri çıkar')),
    h('div', { class: 'row', style: null }, h('button', { onclick: gen }, '↻ Yenile'), h('button', { onclick: () => copy(out.textContent) }, 'Kopyala'),
      onUse && h('button', { class: 'primary', onclick: () => { onUse(out.textContent); d.close(); } }, 'Kullan'), h('button', { onclick: () => d.close() }, 'Kapat')));
  gen();
}

// ------------------------------------------------------------------ vaults / sharing
function newVaultDialog() {
  const name = h('input', { placeholder: 'Örn. Muhasebe, Sosyal medya hesapları' });
  const d = modal('Yeni kasa', h('p', { class: 'muted' }, 'Kasaları ekip arkadaşlarınızla paylaşabilirsiniz. Her kasanın kendi şifreleme anahtarı vardır.'), name,
    h('div', { class: 'row' }, h('button', { class: 'primary', onclick: async () => {
      if (!name.value.trim()) return;
      try { const id = await createVault(name.value.trim()); await loadAll(); d.close(); go({ k: 'vault', id }); } catch (e) { toast(errMsg(e)); }
    } }, 'Oluştur'), h('button', { onclick: () => d.close() }, 'İptal')));
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
  const d = modal('Kasa: ' + v.name); const body = h('div'); d.append(body);
  const draw = async () => {
    let members = []; try { members = await api('GET', `/vaults/${v.id}/members`); } catch (e) { return body.replaceChildren(h('p', { class: 'err' }, errMsg(e))); }
    const owner = v.role === 'owner';
    const email = h('input', { type: 'email', placeholder: 'Ekip arkadaşının e-postası' }); const role = h('select', {}, Object.entries(ROLES).map(([k, l]) => h('option', { value: k, selected: k === 'editor' }, l)));
    const found = h('div', { class: 'muted' });
    const table = h('table', {}, h('tr', {}, h('th', {}, 'Üye'), h('th', {}, 'Rol'), h('th')),
      ...members.map((m) => h('tr', {}, h('td', {}, m.name, h('div', { class: 'muted' }, m.email + (m.status === 'pending' ? ' · davet bekliyor' : ''))),
        h('td', {}, owner ? h('select', { onchange: async (e) => { try { await api('PUT', `/vaults/${v.id}/members/${m.user_id}`, { role: e.target.value }); await loadAll(); draw(); renderAll(); } catch (x) { toast(errMsg(x)); draw(); } } },
          Object.entries(ROLES).map(([k, l]) => h('option', { value: k, selected: k === m.role }, l))) : ROLES[m.role]),
        h('td', {}, (owner || m.user_id === S.user.id) && h('button', { class: 'small danger', onclick: async () => {
          if (!confirm(m.user_id === S.user.id ? 'Kasadan ayrılmak istiyor musunuz?' : `${m.email} kasadan çıkarılsın mı? Kasa anahtarı yenilenecek.`)) return;
          try {
            await api('DELETE', `/vaults/${v.id}/members/${m.user_id}`);
            if (m.user_id === S.user.id) { await loadAll(); d.close(); return go({ k: 'all' }); }
            toast('Anahtar yenileniyor…'); await rotateVault(v); toast('Üye çıkarıldı, anahtar yenilendi'); draw(); renderAll();
          } catch (x) { toast(errMsg(x)); }
        } }, m.user_id === S.user.id ? 'Ayrıl' : 'Çıkar')))));
    const parts = [h('h4', {}, 'Üyeler'), table];
    if (owner) parts.push(h('h4', {}, 'Üye ekle'), h('div', { class: 'row' }, email, role), found,
      h('button', { class: 'primary', onclick: async () => {
        try {
          const u = await api('GET', '/users/lookup?email=' + encodeURIComponent(email.value));
          const fp = await C.fingerprint(u.public_key);
          if (!confirm(`${u.name} <${u.email}>\nParmak izi: ${fp}\n\nBu kişiye kasa erişimi verilsin mi? (Parmak izini kişiyle doğrulayabilirsiniz.)`)) return;
          await api('POST', `/vaults/${v.id}/members`, { user_id: u.id, role: role.value, wrapped_key: await C.wrapVaultKey(v.key, u.public_key) });
          await loadAll(); renderAll(); draw(); toast('Davet gönderildi; kabul edince erişir');
        } catch (e) { found.textContent = errMsg(e); found.className = 'err'; }
      } }, 'Ekle'),
      h('h4', {}, 'Kasa ayarları'),
      h('div', { class: 'row' }, h('button', { onclick: async () => { const n = prompt('Yeni ad', v.name); if (!n) return; await api('PUT', `/vaults/${v.id}`, { enc_name: await C.encJSON(v.key, { name: n }) }); await loadAll(); renderAll(); d.close(); } }, 'Yeniden adlandır'),
        h('button', { onclick: async () => { const rows = await api('GET', `/vaults/${v.id}/audit`); const dd = modal('Etkinlik kaydı', h('div', { class: 'items' }, h('table', {}, rows.map((r) => h('tr', {}, h('td', {}, fmtDate(r.ts)), h('td', {}, r.email || '-'), h('td', {}, r.action))))), h('button', { onclick: () => dd.close() }, 'Kapat')); } }, 'Etkinlik kaydı'),
        h('button', { class: 'danger', onclick: async () => { if (!confirm('Kasa ve içindeki TÜM kayıtlar tüm üyeler için silinecek!')) return; await api('DELETE', `/vaults/${v.id}`); await loadAll(); d.close(); go({ k: 'all' }); } }, 'Kasayı sil')));
    parts.push(h('div', { class: 'row' }, h('button', { onclick: () => d.close() }, 'Kapat')));
    body.replaceChildren(...parts);
  };
  draw();
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
  const breach = h('div', { class: 'card' }, h('h3', {}, 'Sızıntı kontrolü (Have I Been Pwned)'), h('div', { class: 'muted' }, 'Parolanın yalnızca SHA-1 özetinin ilk 5 karakteri gönderilir; parolalarınız cihazınızdan çıkmaz.'));
  const res = h('div'); const go1 = h('button', { class: 'primary', onclick: async () => {
    go1.disabled = true; res.replaceChildren(); let n = 0;
    for (const [pw, group] of byPw) {
      go1.textContent = `Kontrol ediliyor… ${++n}/${byPw.size}`;
      try { if (!S.pwned.has(pw)) S.pwned.set(pw, await C.pwnedCount(pw)); } catch { go1.textContent = 'Ağ hatası'; go1.disabled = false; return; }
      if (S.pwned.get(pw)) group.forEach((i) => res.append(h('div', { class: 'err' }, `⚠ ${i.data.title} — ${S.pwned.get(pw).toLocaleString('tr-TR')} sızıntıda`)));
    }
    go1.textContent = 'Tekrar kontrol et'; go1.disabled = false; if (!res.children.length) res.append(h('div', { class: 'ok' }, '✓ Hiçbir parola bilinen sızıntıda bulunmadı.'));
  } }, 'Tüm parolaları kontrol et');
  breach.append(go1, res);
  return h('div', {}, h('h2', {}, 'Güvenlik Taraması'), h('p', { class: 'muted' }, `${logins.length} giriş kaydı tarandı (tüm analiz tarayıcınızda yapılır).`),
    breach, section('Zayıf parolalar', '50 bitin altındaki parolalar', weak), section('Tekrar kullanılan parolalar', 'Aynı parola birden fazla kayıtta', reused),
    section('1 yıldan eski parolalar', 'Uzun süredir değiştirilmemiş', old), section('2FA eklenmemiş', 'Web adresi olan ama 2FA kodu tanımlanmamış kayıtlar', no2fa));
}

// ------------------------------------------------------------------ admin
function adminView() {
  const box = h('div', {}, h('h2', {}, 'Yönetim')); const body = h('div'); box.append(body);
  const draw = async () => {
    try {
      const [users, invites, audit] = await Promise.all([api('GET', '/admin/users'), api('GET', '/admin/invites'), api('GET', '/admin/audit')]);
      const email = h('input', { type: 'email', placeholder: 'İsteğe bağlı: sadece bu e-posta kullanabilsin' });
      body.replaceChildren(
        h('div', { class: 'card' }, h('h3', {}, 'Davetler'), h('p', { class: 'muted' }, 'Kayıt yalnızca davet koduyla yapılabilir. Kodlar 7 gün geçerlidir ve tek kullanımlıktır.'),
          h('div', { class: 'row' }, email, h('button', { class: 'primary', onclick: async () => {
            const r = await api('POST', '/admin/invites', { email: email.value || null }); const link = `${location.origin}/#invite=${r.code}`;
            await copy(link, 'Davet bağlantısı kopyalandı'); draw();
          } }, 'Davet oluştur')),
          ...invites.map((i) => h('div', { class: 'row' }, h('span', { class: 'mono grow' }, `${location.origin}/#invite=${i.code}`, i.email ? ` (${i.email})` : ''),
            h('button', { class: 'small', onclick: () => copy(`${location.origin}/#invite=${i.code}`) }, 'Kopyala'), h('button', { class: 'small danger', onclick: async () => { await api('DELETE', '/admin/invites/' + i.code); draw(); } }, 'İptal')))),
        h('div', { class: 'card' }, h('h3', {}, 'Kullanıcılar'), h('table', {}, users.map((u) => h('tr', {},
          h('td', {}, u.name, h('div', { class: 'muted' }, u.email)), h('td', {}, u.is_admin ? 'Yönetici' : 'Üye', u.disabled ? ' · devre dışı' : ''),
          h('td', {}, u.id !== S.user.id && h('button', { class: 'small', onclick: async () => { await api('POST', `/admin/users/${u.id}/disable?disable=${!u.disabled}`); draw(); } }, u.disabled ? 'Etkinleştir' : 'Devre dışı bırak'),
            u.id !== S.user.id && h('button', { class: 'small', onclick: async () => { try { await api('POST', `/admin/users/${u.id}/admin?admin=${!u.is_admin}`); draw(); } catch (e) { toast(errMsg(e)); } } }, u.is_admin ? 'Yöneticiliği al' : 'Yönetici yap'))))),
          h('p', { class: 'muted' }, 'Bir kullanıcıyı devre dışı bıraktıktan sonra, ortak kasalarında kasa sahiplerinin onu üyelikten çıkarması önerilir (anahtar yenilenir).')),
        h('div', { class: 'card' }, h('h3', {}, 'Son etkinlikler'), h('table', {}, audit.slice(0, 100).map((r) => h('tr', {}, h('td', {}, fmtDate(r.ts)), h('td', {}, r.email || '-'), h('td', {}, r.action, r.detail && r.action.startsWith('user.') ? ' ' + r.detail : ''))))));
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
  const rows = parseCSV(await file.text()); if (rows.length < 2) throw new Error('Boş dosya');
  const hd = rows[0].map((x) => x.trim().toLowerCase());
  const col = (...names) => hd.findIndex((x) => names.includes(x));
  const ix = { title: col('name', 'title', 'label'), url: col('url', 'login_uri', 'website', 'uri', 'web site'), user: col('username', 'login_username', 'user', 'login_name', 'email'), pw: col('password', 'login_password'), notes: col('note', 'notes', 'extra'), totp: col('totp', 'login_totp', 'otpauth'), type: col('type') };
  if (ix.title < 0 || ix.pw < 0) throw new Error('Tanınmayan sütunlar (Chrome, Bitwarden, Proton Pass, 1Password CSV desteklenir).');
  const g = (r, k) => (ix[k] >= 0 ? (r[ix[k]] || '').trim() : '');
  let n = 0; const list = rows.slice(1);
  for (const r of list) {
    const isNote = g(r, 'type') === 'note' || g(r, 'type') === 'securenote';
    const d = { type: isNote ? 'note' : 'login', title: g(r, 'title') || g(r, 'url') || 'İçe aktarılan', username: g(r, 'user'), password: g(r, 'pw'), urls: g(r, 'url'), totp: g(r, 'totp'), notes: g(r, 'notes'), fields: [], card: {}, created: Date.now(), pw_changed: Date.now() };
    await persist(vid, null, d); status.textContent = `${++n}/${list.length} aktarıldı…`;
  }
  return n;
}

function settingsView() {
  const minutes = h('select', { onchange: (e) => { localStorage.setItem('kasa.autolock', e.target.value); armIdle(); toast('Kaydedildi'); } },
    [[1, '1 dakika'], [5, '5 dakika'], [10, '10 dakika'], [30, '30 dakika'], [60, '1 saat'], [0, 'Asla']].map(([v, l]) => h('option', { value: v, selected: +(localStorage.getItem('kasa.autolock') || 10) === v }, l)));
  const fp = h('span', { class: 'mono' }, '…'); C.fingerprint(S.user.public_key).then((x) => { fp.textContent = x; });
  const cur = h('input', { type: 'password', autocomplete: 'current-password' }), n1 = h('input', { type: 'password', autocomplete: 'new-password' }), n2 = h('input', { type: 'password', autocomplete: 'new-password' }), pwOut = h('div');
  const file = h('input', { type: 'file', accept: '.csv' }), writable = S.vaults.filter((v) => v.key && ['owner', 'editor'].includes(v.role));
  const target = h('select', {}, writable.map((v) => h('option', { value: v.id }, v.name))), impOut = h('div', { class: 'muted' });
  return h('div', {}, h('h2', {}, 'Ayarlar'),
    h('div', { class: 'card' }, h('h3', {}, 'Hesap'), h('div', {}, `${S.user.name} · ${S.user.email}`), h('div', { class: 'muted' }, 'Açık anahtar parmak izi (paylaşırken karşı tarafla doğrulayın): ', fp)),
    h('div', { class: 'card' }, h('h3', {}, 'Otomatik kilit'), minutes),
    h('div', { class: 'card' }, h('h3', {}, 'Kasa yönetimi'), h('div', { class: 'row wrap' }, S.vaults.filter((v) => !v.broken).map((v) => h('button', { onclick: () => vaultDialog(v) }, `${v.name} (${ROLES[v.role]})`)))),
    h('div', { class: 'card' }, h('h3', {}, 'Ana parolayı değiştir'), h('label', {}, 'Mevcut'), cur, h('label', {}, 'Yeni (en az 12 karakter)'), n1, h('label', {}, 'Yeni (tekrar)'), n2, pwOut,
      h('button', { class: 'primary', onclick: async () => {
        pwOut.className = 'err'; pwOut.textContent = '';
        try {
          if (n1.value.length < 12 || C.strength(n1.value).level < 2) throw new Error('Yeni parola yeterince güçlü değil.');
          if (n1.value !== n2.value) throw new Error('Parolalar eşleşmiyor.');
          const pre = await api('GET', '/prelogin?email=' + encodeURIComponent(S.user.email));
          const old = await C.deriveKeys(cur.value, pre.salt, pre.iters);
          const salt = C.randomSalt(), nw = await C.deriveKeys(n1.value, salt, C.ITERS);
          const encPriv = await C.rewrapPrivate(old.masterKey, nw.masterKey, S.user.enc_private_key);
          await api('POST', '/password', { old_auth: old.auth, new_auth: nw.auth, new_salt: salt, new_iters: C.ITERS, enc_private_key: encPriv });
          S.master = nw.masterKey; S.user.enc_private_key = encPriv; [cur, n1, n2].forEach((i) => { i.value = ''; });
          pwOut.className = 'ok'; pwOut.textContent = 'Ana parola değiştirildi. Diğer oturumlar kapatıldı.';
        } catch (e) { pwOut.textContent = errMsg(e); }
      } }, 'Değiştir')),
    h('div', { class: 'card' }, h('h3', {}, 'İçe aktar'), h('div', { class: 'muted' }, 'Chrome, Bitwarden, Proton Pass, 1Password gibi CSV dışa aktarımları.'), h('label', {}, 'Hedef kasa'), target, h('label', {}, 'CSV dosyası'), file, impOut,
      h('button', { onclick: async () => { if (!file.files[0]) return; try { const n = await importCSV(file.files[0], target.value, impOut); impOut.textContent = `${n} kayıt aktarıldı.`; renderSide(); } catch (e) { impOut.className = 'err'; impOut.textContent = errMsg(e); } } }, 'Aktar')),
    h('div', { class: 'card' }, h('h3', {}, 'Dışa aktar'), h('div', { class: 'muted' }, 'Dosya ŞİFRESİZ düz metin olur. İşiniz bitince güvenle silin.'),
      h('button', { onclick: () => {
        if (!confirm('Tüm parolalarınız şifresiz bir CSV dosyasına yazılacak. Devam?')) return;
        const lines = [['name', 'url', 'username', 'password', 'totp', 'note', 'type', 'vault'].join(',')];
        for (const i of liveItems()) lines.push([i.data.title, i.data.urls, i.data.username, i.data.password, i.data.totp, i.data.notes, i.data.type, vaultById(i.vid)?.name].map(csvCell).join(','));
        const a = h('a', { href: URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' })), download: 'kasa-export.csv' }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      } }, 'CSV indir')));
}

if (location.hash.includes('invite=')) renderAuth('register'); else renderAuth();
