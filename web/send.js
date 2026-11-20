// Recipient page for a Send link: https://host/send.html#<id>.<key>
// The key never leaves this browser (fragments are not sent to the server).
import * as C from './crypto.js';

const m = document.getElementById('m'), st = document.getElementById('st');
const h = (tag, a = {}, ...kids) => { const e = document.createElement(tag); for (const [k, v] of Object.entries(a)) { if (v == null || v === false) continue; if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (k === 'class') e.className = v; else e.setAttribute(k, v); } e.append(...kids.flat().filter((x) => x != null)); return e; };
const toast = (t) => { const x = document.getElementById('toast'); x.textContent = t; x.classList.add('show'); setTimeout(() => x.classList.remove('show'), 2000); };
const [id, key] = location.hash.slice(1).split('.');
history.replaceState(null, '', location.pathname);   // keep the key out of the address bar after reading it

async function main() {
  if (!id || !key || !/^[\w-]+$/.test(id)) { st.textContent = 'This link is incomplete. Ask the sender for the full link.'; return; }
  const r = await fetch('/api/send/' + encodeURIComponent(id));
  if (!r.ok) { st.textContent = (await r.json().catch(() => ({}))).detail || 'This link does not work.'; return; }
  const info = await r.json();
  const pw = h('input', { type: 'password', placeholder: 'Password from the sender', autocomplete: 'off' });
  const err = h('p', { class: 'err' });
  const btn = h('button', { class: 'primary' }, 'Show the secret');
  st.textContent = 'Someone shared a secret with you. It is encrypted; it is decrypted here, in your browser. Opening it may use up the link.';
  m.append(...(info.needs_password ? [h('label', {}, 'This link is protected with a password'), pw] : []), err, btn, h('p', { class: 'muted' }, 'Link valid until ' + new Date(info.expires * 1000).toLocaleString()));
  btn.addEventListener('click', async () => {
    btn.disabled = true; err.textContent = '';
    try {
      const a = await fetch(`/api/send/${encodeURIComponent(id)}/access`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw.value }) });
      const j = await a.json().catch(() => ({}));
      if (!a.ok) throw new Error(j.detail || 'Could not open the link.');
      const obj = await C.sendDecrypt(j.enc, key);
      const parts = [];
      if (obj.text) { const t = String(obj.text); parts.push(h('div', { class: 'secret' }, t), h('button', { onclick: async () => { try { await navigator.clipboard.writeText(t); toast('Copied'); } catch { toast('Copy blocked by the browser'); } } }, 'Copy text')); }
      if (obj.kind === 'file') {
        const bytes = C.unb64(obj.data); const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
        parts.push(h('p', {}, h('a', { href: url, download: String(obj.name || 'file').replace(/[\\/]/g, '_'), class: 'button' }, '⬇ Download ' + String(obj.name || 'file')), ' ', h('span', { class: 'muted' }, `(${Math.ceil(bytes.length / 1024)} KB)`)));
      }
      parts.push(h('p', { class: 'muted' }, j.views_left === null ? 'Save what you need now.' : j.views_left > 0 ? `This link can be opened ${j.views_left} more time(s).` : 'This was the last view: the link no longer works. Save what you need now.'));
      m.replaceChildren(h('h1', {}, 'Shared with you'), ...parts);
    } catch (e) { err.textContent = e.message === 'OperationError' || e.name === 'OperationError' ? 'The link is damaged (wrong key).' : e.message; btn.disabled = false; }
  });
}
main().catch((e) => { st.textContent = 'Error: ' + e.message; });
