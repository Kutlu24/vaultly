// End-to-end test: real server + the real browser crypto module (Node WebCrypto).
import * as C from '../web/crypto.js';
import assert from 'node:assert/strict';
const B = process.env.KASA_URL || 'http://localhost:8099';
const call = async (m, p, body, tok) => { const r = await fetch(B + '/api' + p, { method: m, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined }); const j = await r.json().catch(() => ({})); return { s: r.status, j }; };
async function register(email, pw, invite) {
  const salt = C.randomSalt(); const { masterKey, auth } = await C.deriveKeys(pw, salt, C.ITERS); const id = await C.newIdentity(masterKey);
  const r = await call('POST', '/register', { email, name: email, salt, iters: C.ITERS, auth, ...id, invite }); return { ...r, masterKey };
}
async function login(email, pw) {
  const pre = (await call('GET', '/prelogin?email=' + email)).j; const { masterKey, auth } = await C.deriveKeys(pw, pre.salt, pre.iters);
  const r = await call('POST', '/login', { email, auth }); r.priv = r.s === 200 ? await C.loadPrivate(masterKey, r.j.user.enc_private_key) : null; return r;
}
const pw1 = 'correct horse battery staple', pw2 = 'another long passphrase 42';
// TOTP RFC 6238 vector (SHA1, secret "12345678901234567890", t=59 -> 94287082 for 8 digits)
assert.equal((await C.totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000)).code, '287082');
console.log('ok totp RFC vector');
let a = await register('a@x.ch', pw1); assert.equal(a.s, 200); assert.ok(a.j.user.is_admin); console.log('ok first user is admin');
assert.equal((await register('b@x.ch', pw2, null)).s, 403); console.log('ok registration closed without invite');
const inv = (await call('POST', '/admin/invites', {}, a.j.token)).j.code;
let b = await register('b@x.ch', pw2, inv); assert.equal(b.s, 200); assert.ok(!b.j.user.is_admin);
assert.equal((await register('c@x.ch', pw2, inv)).s, 403); console.log('ok invite single-use');
assert.equal((await call('GET', '/admin/users', null, b.j.token)).s, 403); console.log('ok non-admin blocked');
assert.equal((await login('a@x.ch', 'wrong password!!')).s, 401); console.log('ok wrong password rejected');
a = await login('a@x.ch', pw1); b = await login('b@x.ch', pw2); assert.equal(a.s, 200);
// vault + item
const vk = await C.newVaultKey();
const v = (await call('POST', '/vaults', { enc_name: await C.encJSON(vk, { name: 'Ekip' }), wrapped_key: await C.wrapVaultKey(vk, a.j.user.public_key) }, a.j.token)).j.id;
const it = (await call('POST', `/vaults/${v}/items`, { data: await C.encJSON(vk, { title: 'Bank', password: 'S3cret!' }) }, a.j.token)).j;
assert.equal((await call('GET', `/vaults/${v}/items`, null, b.j.token)).s, 404); console.log('ok non-member cannot see vault');
// share with b as viewer
const lk = (await call('GET', '/users/lookup?email=b@x.ch', null, a.j.token)).j;
await call('POST', `/vaults/${v}/members`, { user_id: lk.id, role: 'viewer', wrapped_key: await C.wrapVaultKey(vk, lk.public_key) }, a.j.token);
assert.equal((await call('GET', `/vaults/${v}/items`, null, b.j.token)).s, 404); console.log('ok pending invite grants no access');
assert.equal((await call('POST', `/vaults/${v}/accept`, null, b.j.token)).s, 200);
const bv = (await call('GET', '/vaults', null, b.j.token)).j[0]; const bk = await C.unwrapVaultKey(bv.wrapped_key, b.priv);
assert.equal((await C.decJSON(bk, bv.enc_name)).name, 'Ekip');
const bi = (await call('GET', `/vaults/${v}/items`, null, b.j.token)).j[0]; assert.equal((await C.decJSON(bk, bi.data)).password, 'S3cret!'); console.log('ok member decrypts shared item');
assert.equal((await call('POST', `/vaults/${v}/items`, { data: 'x' }, b.j.token)).s, 403); console.log('ok viewer cannot write');
assert.equal((await call('PUT', `/vaults/${v}/items/${it.id}`, { data: 'x', rev: 99 }, a.j.token)).s, 409); console.log('ok stale rev -> 409');
assert.equal((await call('DELETE', `/vaults/${v}/items/${it.id}`, null, a.j.token)).s, 400); console.log('ok must trash before delete');
// remove b + rotate
await call('DELETE', `/vaults/${v}/members/${lk.id}`, null, a.j.token);
assert.equal((await call('GET', `/vaults/${v}/items`, null, b.j.token)).s, 404);
const raw = (await call('GET', `/vaults/${v}/items`, null, a.j.token)).j; const nk = await C.newVaultKey();
const items = []; for (const r of raw) items.push({ id: r.id, data: await C.encJSON(nk, await C.decJSON(vk, r.data)) });
const rot = await call('POST', `/vaults/${v}/rotate`, { enc_name: await C.encJSON(nk, { name: 'Ekip' }), wrapped_keys: { [a.j.user.id]: await C.wrapVaultKey(nk, a.j.user.public_key) }, items, expect_members: [a.j.user.id] }, a.j.token);
assert.equal(rot.s, 200);
const av = (await call('GET', '/vaults', null, a.j.token)).j[0]; const ak = await C.unwrapVaultKey(av.wrapped_key, a.priv);
const ai = (await call('GET', `/vaults/${v}/items`, null, a.j.token)).j[0]; assert.equal((await C.decJSON(ak, ai.data)).title, 'Bank');
await assert.rejects(C.decJSON(vk, ai.data)); console.log('ok rotation: old key no longer decrypts');
// last owner protection
assert.equal((await call('DELETE', `/vaults/${v}/members/${a.j.user.id}`, null, a.j.token)).s, 400); console.log('ok last owner protected');
// password change
const pre = (await call('GET', '/prelogin?email=a@x.ch')).j; const old = await C.deriveKeys(pw1, pre.salt, pre.iters); const salt = C.randomSalt(); const nw = await C.deriveKeys('brand new long passphrase 9', salt, C.ITERS);
const ep = await C.rewrapPrivate(old.masterKey, nw.masterKey, a.j.user.enc_private_key);
assert.equal((await call('POST', '/password', { old_auth: old.auth, new_auth: nw.auth, new_salt: salt, new_iters: C.ITERS, enc_private_key: ep }, a.j.token)).s, 200);
assert.equal((await login('a@x.ch', pw1)).s, 401); const a2 = await login('a@x.ch', 'brand new long passphrase 9'); assert.equal(a2.s, 200);
const av2 = (await call('GET', '/vaults', null, a2.j.token)).j[0]; await C.unwrapVaultKey(av2.wrapped_key, a2.priv); console.log('ok password change keeps vault access');
// generator/strength sanity
const g = C.generatePassword({ length: 24 }); assert.equal(g.length, 24); assert.ok(C.strength(g).level >= 3); assert.ok(C.strength('password1').level <= 1); console.log('ok generator/strength');
console.log('\nALL PASSED');
