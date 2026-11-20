// End-to-end tests for 2FA, sessions, Send, snapshots and backups (real server + real crypto module).
// Run against a FRESH data dir: KASA_URL=http://localhost:8099 node tests/features.mjs
import * as C from '../web/crypto.js';
import assert from 'node:assert/strict';
const B = process.env.KASA_URL || 'http://localhost:8099';
const call = async (m, p, body, tok, ua) => { const r = await fetch(B + '/api' + p, { method: m, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}), ...(ua ? { 'User-Agent': ua } : {}) }, body: body ? JSON.stringify(body) : undefined }); const j = await r.json().catch(() => ({})); return { s: r.status, j }; };
const ok = (m) => console.log('ok', m);
async function keys(email, pw) { const pre = (await call('GET', '/prelogin?email=' + email)).j; return C.deriveKeys(pw, pre.salt, pre.iters); }
async function register(email, pw, invite) {
  const salt = C.randomSalt(); const { masterKey, auth } = await C.deriveKeys(pw, salt, C.ITERS); const id = await C.newIdentity(masterKey);
  return call('POST', '/register', { email, name: email, salt, iters: C.ITERS, auth, ...id, invite });
}
const PW = 'team vault passphrase 2026', PW2 = 'second member long phrase';
let a = await register('admin@t.org', PW);
if (a.s !== 200) { console.error('Use an empty data dir for this test.'); process.exit(1); }
const A = a.j.token;
const inv = (await call('POST', '/admin/invites', {}, A)).j.code;
const b = await register('member@t.org', PW2, inv); const Bt = b.j.token;

// ---- 2FA
const auth = (await keys('admin@t.org', PW)).auth;
assert.equal((await call('POST', '/2fa/setup', { auth: 'x'.repeat(44) }, A)).s, 403); ok('2FA setup needs the master password');
const setup = (await call('POST', '/2fa/setup', { auth }, A)).j;
assert.match(setup.uri, /^otpauth:\/\/totp\/Vaultly:admin%40t\.org\?secret=[A-Z2-7]+&issuer=Vaultly$/);
assert.equal((await call('POST', '/2fa/enable', { code: '000000' }, A)).s, 400);
const en = await call('POST', '/2fa/enable', { code: (await C.totp(setup.secret)).code }, A);
assert.equal(en.s, 200); assert.equal(en.j.recovery_codes.length, 8); ok('2FA enabled with recovery codes');
let r = await call('POST', '/login', { email: 'admin@t.org', auth });
assert.equal(r.s, 401); assert.equal(r.j.detail, '2FA_REQUIRED'); ok('login asks for the code');
assert.equal((await call('POST', '/login', { email: 'admin@t.org', auth, code: '123456' })).s, 401); ok('wrong code refused');
const next = (await C.totp(setup.secret, Date.now() + 30000)).code;   // the current step was used to enable (replay guard)
r = await call('POST', '/login', { email: 'admin@t.org', auth, code: next }, null, 'Mozilla/5.0 (Android 14) Firefox/130');
assert.equal(r.s, 200); assert.equal(r.j.user.totp, true); const A2 = r.j.token; ok('code accepted');
assert.equal((await call('POST', '/login', { email: 'admin@t.org', auth, code: next })).s, 401); ok('same code cannot be replayed');
r = await call('POST', '/login', { email: 'admin@t.org', auth, code: en.j.recovery_codes[0].toUpperCase() });
assert.equal(r.s, 200); ok('recovery code works');
assert.equal((await call('POST', '/login', { email: 'admin@t.org', auth, code: en.j.recovery_codes[0] })).s, 401); ok('recovery code is single-use');
assert.equal((await call('GET', '/2fa/status', null, A)).j.recovery_left, 7);
assert.equal((await call('POST', '/admin/users/' + a.j.user.id + '/reset-2fa', { auth: 'z'.repeat(44) }, Bt)).s, 403); ok('non-admin cannot reset 2FA');

// ---- sessions + activity
const sess = (await call('GET', '/account/sessions', null, A2)).j;
assert.ok(sess.length >= 3 && sess.some((x) => x.current && x.agent === 'Firefox on Android')); ok('session list with device label');
const act = (await call('GET', '/account/activity', null, A2)).j;
assert.ok(act.some((x) => x.action === 'user.login_failed' && x.detail.includes('2FA'))); ok('failed sign-ins are in the activity');
const other = sess.find((x) => !x.current);
assert.equal((await call('DELETE', '/account/sessions/' + other.id, null, A2)).j.ended, 1);
const ended = (await call('DELETE', '/account/sessions', null, A2)).j.ended; assert.ok(ended >= 1);
assert.equal((await call('GET', '/vaults', null, A)).s, 401); assert.equal((await call('GET', '/vaults', null, A2)).s, 200); ok('sign out other devices');
assert.equal((await call('DELETE', '/account/sessions/zz', null, Bt)).s, 400);

// admin resets member? (member has no 2FA) -> admin resets own? use member: turn on, then admin resets
const authB = (await keys('member@t.org', PW2)).auth;
const sB = (await call('POST', '/2fa/setup', { auth: authB }, Bt)).j; await call('POST', '/2fa/enable', { code: (await C.totp(sB.secret)).code }, Bt);
assert.equal((await call('POST', '/admin/users/' + b.j.user.id + '/reset-2fa', { auth: 'q'.repeat(44) }, A2)).s, 403); ok('admin reset needs the admin master password');
assert.equal((await call('POST', '/admin/users/' + b.j.user.id + '/reset-2fa', { auth }, A2)).s, 200);
assert.ok((await call('GET', '/account/activity', null, (await call('POST', '/login', { email: 'member@t.org', auth: authB })).j.token)).j.some((x) => x.action === 'user.2fa_reset_by_admin')); ok('member sees the reset in their activity');
assert.equal((await call('GET', '/vaults', null, Bt)).s, 401); // admin reset also signs the member out
const Bt2 = (await call('POST', '/login', { email: 'member@t.org', auth: authB })).j.token; assert.ok(Bt2); ok('admin 2FA reset (member signs in without code)');
// persistent 2FA lockout: 5 wrong codes lock the code check for 15 min even with the right password, from any IP
const sB2 = (await call('POST', '/2fa/setup', { auth: authB }, Bt2)).j; await call('POST', '/2fa/enable', { code: (await C.totp(sB2.secret)).code }, Bt2);
for (let i = 0; i < 5; i++) await call('POST', '/login', { email: 'member@t.org', auth: authB, code: String(100000 + i) });
const lockedTry = await call('POST', '/login', { email: 'member@t.org', auth: authB, code: (await C.totp(sB2.secret, Date.now() + 30000)).code });
assert.ok([429].includes(lockedTry.s)); ok('2FA locks after 5 wrong codes');
const par = await Promise.all(Array.from({ length: 8 }, (_, i) => call('POST', '/login', { email: 'member@t.org', auth: authB, code: String(200000 + i) })));
assert.ok(par.every((x) => x.s === 429)); ok('parallel attempts during the lock are all refused');
assert.equal((await call('POST', '/admin/users/' + b.j.user.id + '/reset-2fa', { auth }, A2)).s, 200);   // admin reset also clears the lock
const Bt3 = (await call('POST', '/login', { email: 'member@t.org', auth: authB })).j.token; assert.ok(Bt3);
assert.equal((await call('POST', '/2fa/disable', { auth: 'y'.repeat(44) }, A2)).s, 403);
assert.equal((await call('POST', '/2fa/disable', { auth }, A2)).s, 200); ok('disable needs the master password');

// ---- Send
const { enc, key } = await C.sendEncrypt({ kind: 'text', text: 'wifi: hunter2' });
const sid = (await call('POST', '/sends', { enc, expire_hours: 1, max_views: 2, password: 'pin1234', note: 'for accountant' }, A2)).j.id;
assert.deepEqual(Object.keys((await call('GET', '/send/' + sid)).j).sort(), ['expires', 'needs_password']);
assert.equal((await call('POST', `/send/${sid}/access`, { password: 'nope' })).s, 401);
r = await call('POST', `/send/${sid}/access`, { password: 'pin1234' });
assert.equal(r.s, 200); assert.equal(r.j.views_left, 1); assert.equal((await C.sendDecrypt(r.j.enc, key)).text, 'wifi: hunter2'); ok('Send decrypts with the fragment key');
await assert.rejects(C.sendDecrypt(r.j.enc, C.b64url(new Uint8Array(32)))); ok('wrong key cannot decrypt');
const mine = (await call('GET', '/sends', null, A2)).j; assert.equal(mine[0].note, 'for accountant'); assert.equal(mine[0].views, 1); assert.ok(!('enc' in mine[0]));
const actA = (await call('GET', '/account/activity', null, A2)).j.filter((x) => x.action.startsWith('user.send')); assert.ok(actA.every((x) => !x.detail.includes(sid))); ok('Send ids are not written to the log');
await call('DELETE', '/sends/' + sid, null, Bt3); assert.equal((await call('GET', '/send/' + sid)).s, 200); ok('others cannot delete my Send');
assert.equal((await call('POST', `/send/${sid}/access`, { password: 'pin1234' })).s, 200);
assert.equal((await call('POST', `/send/${sid}/access`, { password: 'pin1234' })).s, 404); ok('view limit enforced');
const s2 = (await call('POST', '/sends', { enc, expire_hours: 1 }, A2)).j.id;
for (let i = 0; i < 5; i++) await call('POST', `/send/${s2}/access`, { password: 'x' });   // no password set: these succeed, unlimited views
assert.equal((await call('POST', `/send/${s2}/access`, {})).s, 200);
await call('DELETE', '/sends/' + s2, null, A2); assert.equal((await call('GET', '/send/' + s2)).s, 404); ok('Send delete');
const s3 = (await call('POST', '/sends', { enc, expire_hours: 1, password: 'right' }, A2)).j.id;
for (let i = 0; i < 5; i++) await call('POST', `/send/${s3}/access`, { password: 'wrong' });
assert.equal((await call('POST', `/send/${s3}/access`, { password: 'right' })).s, 429); ok('Send locks after 5 wrong passwords');

// ---- snapshots
const vk = await C.newVaultKey();
const me = (await call('GET', '/vaults', null, A2)).j;
const vid = (await call('POST', '/vaults', { enc_name: await C.encJSON(vk, { name: 'Finance' }), wrapped_key: await C.wrapVaultKey(vk, a.j.user.public_key) }, A2)).j.id;
const i1 = (await call('POST', `/vaults/${vid}/items`, { data: await C.encJSON(vk, { title: 'Bank' }) }, A2)).j;
assert.equal((await call('GET', `/vaults/${vid}/snapshots`, null, A2)).j.length, 0); // empty vault at first write: nothing to keep
const i2 = (await call('POST', `/vaults/${vid}/items`, { data: await C.encJSON(vk, { title: 'Post office' }) }, A2)).j;
let snaps = (await call('GET', `/vaults/${vid}/snapshots`, null, A2)).j; assert.equal(snaps.length, 1); assert.equal(snaps[0].count, 1);
// editor "vandalism": add member B as editor, B trashes + deletes Bank
await call('POST', `/vaults/${vid}/members`, { user_id: b.j.user.id, role: 'editor', wrapped_key: await C.wrapVaultKey(vk, b.j.user.public_key) }, A2);
await call('POST', `/vaults/${vid}/accept`, null, Bt3);
const t = await call('PUT', `/vaults/${vid}/items/${i1.id}`, { data: i1.data, rev: i1.rev, trashed: true }, Bt3); assert.equal(t.s, 200);
assert.equal((await call('DELETE', `/vaults/${vid}/items/${i1.id}`, null, Bt3)).s, 200);
assert.equal((await call('GET', `/vaults/${vid}/snapshots`, null, Bt3)).s, 403); ok('only owners see snapshots');
r = await call('POST', `/vaults/${vid}/snapshots/${snaps[0].id}/restore`, null, A2);
assert.equal(r.s, 200); assert.equal(r.j.restored, 1);
const items = (await call('GET', `/vaults/${vid}/items`, null, A2)).j;
assert.deepEqual(items.map((x) => x.id).sort(), [i1.id, i2.id].sort()); assert.equal((await C.decJSON(vk, items.find((x) => x.id === i1.id).data)).title, 'Bank'); ok('restore brings a deleted item back, later items stay');
snaps = (await call('GET', `/vaults/${vid}/snapshots`, null, A2)).j; assert.ok(snaps.some((x) => x.reason === 'before restore'));
// key rotation clears snapshots (old key)
await call('DELETE', `/vaults/${vid}/members/${b.j.user.id}`, null, A2);
const nk = await C.newVaultKey(); const raw = (await call('GET', `/vaults/${vid}/items`, null, A2)).j;
const ritems = []; for (const it of raw) ritems.push({ id: it.id, data: await C.encJSON(nk, await C.decJSON(vk, it.data)) });
assert.equal((await call('POST', `/vaults/${vid}/rotate`, { enc_name: await C.encJSON(nk, { name: 'Finance' }), wrapped_keys: { [a.j.user.id]: await C.wrapVaultKey(nk, a.j.user.public_key) }, items: ritems, expect_members: [a.j.user.id] }, A2)).s, 200);
assert.equal((await call('GET', `/vaults/${vid}/snapshots`, null, A2)).j.length, 0); ok('key rotation drops snapshots under the old key');

// ---- backup file + passphrase
const bk = await C.backupEncrypt('backup password 12', { items: [{ vault: 'Finance', data: { title: 'Bank' } }] });
assert.equal((await C.backupDecrypt('backup password 12', bk)).items[0].data.title, 'Bank');
await assert.rejects(C.backupDecrypt('wrong password!!', bk), /Wrong backup password/); ok('encrypted backup round trip');
const words = C.parseWordlist('11111\tabacus\n11112\tabdomen\n'); assert.match(C.passphrase(words, { count: 4, sep: '-', capitalize: true, number: false }), /^(Abacus|Abdomen)(-(Abacus|Abdomen)){3}$/); ok('passphrase');
// ---- attachments (encrypted per file, stored as opaque blobs)
const rawCall = async (m, p, body, tok) => { const r = await fetch(B + '/api' + p, { method: m, headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/octet-stream' }, body }); return { s: r.status, buf: r.ok && m === 'GET' ? new Uint8Array(await r.arrayBuffer()) : null }; };
const vk2 = await C.newVaultKey();
const v2 = (await call('POST', '/vaults', { enc_name: await C.encJSON(vk2, { name: 'Docs' }), wrapped_key: await C.wrapVaultKey(vk2, a.j.user.public_key) }, A2)).j.id;
const file = new TextEncoder().encode('contract scan '.repeat(1000));
const { blob, key: fkey } = await C.fileEncrypt(file);
const aid = 'ab'.repeat(16);
assert.equal((await rawCall('PUT', `/vaults/${v2}/attachments/${aid}`, blob, Bt3)).s, 404); ok('non-member cannot upload');
assert.equal((await rawCall('PUT', `/vaults/${v2}/attachments/../../x`, blob, A2)).s >= 400, true);
assert.equal((await rawCall('PUT', `/vaults/${v2}/attachments/${aid}`, blob, A2)).s, 200);
assert.equal((await rawCall('PUT', `/vaults/${v2}/attachments/${aid}`, blob, A2)).s, 409); ok('upload; ids cannot be overwritten');
await call('POST', `/vaults/${v2}/members`, { user_id: b.j.user.id, role: 'viewer', wrapped_key: await C.wrapVaultKey(vk2, b.j.user.public_key) }, A2);
await call('POST', `/vaults/${v2}/accept`, null, Bt3);
const got = await rawCall('GET', `/vaults/${v2}/attachments/${aid}`, null, Bt3);
assert.equal(got.s, 200); assert.equal(new TextDecoder().decode(await C.fileDecrypt(got.buf, fkey)), 'contract scan '.repeat(1000)); ok('viewer downloads and decrypts');
assert.ok(!new TextDecoder().decode(got.buf).includes('contract')); ok('server only holds ciphertext');
assert.equal((await rawCall('PUT', `/vaults/${v2}/attachments/${'cd'.repeat(16)}`, blob, Bt3)).s, 403); ok('viewer cannot upload');
assert.equal((await call('DELETE', `/vaults/${v2}/attachments/${aid}`, null, Bt3)).s, 403);
assert.equal((await call('DELETE', `/vaults/${v2}/attachments/${aid}`, null, A2)).s, 200);
assert.equal((await rawCall('GET', `/vaults/${v2}/attachments/${aid}`, null, A2)).s, 200); ok('deleted files stay restorable (snapshot window)');
assert.equal((await rawCall('PUT', `/vaults/${v2}/attachments/${'ef'.repeat(16)}`, new Uint8Array(26 * 1024 * 1024), A2)).s, 413); ok('25 MB limit');
await call('DELETE', `/vaults/${v2}`, null, A2);
assert.equal((await rawCall('GET', `/vaults/${v2}/attachments/${aid}`, null, A2)).s, 404); ok('vault delete removes its files');

console.log('\nALL FEATURE TESTS PASSED');
