// Kasa client-side crypto. Everything secret is derived / encrypted here;
// the server only receives ciphertext and a derived "auth" value.
const enc = new TextEncoder(), dec = new TextDecoder();
const subtle = crypto.subtle;

export const b64 = (buf) => { const a = new Uint8Array(buf); let s = ''; for (const x of a) s += String.fromCharCode(x); return btoa(s); };
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const ITERS = 600000;

// password -> { masterKey (AES-GCM, non-extractable), auth (b64 sent to server) }
export async function deriveKeys(password, saltB64, iters) {
  const base = await subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iters }, base, 512));
  const masterKey = await subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const auth = b64(bits.slice(32));   // second half: server never learns the first half
  return { masterKey, auth };
}

export const randomSalt = () => b64(crypto.getRandomValues(new Uint8Array(16)));

async function aesEncrypt(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return b64(out);
}
async function aesDecrypt(key, s) {
  const all = unb64(s);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12) }, key, all.slice(12)));
}
export const encJSON = (key, obj) => aesEncrypt(key, enc.encode(JSON.stringify(obj)));
export const decJSON = async (key, s) => JSON.parse(dec.decode(await aesDecrypt(key, s)));

// ---- user identity keypair (RSA-OAEP): public key shared, private key wrapped by master key
export async function newIdentity(masterKey) {
  const kp = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const pub = b64(await subtle.exportKey('spki', kp.publicKey));
  const priv = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
  return { public_key: pub, enc_private_key: await aesEncrypt(masterKey, priv) };
}
export async function rewrapPrivate(oldMaster, newMaster, encPriv) {
  return aesEncrypt(newMaster, await aesDecrypt(oldMaster, encPriv));
}
export async function loadPrivate(masterKey, encPriv) {
  const pkcs8 = await aesDecrypt(masterKey, encPriv);
  return subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}
const importPub = (b) => subtle.importKey('spki', unb64(b), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);

export async function fingerprint(pubB64) {
  const h = new Uint8Array(await subtle.digest('SHA-256', unb64(pubB64)));
  return [...h.slice(0, 10)].map((x) => x.toString(16).padStart(2, '0')).join('').match(/.{4}/g).join(' ');
}

// ---- vault keys (AES-256-GCM), wrapped per member with RSA-OAEP
export const newVaultKey = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
export async function wrapVaultKey(vaultKey, pubB64) {
  const raw = await subtle.exportKey('raw', vaultKey);
  return b64(await subtle.encrypt({ name: 'RSA-OAEP' }, await importPub(pubB64), raw));
}
export async function unwrapVaultKey(wrapped, privKey) {
  const raw = await subtle.decrypt({ name: 'RSA-OAEP' }, privKey, unb64(wrapped));
  return subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt', 'decrypt']);
}

// ---- password generation (rejection sampling => no modulo bias)
function randInt(n) {
  const lim = Math.floor(0x100000000 / n) * n; const a = new Uint32Array(1);
  do { crypto.getRandomValues(a); } while (a[0] >= lim);
  return a[0] % n;
}
export function generatePassword({ length = 20, lower = true, upper = true, digits = true, symbols = true, avoidAmbiguous = true } = {}) {
  let sets = [];
  const amb = (s) => (avoidAmbiguous ? s.replace(/[Il1O0o]/g, '') : s);
  if (lower) sets.push(amb('abcdefghijklmnopqrstuvwxyz'));
  if (upper) sets.push(amb('ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
  if (digits) sets.push(amb('0123456789'));
  if (symbols) sets.push('!@#$%^&*()-_=+[]{};:,.?');
  if (!sets.length) sets = [amb('abcdefghijklmnopqrstuvwxyz')];
  const all = sets.join('');
  const out = sets.map((s) => s[randInt(s.length)]);          // at least one of each chosen class
  while (out.length < length) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.slice(0, Math.max(length, sets.length)).join('');
}

// ---- strength estimate (bits) with penalties for repetition and common patterns
const COMMON = ['password', 'parola', 'sifre', 'şifre', 'qwerty', '123456', 'admin', 'letmein', 'welcome', 'iloveyou', 'kasa', 'istanbul', 'ankara', 'galatasaray', 'fenerbahce', 'besiktas'];
export function strength(pw) {
  if (!pw) return { bits: 0, label: '', level: 0 };
  let pool = 0;
  if (/[a-zçğıöşü]/.test(pw)) pool += 29; if (/[A-ZÇĞİÖŞÜ]/.test(pw)) pool += 29;
  if (/\d/.test(pw)) pool += 10; if (/[^\w\sçğıöşüÇĞİÖŞÜ]|_/.test(pw)) pool += 30;
  let bits = pw.length * Math.log2(Math.max(pool, 2));
  const uniq = new Set(pw).size; bits *= Math.min(1, 0.4 + uniq / pw.length * 0.6);
  const low = pw.toLowerCase();
  if (COMMON.some((c) => low.includes(c))) bits = pw.length < 16 ? Math.min(bits, 28) : bits - 15;
  if (/(.)\1{2,}/.test(pw) || /(012|123|234|345|456|567|678|789|abc|bcd|cde)/i.test(pw)) bits *= 0.75;
  bits = Math.round(bits);
  const level = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { bits, level, label: ['', 'Zayıf', 'Orta', 'Güçlü', 'Çok güçlü'][level] };
}

// ---- Have I Been Pwned (k-anonymity: only the first 5 SHA-1 hex chars leave the browser)
export async function pwnedCount(pw) {
  const h = [...new Uint8Array(await subtle.digest('SHA-1', enc.encode(pw)))].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();
  const r = await fetch('https://api.pwnedpasswords.com/range/' + h.slice(0, 5), { headers: { 'Add-Padding': 'true' } });
  if (!r.ok) throw new Error('HIBP');
  for (const line of (await r.text()).split('\n')) {
    const [suf, n] = line.trim().split(':');
    if (suf === h.slice(5)) return parseInt(n, 10);
  }
  return 0;
}

// ---- TOTP (RFC 6238)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  s = s.replace(/[\s=-]/g, '').toUpperCase(); let bits = '';
  for (const c of s) { const i = B32.indexOf(c); if (i < 0) throw new Error('bad base32'); bits += i.toString(2).padStart(5, '0'); }
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}
export function parseTotp(input) {
  input = (input || '').trim(); if (!input) return null;
  let secret = input, digits = 6, period = 30, algo = 'SHA-1';
  if (input.startsWith('otpauth://')) {
    const u = new URL(input); secret = u.searchParams.get('secret') || '';
    digits = +(u.searchParams.get('digits') || 6); period = +(u.searchParams.get('period') || 30);
    algo = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[(u.searchParams.get('algorithm') || 'SHA1').toUpperCase()] || 'SHA-1';
  }
  return { secret, digits, period, algo };
}
export async function totp(input, now = Date.now()) {
  const p = parseTotp(input); if (!p) return null;
  const key = await subtle.importKey('raw', b32decode(p.secret), { name: 'HMAC', hash: p.algo }, false, ['sign']);
  const counter = Math.floor(now / 1000 / p.period);
  const msg = new ArrayBuffer(8); new DataView(msg).setUint32(4, counter); new DataView(msg).setUint32(0, Math.floor(counter / 2 ** 32));
  const h = new Uint8Array(await subtle.sign('HMAC', key, msg));
  const o = h[h.length - 1] & 15;
  const code = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** p.digits;
  return { code: String(code).padStart(p.digits, '0'), remaining: p.period - (Math.floor(now / 1000) % p.period), period: p.period };
}
