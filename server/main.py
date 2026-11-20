"""Vaultly - zero-knowledge team password manager (server).

The server only ever stores ciphertext. All vault/item encryption happens in
the browser (see web/crypto.js). The server enforces authentication, roles,
optimistic locking and keeps an audit trail of who changed what.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DATA_DIR = Path(os.environ.get("KASA_DATA", Path(__file__).parent.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "kasa.db"
WEB_DIR = Path(__file__).parent.parent / "web"
SESSION_TTL = 12 * 3600
INVITE_TTL = 7 * 86400
MAX_BLOB = 256 * 1024
DEFAULT_ITERS = 600_000

SECRET_FILE = DATA_DIR / "secret.key"
if not SECRET_FILE.exists():
    SECRET_FILE.write_bytes(secrets.token_bytes(32))
    SECRET_FILE.chmod(0o600)
SERVER_SECRET = SECRET_FILE.read_bytes()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  salt TEXT NOT NULL, iters INTEGER NOT NULL, auth_hash TEXT NOT NULL,
  public_key TEXT NOT NULL, enc_private_key TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS invites(
  code TEXT PRIMARY KEY, created_by TEXT NOT NULL, email TEXT, expires REAL NOT NULL,
  used_by TEXT);
CREATE TABLE IF NOT EXISTS vaults(
  id TEXT PRIMARY KEY, enc_name TEXT NOT NULL, created_by TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS members(
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('owner','editor','viewer')),
  wrapped_key TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', invited_by TEXT, PRIMARY KEY(vault_id,user_id));
CREATE TABLE IF NOT EXISTS items(
  id TEXT PRIMARY KEY, vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  data TEXT NOT NULL, trashed INTEGER NOT NULL DEFAULT 0, rev INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL, updated_by TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS items_vault ON items(vault_id);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, user_id TEXT, vault_id TEXT,
  action TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS audit_vault ON audit(vault_id, ts);
CREATE TABLE IF NOT EXISTS sends(
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, enc TEXT NOT NULL, size INTEGER NOT NULL,
  created REAL NOT NULL, expires REAL NOT NULL, max_views INTEGER, views INTEGER NOT NULL DEFAULT 0,
  pw_salt TEXT, pw_hash TEXT, fails INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0, note TEXT);
CREATE TABLE IF NOT EXISTS snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT, vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE, at REAL NOT NULL,
  reason TEXT NOT NULL, key_version INTEGER NOT NULL, enc_name TEXT NOT NULL, items TEXT NOT NULL, count INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS snapshots_vault ON snapshots(vault_id, at);
"""


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


with db() as _c:
    _c.execute("PRAGMA journal_mode=WAL")
    _c.executescript(SCHEMA)
    try:
        _c.execute("ALTER TABLE members ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    except sqlite3.OperationalError:
        pass  # already present
    try:
        _c.execute("ALTER TABLE members ADD COLUMN invited_by TEXT")
    except sqlite3.OperationalError:
        pass
    for _t, _col, _ddl in (("users", "totp_secret", "TEXT"), ("users", "totp_pending", "TEXT"), ("users", "totp_last", "INTEGER NOT NULL DEFAULT 0"),
                           ("users", "recovery", "TEXT"), ("sessions", "created", "REAL"), ("sessions", "last_seen", "REAL"),
                           ("sessions", "ip", "TEXT"), ("sessions", "agent", "TEXT"), ("vaults", "key_version", "INTEGER NOT NULL DEFAULT 1")):
        if _col not in {r[1] for r in _c.execute(f"PRAGMA table_info({_t})")}:
            _c.execute(f"ALTER TABLE {_t} ADD COLUMN {_col} {_ddl}")

app = FastAPI(title="Vaultly", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- helpers
_fails: dict = {}  # key -> (count, first_ts)


def throttle(key: str, limit: int = 8, window: int = 300):
    n, ts = _fails.get(key, (0, time.time()))
    if time.time() - ts > window:
        n, ts = 0, time.time()
    if n >= limit:
        wait = max(1, int(window - (time.time() - ts)))
        raise HTTPException(429, "Too many attempts. Please try again shortly.", headers={"Retry-After": str(wait)})


def fail(key: str, window: int = 300):
    n, ts = _fails.get(key, (0, time.time()))
    if time.time() - ts > window:
        n, ts = 0, time.time()
    _fails[key] = (n + 1, ts)


def _trusted_proxy(ip: str) -> bool:
    """Is the TCP peer one of our reverse proxies? KASA_TRUSTED_PROXIES = comma-separated CIDRs.
    Default: loopback + private ranges (only our own proxy can reach the container there)."""
    import ipaddress
    nets = os.environ.get("KASA_TRUSTED_PROXIES", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7")
    try:
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(n.strip(), strict=False) for n in nets.split(",") if n.strip())
    except ValueError:
        return False


def client_ip(request: Request) -> str:
    """Real client IP. Without a reverse proxy: the socket peer. Behind KASA_PROXY_HOPS trusted proxies
    that APPEND to X-Forwarded-For, take the hops-th entry from the RIGHT: everything left of it is
    client-supplied and spoofable, the entries our own proxies appended are not."""
    peer = request.client.host if request.client else "?"
    hdr = os.environ.get("KASA_CLIENT_IP_HEADER", "")   # e.g. fly-client-ip: a header the platform proxy sets itself
    if hdr and _trusted_proxy(peer) and request.headers.get(hdr):
        return request.headers[hdr].split(",")[0].strip()
    hops = int(os.environ.get("KASA_PROXY_HOPS", "0") or 0)
    if hops > 0 and _trusted_proxy(peer):   # header is only meaningful when the TCP peer is our own proxy
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return peer


def norm_email(e: str) -> str:
    return e.strip().lower()


def hash_auth(auth_b64: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    h = hashlib.scrypt(auth_b64.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_auth(auth_b64: str, stored: str) -> bool:
    salt_b64, _ = stored.split("$")
    return hmac.compare_digest(hash_auth(auth_b64, base64.b64decode(salt_b64)), stored)


_known_ips: dict = {}  # email -> {ip: expiry}; in memory, resets on restart
KNOWN_TTL = 14 * 86400


def is_known_ip(email: str, ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        if a.is_loopback or a.is_private:   # could be our own reverse proxy: never trust as a device identity
            return False
    except ValueError:
        return False
    return _known_ips.get(email, {}).get(ip, 0) > time.time()

DUMMY_HASH = hash_auth("dummy")


def log(con, user_id, vault_id, action, detail=""):
    con.execute("INSERT INTO audit(ts,user_id,vault_id,action,detail) VALUES(?,?,?,?,?)",
                (time.time(), user_id, vault_id, action, detail))


def short_agent(ua: str) -> str:
    """'Firefox on Android' style label for the session list (never rendered as HTML)."""
    ua = ua or ""
    b = next((n for k, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari"), ("node", "script"), ("curl/", "curl")) if k in ua), "unknown browser")
    o = next((n for k, n in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"), ("Windows", "Windows"), ("Mac OS", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux")) if k in ua), "")
    return b + (" on " + o if o else "")


def new_session(con, user_id, request: Optional[Request] = None) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    con.execute("INSERT INTO sessions(token_hash,user_id,expires,created,last_seen,ip,agent) VALUES(?,?,?,?,?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), user_id, now + SESSION_TTL, now, now,
                 client_ip(request) if request else None, short_agent(request.headers.get("user-agent", "")) if request else None))
    con.execute("DELETE FROM sessions WHERE expires<?", (now,))
    return token


# ---- two-factor sign-in (RFC 6238 TOTP, SHA-1, 6 digits, 30 s) + single-use recovery codes ----
def totp_at(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    hm = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    o = hm[-1] & 15
    return str((int.from_bytes(hm[o:o + 4], "big") & 0x7FFFFFFF) % 1_000_000).zfill(6)


def totp_match(secret_b32: str, code: str, after: int = 0) -> Optional[int]:
    """Counter of the matching step (now, or one step either side), refusing steps already used (replay)."""
    now = int(time.time() // 30)
    for c in (now - 1, now, now + 1):
        if c > after and hmac.compare_digest(totp_at(secret_b32, c), code):
            return c
    return None


def recovery_hash(code: str) -> str:
    return hmac.new(SERVER_SECRET, code.replace("-", "").replace(" ", "").lower().encode(), "sha256").hexdigest()


def new_recovery_codes() -> tuple[list[str], str]:
    codes = ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(8)]
    return codes, json.dumps([recovery_hash(c) for c in codes])


def check_second_factor(con, u, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if code.isdigit() and len(code) == 6:
        c = totp_match(u["totp_secret"], code, u["totp_last"] or 0)
        if c is not None:
            con.execute("UPDATE users SET totp_last=? WHERE id=?", (c, u["id"]))
            return True
        return False
    hashes = json.loads(u["recovery"] or "[]")
    h = recovery_hash(code)
    if h in hashes:
        hashes.remove(h)
        con.execute("UPDATE users SET recovery=? WHERE id=?", (json.dumps(hashes), u["id"]))
        log(con, u["id"], None, "user.2fa_recovery_used", f"{len(hashes)} left")
        return True
    return False


def user_public(u) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u["name"], "is_admin": bool(u["is_admin"]),
            "public_key": u["public_key"], "enc_private_key": u["enc_private_key"], "totp": bool(u["totp_secret"])}


def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign-in required")
    th = hashlib.sha256(authorization[7:].encode()).hexdigest()
    with db() as con:
        row = con.execute(
            "SELECT u.*, s.last_seen AS _seen FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires>? AND u.disabled=0", (th, time.time())).fetchone()
    if not row:
        raise HTTPException(401, "Session expired")
    if (row["_seen"] or 0) < time.time() - 300:   # cheap "last active" for the session list
        with db() as con:
            con.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (time.time(), th))
    return dict(row) | {"_th": th}


def admin_user(u=Depends(current_user)):
    if not u["is_admin"]:
        raise HTTPException(403, "Administrator access required")
    return u


def role_of(con, vault_id, user_id) -> Optional[str]:
    r = con.execute("SELECT role FROM members WHERE vault_id=? AND user_id=? AND status='active'", (vault_id, user_id)).fetchone()
    return r["role"] if r else None


def need(con, vault_id, user, *roles):
    r = role_of(con, vault_id, user["id"])
    if r is None:
        raise HTTPException(404, "Vault not found")
    if roles and r not in roles:
        raise HTTPException(403, "You don't have permission to do this")
    return r


# ---------------------------------------------------------------- models
class Register(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    salt: str = Field(max_length=64)
    iters: int = Field(ge=100_000, le=5_000_000)
    auth: str = Field(min_length=20, max_length=200)
    public_key: str = Field(max_length=2000)
    enc_private_key: str = Field(max_length=8000)
    invite: Optional[str] = None


class Login(BaseModel):
    email: str
    auth: str = Field(max_length=200)
    code: Optional[str] = Field(default=None, max_length=40)   # 2FA code or recovery code


class ChangePw(BaseModel):
    old_auth: str
    new_auth: str = Field(min_length=20, max_length=200)
    new_salt: str = Field(max_length=64)
    new_iters: int = Field(ge=100_000, le=5_000_000)
    enc_private_key: str = Field(max_length=8000)


class NewVault(BaseModel):
    enc_name: str = Field(max_length=2000)
    wrapped_key: str = Field(max_length=2000)


class Rename(BaseModel):
    enc_name: str = Field(max_length=2000)


class AddMember(BaseModel):
    user_id: str
    role: str = Field(pattern="^(owner|editor|viewer)$")
    wrapped_key: str = Field(max_length=2000)


class SetRole(BaseModel):
    role: str = Field(pattern="^(owner|editor|viewer)$")


class ItemIn(BaseModel):
    data: str = Field(max_length=MAX_BLOB)
    rev: Optional[int] = None
    trashed: Optional[bool] = None


class Rotate(BaseModel):
    enc_name: str
    wrapped_keys: dict
    items: list
    expect_members: list


class InviteIn(BaseModel):
    email: Optional[str] = None


# ---------------------------------------------------------------- auth
@app.get("/api/status")
def status():
    with db() as con:
        n = con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    return {"setup": n == 0}


@app.get("/api/prelogin")
def prelogin(email: str, request: Request):
    throttle("pre:" + client_ip(request), 40)
    fail("pre:" + client_ip(request))
    email = norm_email(email)
    with db() as con:
        u = con.execute("SELECT salt,iters FROM users WHERE email=?", (email,)).fetchone()
    if u:
        return {"salt": u["salt"], "iters": u["iters"]}
    fake = hmac.new(SERVER_SECRET, email.encode(), "sha256").digest()[:16]  # no user enumeration
    return {"salt": base64.b64encode(fake).decode(), "iters": DEFAULT_ITERS}


@app.post("/api/register")
def register(body: Register, request: Request):
    throttle("reg:" + client_ip(request), 10)
    fail("reg:" + client_ip(request))
    email = norm_email(body.email)
    if "@" not in email:
        raise HTTPException(400, "Invalid email")
    with db() as con:
        con.execute("BEGIN IMMEDIATE")  # serialises first-admin bootstrap and invite claiming
        count = con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "This email is already registered")
        if count > 0:
            inv = con.execute("SELECT * FROM invites WHERE code=? AND used_by IS NULL AND expires>?",
                              (body.invite or "", time.time())).fetchone()
            if not inv or (inv["email"] and inv["email"] != email):
                raise HTTPException(403, "Invalid or expired invite code")
        uid = uuid.uuid4().hex
        con.execute("INSERT INTO users(id,email,name,salt,iters,auth_hash,public_key,enc_private_key,is_admin,disabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,0,?)",
                    (uid, email, body.name.strip(), body.salt, body.iters, hash_auth(body.auth),
                     body.public_key, body.enc_private_key, 1 if count == 0 else 0, time.time()))
        if count > 0:
            claimed = con.execute("UPDATE invites SET used_by=? WHERE code=? AND used_by IS NULL AND expires>?",
                                  (uid, body.invite, time.time()))
            if claimed.rowcount != 1:
                raise HTTPException(403, "Invalid or expired invite code")
        log(con, uid, None, "user.register", email)
        u = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return {"token": new_session(con, uid, request), "user": user_public(u)}


@app.post("/api/login")
def login(body: Login, request: Request):
    email = norm_email(body.email)
    key = "login:" + client_ip(request) + ":" + email
    acct = "acct:" + email  # per-account limit: rotating IPs does not reset it
    throttle(key)                 # per IP+account: 8 failures / 5 min
    ip = client_ip(request)
    if not is_known_ip(email, ip):   # IPs that logged in before bypass the account-wide cap, so an outsider cannot lock you out
        throttle(acct, 30, 900)       # per account across all IPs: 30 failures / 15 min, then 429 + Retry-After (self-expiring)
    with db() as con:
        u = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        ok = verify_auth(body.auth, u["auth_hash"] if u else DUMMY_HASH) and u is not None and not u["disabled"]
        if not ok:
            fail(key); fail(acct, 900)
            if u is not None:
                log(con, u["id"], None, "user.login_failed", client_ip(request))
                con.commit()   # the context manager rolls back on the exception below
            raise HTTPException(401, "Incorrect email or master password")
        if u["totp_secret"]:
            if not body.code:
                raise HTTPException(401, "2FA_REQUIRED")   # the client then asks for the code and sends everything again
            if not check_second_factor(con, u, body.code):
                fail(key); fail(acct, 900)
                log(con, u["id"], None, "user.login_failed", client_ip(request) + " (wrong 2FA code)")
                con.commit()
                raise HTTPException(401, "Incorrect two-factor code")
        _fails.pop(key, None); _fails.pop(acct, None)
        known = _known_ips.setdefault(email, {})
        known = {k: v for k, v in known.items() if v > time.time()}
        if len(known) < 10 or ip in known:
            known[ip] = time.time() + KNOWN_TTL
        _known_ips[email] = known
        log(con, u["id"], None, "user.login", client_ip(request) + " · " + short_agent(request.headers.get("user-agent", "")))
        u = con.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
        return {"token": new_session(con, u["id"], request), "user": user_public(u)}


@app.post("/api/logout")
def logout(u=Depends(current_user)):
    with db() as con:
        con.execute("DELETE FROM sessions WHERE token_hash=?", (u["_th"],))
    return {"ok": True}


@app.post("/api/password")
def change_password(body: ChangePw, u=Depends(current_user)):
    throttle("pw:" + u["id"])
    if not verify_auth(body.old_auth, u["auth_hash"]):
        fail("pw:" + u["id"])
        raise HTTPException(403, "Current master password is incorrect")
    with db() as con:
        con.execute("UPDATE users SET salt=?,iters=?,auth_hash=?,enc_private_key=? WHERE id=?",
                    (body.new_salt, body.new_iters, hash_auth(body.new_auth), body.enc_private_key, u["id"]))
        con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?", (u["id"], u["_th"]))
        _known_ips.pop(u["email"], None)
        log(con, u["id"], None, "user.password_change")
    return {"ok": True}


# ---------------------------------------------------------------- account security
class AuthOnly(BaseModel):
    auth: str = Field(max_length=200)


class CodeIn(BaseModel):
    code: str = Field(max_length=20)


def reverify(u, auth: str):
    """Sensitive account changes need the master password again (a stolen session alone is not enough)."""
    throttle("re:" + u["id"])
    if not verify_auth(auth, u["auth_hash"]):
        fail("re:" + u["id"])
        raise HTTPException(403, "Master password is incorrect")


@app.get("/api/account/sessions")
def my_sessions(u=Depends(current_user)):
    with db() as con:
        rows = con.execute("SELECT token_hash,created,last_seen,ip,agent FROM sessions WHERE user_id=? AND expires>? ORDER BY last_seen DESC",
                           (u["id"], time.time())).fetchall()
    return [{"id": r["token_hash"][:16], "created": r["created"], "last_seen": r["last_seen"], "ip": r["ip"], "agent": r["agent"],
             "current": r["token_hash"] == u["_th"]} for r in rows]


@app.delete("/api/account/sessions/{sid}")
def end_session(sid: str, u=Depends(current_user)):
    if len(sid) != 16 or not all(c in "0123456789abcdef" for c in sid):
        raise HTTPException(400, "Bad session id")
    with db() as con:
        n = con.execute("DELETE FROM sessions WHERE user_id=? AND substr(token_hash,1,16)=? AND token_hash!=?", (u["id"], sid, u["_th"])).rowcount
        log(con, u["id"], None, "user.session_end", str(n))
    return {"ended": n}


@app.delete("/api/account/sessions")
def end_other_sessions(u=Depends(current_user)):
    with db() as con:
        n = con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?", (u["id"], u["_th"])).rowcount
        _known_ips.pop(u["email"], None)
        log(con, u["id"], None, "user.sessions_end_all", str(n))
    return {"ended": n}


@app.get("/api/account/activity")
def my_activity(u=Depends(current_user)):
    with db() as con:
        rows = con.execute("SELECT ts,action,detail FROM audit WHERE user_id=? AND action LIKE 'user.%' ORDER BY id DESC LIMIT 60", (u["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/2fa/setup")
def twofa_setup(body: AuthOnly, u=Depends(current_user)):
    reverify(u, body.auth)
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    with db() as con:
        con.execute("UPDATE users SET totp_pending=? WHERE id=?", (secret, u["id"]))
    from urllib.parse import quote
    return {"secret": secret, "uri": f"otpauth://totp/Vaultly:{quote(u['email'])}?secret={secret}&issuer=Vaultly"}


@app.post("/api/2fa/enable")
def twofa_enable(body: CodeIn, u=Depends(current_user)):
    if not u["totp_pending"]:
        raise HTTPException(400, "Start the setup first")
    c = totp_match(u["totp_pending"], body.code.strip().replace(" ", ""))
    if c is None:
        raise HTTPException(400, "That code is not right. Check the time on your phone and try the newest code.")
    codes, hashed = new_recovery_codes()
    with db() as con:
        con.execute("UPDATE users SET totp_secret=totp_pending, totp_pending=NULL, totp_last=?, recovery=? WHERE id=?", (c, hashed, u["id"]))
        log(con, u["id"], None, "user.2fa_on")
    return {"recovery_codes": codes}


@app.post("/api/2fa/disable")
def twofa_disable(body: AuthOnly, u=Depends(current_user)):
    reverify(u, body.auth)
    with db() as con:
        con.execute("UPDATE users SET totp_secret=NULL, totp_pending=NULL, recovery=NULL WHERE id=?", (u["id"],))
        log(con, u["id"], None, "user.2fa_off")
    return {"ok": True}


@app.post("/api/2fa/recovery")
def twofa_new_codes(body: AuthOnly, u=Depends(current_user)):
    reverify(u, body.auth)
    if not u["totp_secret"]:
        raise HTTPException(400, "Two-factor sign-in is off")
    codes, hashed = new_recovery_codes()
    with db() as con:
        con.execute("UPDATE users SET recovery=? WHERE id=?", (hashed, u["id"]))
        log(con, u["id"], None, "user.2fa_new_codes")
    return {"recovery_codes": codes, "left": len(codes)}


@app.get("/api/2fa/status")
def twofa_status(u=Depends(current_user)):
    return {"on": bool(u["totp_secret"]), "recovery_left": len(json.loads(u["recovery"] or "[]"))}


# ---------------------------------------------------------------- admin
@app.get("/api/admin/users")
def list_users(_=Depends(admin_user)):
    with db() as con:
        rows = con.execute("SELECT id,email,name,is_admin,disabled,created_at,(totp_secret IS NOT NULL) AS totp FROM users ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/users/{uid}/disable")
def disable_user(uid: str, disable: bool = True, u=Depends(admin_user)):
    if uid == u["id"]:
        raise HTTPException(400, "You cannot disable yourself")
    with db() as con:
        con.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disable else 0, uid))
        if disable:
            con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            row = con.execute("SELECT email FROM users WHERE id=?", (uid,)).fetchone()
            if row:
                _known_ips.pop(row["email"], None)
        log(con, u["id"], None, "user.disable" if disable else "user.enable", uid)
    return {"ok": True}


@app.post("/api/admin/users/{uid}/admin")
def set_admin(uid: str, admin: bool, u=Depends(admin_user)):
    with db() as con:
        if not admin and con.execute("SELECT COUNT(*) c FROM users WHERE is_admin=1 AND disabled=0").fetchone()["c"] <= 1:
            raise HTTPException(400, "At least one administrator must remain")
        con.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if admin else 0, uid))
        log(con, u["id"], None, "user.admin" if admin else "user.unadmin", uid)
    return {"ok": True}


@app.post("/api/admin/users/{uid}/reset-2fa")
def admin_reset_2fa(uid: str, u=Depends(admin_user)):
    """For a member who lost both phone and recovery codes. Their data stays protected by the master password."""
    with db() as con:
        n = con.execute("UPDATE users SET totp_secret=NULL, totp_pending=NULL, recovery=NULL WHERE id=?", (uid,)).rowcount
        if not n:
            raise HTTPException(404, "User not found")
        con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        log(con, u["id"], None, "user.2fa_reset_by_admin", uid)
    return {"ok": True}


@app.get("/api/admin/invites")
def list_invites(_=Depends(admin_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM invites WHERE used_by IS NULL AND expires>? ORDER BY expires", (time.time(),)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/invites")
def create_invite(body: InviteIn, u=Depends(admin_user)):
    code = secrets.token_urlsafe(12)
    email = norm_email(body.email) if body.email else None
    with db() as con:
        con.execute("INSERT INTO invites VALUES(?,?,?,?,NULL)", (code, u["id"], email, time.time() + INVITE_TTL))
        log(con, u["id"], None, "invite.create", email or "")
    return {"code": code, "expires": time.time() + INVITE_TTL}


@app.delete("/api/admin/invites/{code}")
def delete_invite(code: str, u=Depends(admin_user)):
    with db() as con:
        con.execute("DELETE FROM invites WHERE code=?", (code,))
    return {"ok": True}


@app.get("/api/admin/audit")
def admin_audit(_=Depends(admin_user)):
    with db() as con:
        rows = con.execute(
            "SELECT a.ts,a.action,a.detail,a.vault_id,u.email FROM audit a LEFT JOIN users u ON u.id=a.user_id "
            "ORDER BY a.id DESC LIMIT 300").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- users (for sharing)
@app.get("/api/users/lookup")
def lookup(email: str, u=Depends(current_user)):
    throttle("lk:" + u["id"], 30)
    fail("lk:" + u["id"])
    with db() as con:
        r = con.execute("SELECT id,email,name,public_key FROM users WHERE email=? AND disabled=0",
                        (norm_email(email),)).fetchone()
    if not r:
        raise HTTPException(404, "No user with this email (invite them first)")
    return dict(r)


# ---------------------------------------------------------------- vaults
@app.get("/api/vaults")
def list_vaults(u=Depends(current_user)):
    with db() as con:
        rows = con.execute(
            "SELECT v.id,v.enc_name,m.role,m.wrapped_key,m.status,(v.created_by=m.user_id) AS mine,"
            "(SELECT email FROM users WHERE id=m.invited_by) AS creator,"
            "(SELECT group_concat(u2.email, ', ') FROM members m2 JOIN users u2 ON u2.id=m2.user_id WHERE m2.vault_id=v.id AND m2.role='owner' AND m2.status='active') AS owners,"
            "(SELECT COUNT(*) FROM members WHERE vault_id=v.id AND status='active') AS member_count "
            "FROM vaults v JOIN members m ON m.vault_id=v.id WHERE m.user_id=? ORDER BY v.created_at",
            (u["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/vaults")
def create_vault(body: NewVault, u=Depends(current_user)):
    vid = uuid.uuid4().hex
    with db() as con:
        con.execute("INSERT INTO vaults(id,enc_name,created_by,created_at) VALUES(?,?,?,?)", (vid, body.enc_name, u["id"], time.time()))
        con.execute("INSERT INTO members(vault_id,user_id,role,wrapped_key) VALUES(?,?,'owner',?)", (vid, u["id"], body.wrapped_key))
        log(con, u["id"], vid, "vault.create")
    return {"id": vid}


@app.put("/api/vaults/{vid}")
def rename_vault(vid: str, body: Rename, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        con.execute("UPDATE vaults SET enc_name=? WHERE id=?", (body.enc_name, vid))
        log(con, u["id"], vid, "vault.rename")
    return {"ok": True}


@app.delete("/api/vaults/{vid}")
def delete_vault(vid: str, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        con.execute("DELETE FROM vaults WHERE id=?", (vid,))
        log(con, u["id"], vid, "vault.delete")
    return {"ok": True}


@app.get("/api/vaults/{vid}/members")
def members(vid: str, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u)
        rows = con.execute(
            "SELECT u.id user_id,u.email,u.name,u.public_key,m.role,m.status FROM members m JOIN users u ON u.id=m.user_id "
            "WHERE m.vault_id=? ORDER BY u.email", (vid,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/vaults/{vid}/members")
def add_member(vid: str, body: AddMember, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        if not con.execute("SELECT 1 FROM users WHERE id=? AND disabled=0", (body.user_id,)).fetchone():
            raise HTTPException(404, "User not found")
        if body.user_id == u["id"]:
            raise HTTPException(400, "You are already a member")
        # invitee must accept before the vault key becomes usable / vault shows up in their account
        con.execute("INSERT INTO members(vault_id,user_id,role,wrapped_key,status,invited_by) VALUES(?,?,?,?,'pending',?)",
                    (vid, body.user_id, body.role, body.wrapped_key, u["id"]))
        log(con, u["id"], vid, "member.invite", f"{body.user_id}:{body.role}")
    return {"ok": True}


def _last_owner(con, vid, uid):
    owners = [r["user_id"] for r in con.execute("SELECT user_id FROM members WHERE vault_id=? AND role='owner'", (vid,))]
    return owners == [uid]


@app.post("/api/vaults/{vid}/accept")
def accept_share(vid: str, u=Depends(current_user)):
    with db() as con:
        r = con.execute("UPDATE members SET status='active' WHERE vault_id=? AND user_id=? AND status='pending'", (vid, u["id"]))
        if r.rowcount != 1:
            raise HTTPException(404, "No pending invitation")
        log(con, u["id"], vid, "member.accept")
    return {"ok": True}


@app.put("/api/vaults/{vid}/members/{uid}")
def set_role(vid: str, uid: str, body: SetRole, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        if body.role != "owner" and _last_owner(con, vid, uid):
            raise HTTPException(400, "The vault must keep at least one owner")
        con.execute("UPDATE members SET role=? WHERE vault_id=? AND user_id=?", (body.role, vid, uid))
        log(con, u["id"], vid, "member.role", f"{uid}:{body.role}")
    return {"ok": True}


@app.delete("/api/vaults/{vid}/members/{uid}")
def remove_member(vid: str, uid: str, u=Depends(current_user)):
    """Removes the member. The client MUST then call /rotate so the removed
    member's copy of the vault key becomes useless for future data."""
    with db() as con:
        if uid == u["id"] and con.execute("SELECT 1 FROM members WHERE vault_id=? AND user_id=? AND status='pending'", (vid, uid)).fetchone():
            con.execute("DELETE FROM members WHERE vault_id=? AND user_id=?", (vid, uid))
            log(con, u["id"], vid, "member.decline")
            return {"ok": True}
        need(con, vid, u, *(() if uid == u["id"] else ("owner",)))
        if _last_owner(con, vid, uid):
            raise HTTPException(400, "The last owner cannot be removed; delete the vault or assign another owner first")
        con.execute("DELETE FROM members WHERE vault_id=? AND user_id=?", (vid, uid))
        log(con, u["id"], vid, "member.remove", uid)
    return {"ok": True}


@app.post("/api/vaults/{vid}/rotate")
def rotate(vid: str, body: Rotate, u=Depends(current_user)):
    """Atomically replace the vault key: new name ciphertext, every item re-encrypted,
    and a freshly wrapped key for each remaining member."""
    with db() as con:
        need(con, vid, u, "owner")
        cur = {r["user_id"] for r in con.execute("SELECT user_id FROM members WHERE vault_id=?", (vid,))}
        if set(body.wrapped_keys) != cur or set(body.expect_members) != cur:
            raise HTTPException(409, "Member list changed, please try again")
        ids = {r["id"] for r in con.execute("SELECT id FROM items WHERE vault_id=?", (vid,))}
        if {i["id"] for i in body.items} != ids:
            raise HTTPException(409, "Item list changed, please try again")
        con.execute("UPDATE vaults SET enc_name=?, key_version=key_version+1 WHERE id=?", (body.enc_name, vid))
        # old snapshots are encrypted with the old key, which the removed member may still hold: drop them
        con.execute("DELETE FROM snapshots WHERE vault_id=?", (vid,))
        for uid, wk in body.wrapped_keys.items():
            con.execute("UPDATE members SET wrapped_key=? WHERE vault_id=? AND user_id=?", (wk, vid, uid))
        for it in body.items:
            if len(it["data"]) > MAX_BLOB:
                raise HTTPException(413, "Item too large")
            con.execute("UPDATE items SET data=?, rev=rev+1 WHERE id=? AND vault_id=?", (it["data"], it["id"], vid))
        log(con, u["id"], vid, "vault.rotate")
    return {"ok": True}


# ---------------------------------------------------------------- snapshots
SNAP_DAILY_KEEP, SNAP_OTHER_KEEP, SNAP_MAX = 14, 5, 32 * 1024 * 1024


def snapshot(con, vid: str, reason: str = "daily", force: bool = False):
    """Server-side copy of a vault's ciphertext, so an owner can undo mass deletion or vandalism.
    Daily (before the first change of the day) and before a restore; kept apart so forced ones cannot evict daily ones."""
    now = time.time()
    if not force:
        last = con.execute("SELECT MAX(at) a FROM snapshots WHERE vault_id=? AND reason='daily'", (vid,)).fetchone()["a"]
        if last and now - last < 86400:
            return
    v = con.execute("SELECT enc_name,key_version FROM vaults WHERE id=?", (vid,)).fetchone()
    rows = [dict(r) for r in con.execute("SELECT id,data,trashed FROM items WHERE vault_id=?", (vid,))]
    if not v or (not rows and reason == "daily"):
        return
    payload = json.dumps(rows)
    if len(payload) > SNAP_MAX:
        return
    con.execute("INSERT INTO snapshots(vault_id,at,reason,key_version,enc_name,items,count) VALUES(?,?,?,?,?,?,?)",
                (vid, now, reason, v["key_version"], v["enc_name"], payload, len(rows)))
    daily = reason == "daily"
    con.execute(f"DELETE FROM snapshots WHERE vault_id=? AND reason{'=' if daily else '!='}'daily' AND id NOT IN "
                f"(SELECT id FROM snapshots WHERE vault_id=? AND reason{'=' if daily else '!='}'daily' ORDER BY at DESC LIMIT ?)",
                (vid, vid, SNAP_DAILY_KEEP if daily else SNAP_OTHER_KEEP))


@app.get("/api/vaults/{vid}/snapshots")
def list_snapshots(vid: str, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        rows = con.execute("SELECT id,at,reason,count FROM snapshots WHERE vault_id=? ORDER BY at DESC", (vid,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/vaults/{vid}/snapshots/{sid}/restore")
def restore_snapshot(vid: str, sid: int, u=Depends(current_user)):
    """Brings every item of the snapshot back to its state then. Items created later are kept."""
    with db() as con:
        need(con, vid, u, "owner")
        snap = con.execute("SELECT * FROM snapshots WHERE id=? AND vault_id=?", (sid, vid)).fetchone()
        if not snap:
            raise HTTPException(404, "Snapshot not found")
        if snap["key_version"] != con.execute("SELECT key_version FROM vaults WHERE id=?", (vid,)).fetchone()["key_version"]:
            raise HTTPException(409, "This snapshot was made before the vault key was rotated and can no longer be restored")
        snapshot(con, vid, "before restore", force=True)
        now, restored = time.time(), 0
        for it in json.loads(snap["items"]):
            cur = con.execute("SELECT data,trashed FROM items WHERE id=? AND vault_id=?", (it["id"], vid)).fetchone()
            if cur and cur["data"] == it["data"] and cur["trashed"] == it["trashed"]:
                continue
            if cur:
                con.execute("UPDATE items SET data=?,trashed=?,rev=rev+1,updated_by=?,updated_at=? WHERE id=?", (it["data"], it["trashed"], u["id"], now, it["id"]))
            elif not con.execute("SELECT 1 FROM items WHERE id=?", (it["id"],)).fetchone():
                con.execute("INSERT INTO items VALUES(?,?,?,?,1,?,?,?,?)", (it["id"], vid, it["data"], it["trashed"], u["id"], u["id"], now, now))
            else:
                continue
            restored += 1
        log(con, u["id"], vid, "vault.snapshot_restore", f"{sid}:{restored}")
    return {"restored": restored}


# ---------------------------------------------------------------- items
def item_out(r):
    return {"id": r["id"], "data": r["data"], "trashed": bool(r["trashed"]), "rev": r["rev"],
            "created_at": r["created_at"], "updated_at": r["updated_at"]}


@app.get("/api/vaults/{vid}/items")
def list_items(vid: str, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u)
        rows = con.execute("SELECT * FROM items WHERE vault_id=? ORDER BY updated_at DESC", (vid,)).fetchall()
    return [item_out(r) for r in rows]


@app.post("/api/vaults/{vid}/items")
def create_item(vid: str, body: ItemIn, u=Depends(current_user)):
    iid, now = uuid.uuid4().hex, time.time()
    with db() as con:
        need(con, vid, u, "owner", "editor")
        snapshot(con, vid)
        con.execute("INSERT INTO items VALUES(?,?,?,0,1,?,?,?,?)", (iid, vid, body.data, u["id"], u["id"], now, now))
        log(con, u["id"], vid, "item.create", iid)
        return item_out(con.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone())


@app.put("/api/vaults/{vid}/items/{iid}")
def update_item(vid: str, iid: str, body: ItemIn, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner", "editor")
        row = con.execute("SELECT * FROM items WHERE id=? AND vault_id=?", (iid, vid)).fetchone()
        if not row:
            raise HTTPException(404, "Item not found")
        if body.rev is not None and body.rev != row["rev"]:
            raise HTTPException(409, "Item was changed by someone else; refresh")
        snapshot(con, vid)
        trashed = row["trashed"] if body.trashed is None else int(body.trashed)
        con.execute("UPDATE items SET data=?,trashed=?,rev=rev+1,updated_by=?,updated_at=? WHERE id=?",
                    (body.data, trashed, u["id"], time.time(), iid))
        action = "item.update" if body.trashed is None else ("item.trash" if body.trashed else "item.restore")
        log(con, u["id"], vid, action, iid)
        return item_out(con.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone())


@app.delete("/api/vaults/{vid}/items/{iid}")
def delete_item(vid: str, iid: str, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner", "editor")
        row = con.execute("SELECT trashed FROM items WHERE id=? AND vault_id=?", (iid, vid)).fetchone()
        if not row:
            raise HTTPException(404, "Item not found")
        if not row["trashed"]:
            raise HTTPException(400, "Move it to the trash first")
        snapshot(con, vid)
        con.execute("DELETE FROM items WHERE id=?", (iid,))
        log(con, u["id"], vid, "item.delete", iid)
    return {"ok": True}


@app.get("/api/vaults/{vid}/audit")
def vault_audit(vid: str, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        rows = con.execute(
            "SELECT a.ts,a.action,a.detail,u.email FROM audit a LEFT JOIN users u ON u.id=a.user_id "
            "WHERE a.vault_id=? ORDER BY a.id DESC LIMIT 200", (vid,)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- Send: expiring encrypted links
# The browser encrypts the content with a fresh random key that lives only in the link's #fragment,
# so the server (and anyone reading its database) cannot read what was sent.
MAX_SEND = 10 * 1024 * 1024            # plaintext bytes; ciphertext is base64 (x 4/3)
SEND_USER_QUOTA = 100 * 1024 * 1024
SEND_TOTAL_QUOTA = 500 * 1024 * 1024


class SendIn(BaseModel):
    enc: str = Field(max_length=int(MAX_SEND * 4 / 3) + 1024)
    expire_hours: float = Field(gt=0, le=24 * 30)
    max_views: Optional[int] = Field(default=None, ge=1, le=1000)
    password: Optional[str] = Field(default=None, max_length=200)
    note: str = Field(default="", max_length=200)    # your own reminder, stored in plain text, never shown to the recipient


class SendAccess(BaseModel):
    password: str = Field(default="", max_length=200)


def send_pw_hash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def purge_sends(con):
    con.execute("DELETE FROM sends WHERE expires<? OR (max_views IS NOT NULL AND views>=max_views)", (time.time(),))


@app.post("/api/sends")
def create_send(body: SendIn, u=Depends(current_user)):
    with db() as con:
        purge_sends(con)
        size = len(body.enc)
        mine = con.execute("SELECT COALESCE(SUM(size),0) n FROM sends WHERE user_id=?", (u["id"],)).fetchone()["n"]
        total = con.execute("SELECT COALESCE(SUM(size),0) n FROM sends").fetchone()["n"]
        if mine + size > SEND_USER_QUOTA or total + size > SEND_TOTAL_QUOTA:
            raise HTTPException(413, "Send storage is full; delete old Sends first")
        sid = secrets.token_urlsafe(12)
        salt = secrets.token_hex(8) if body.password else None
        con.execute("INSERT INTO sends(id,user_id,enc,size,created,expires,max_views,pw_salt,pw_hash,note) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (sid, u["id"], body.enc, size, time.time(), time.time() + body.expire_hours * 3600, body.max_views, salt,
                     send_pw_hash(body.password, salt) if body.password else None, body.note.strip()))
        log(con, u["id"], None, "user.send_create", sid)
    return {"id": sid}


@app.get("/api/sends")
def my_sends(u=Depends(current_user)):
    with db() as con:
        purge_sends(con)
        rows = con.execute("SELECT id,size,created,expires,max_views,views,note,(pw_hash IS NOT NULL) AS has_password FROM sends WHERE user_id=? ORDER BY created DESC",
                           (u["id"],)).fetchall()
    return [dict(r) | {"has_password": bool(r["has_password"])} for r in rows]


@app.delete("/api/sends/{sid}")
def delete_send(sid: str, u=Depends(current_user)):
    with db() as con:
        con.execute("DELETE FROM sends WHERE id=? AND user_id=?", (sid, u["id"]))
    return {"ok": True}


def live_send(con, sid: str):
    purge_sends(con)
    r = con.execute("SELECT * FROM sends WHERE id=?", (sid,)).fetchone()
    if not r:
        raise HTTPException(404, "This link does not exist, has expired or was already used up.")
    return r


@app.get("/api/send/{sid}")
def send_info(sid: str, request: Request):
    throttle("sendinfo:" + client_ip(request), 120, 60)
    fail("sendinfo:" + client_ip(request), 60)
    with db() as con:
        r = live_send(con, sid)
    return {"needs_password": r["pw_hash"] is not None, "expires": r["expires"]}


@app.post("/api/send/{sid}/access")
def send_access(sid: str, body: SendAccess, request: Request):
    ip = client_ip(request)
    throttle("send:" + ip, 30, 60)
    fail("send:" + ip, 60)
    now = time.time()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")   # view counting must not interleave
        r = live_send(con, sid)
        if r["locked_until"] > now:
            raise HTTPException(429, "Too many wrong passwords. Try again later.", headers={"Retry-After": str(int(r["locked_until"] - now) + 1)})
        if r["pw_hash"] is not None and not hmac.compare_digest(send_pw_hash(body.password, r["pw_salt"]), r["pw_hash"]):
            con.execute("UPDATE sends SET fails=fails+1 WHERE id=?", (sid,))
            if con.execute("SELECT fails FROM sends WHERE id=?", (sid,)).fetchone()["fails"] >= 5:
                con.execute("UPDATE sends SET fails=0, locked_until=? WHERE id=?", (now + 600, sid))
            con.commit()
            raise HTTPException(401, "Wrong password")
        cur = con.execute("UPDATE sends SET views=views+1, fails=0 WHERE id=? AND expires>? AND (max_views IS NULL OR views<max_views)", (sid, now))
        if cur.rowcount != 1:
            raise HTTPException(404, "This link does not exist, has expired or was already used up.")
        log(con, r["user_id"], None, "user.send_opened", sid)
    left = None if r["max_views"] is None else r["max_views"] - r["views"] - 1
    return {"enc": r["enc"], "views_left": left, "expires": r["expires"]}


@app.exception_handler(sqlite3.IntegrityError)
def integrity(_, exc):
    return JSONResponse({"detail": "Data conflict"}, status_code=409)


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
