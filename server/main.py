"""Kasa - zero-knowledge team password manager (server).

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

app = FastAPI(title="Kasa", docs_url=None, redoc_url=None, openapi_url=None)


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
        raise HTTPException(429, "Çok fazla deneme. Birkaç dakika sonra tekrar deneyin.")


def fail(key: str):
    n, ts = _fails.get(key, (0, time.time()))
    if time.time() - ts > 300:
        n, ts = 0, time.time()
    _fails[key] = (n + 1, ts)


def client_ip(request: Request) -> str:
    # uvicorn rewrites client.host from X-Forwarded-For only for trusted proxies (--forwarded-allow-ips)
    return request.client.host if request.client else "?"


def norm_email(e: str) -> str:
    return e.strip().lower()


def hash_auth(auth_b64: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    h = hashlib.scrypt(auth_b64.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_auth(auth_b64: str, stored: str) -> bool:
    salt_b64, _ = stored.split("$")
    return hmac.compare_digest(hash_auth(auth_b64, base64.b64decode(salt_b64)), stored)


DUMMY_HASH = hash_auth("dummy")


def log(con, user_id, vault_id, action, detail=""):
    con.execute("INSERT INTO audit(ts,user_id,vault_id,action,detail) VALUES(?,?,?,?,?)",
                (time.time(), user_id, vault_id, action, detail))


def new_session(con, user_id) -> str:
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO sessions VALUES(?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), user_id, time.time() + SESSION_TTL))
    con.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
    return token


def user_public(u) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u["name"], "is_admin": bool(u["is_admin"]),
            "public_key": u["public_key"], "enc_private_key": u["enc_private_key"]}


def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Giriş gerekli")
    th = hashlib.sha256(authorization[7:].encode()).hexdigest()
    with db() as con:
        row = con.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires>? AND u.disabled=0", (th, time.time())).fetchone()
    if not row:
        raise HTTPException(401, "Oturum süresi doldu")
    return dict(row) | {"_th": th}


def admin_user(u=Depends(current_user)):
    if not u["is_admin"]:
        raise HTTPException(403, "Yönetici yetkisi gerekli")
    return u


def role_of(con, vault_id, user_id) -> Optional[str]:
    r = con.execute("SELECT role FROM members WHERE vault_id=? AND user_id=? AND status='active'", (vault_id, user_id)).fetchone()
    return r["role"] if r else None


def need(con, vault_id, user, *roles):
    r = role_of(con, vault_id, user["id"])
    if r is None:
        raise HTTPException(404, "Kasa bulunamadı")
    if roles and r not in roles:
        raise HTTPException(403, "Bu işlem için yetkiniz yok")
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
        raise HTTPException(400, "Geçersiz e-posta")
    with db() as con:
        con.execute("BEGIN IMMEDIATE")  # serialises first-admin bootstrap and invite claiming
        count = con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "Bu e-posta zaten kayıtlı")
        if count > 0:
            inv = con.execute("SELECT * FROM invites WHERE code=? AND used_by IS NULL AND expires>?",
                              (body.invite or "", time.time())).fetchone()
            if not inv or (inv["email"] and inv["email"] != email):
                raise HTTPException(403, "Geçersiz veya süresi dolmuş davet kodu")
        uid = uuid.uuid4().hex
        con.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,0,?)",
                    (uid, email, body.name.strip(), body.salt, body.iters, hash_auth(body.auth),
                     body.public_key, body.enc_private_key, 1 if count == 0 else 0, time.time()))
        if count > 0:
            claimed = con.execute("UPDATE invites SET used_by=? WHERE code=? AND used_by IS NULL AND expires>?",
                                  (uid, body.invite, time.time()))
            if claimed.rowcount != 1:
                raise HTTPException(403, "Geçersiz veya süresi dolmuş davet kodu")
        log(con, uid, None, "user.register", email)
        u = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return {"token": new_session(con, uid), "user": user_public(u)}


@app.post("/api/login")
def login(body: Login, request: Request):
    email = norm_email(body.email)
    key = "login:" + client_ip(request) + ":" + email
    acct = "acct:" + email  # per-account limit: rotating IPs does not reset it
    throttle(key)
    time.sleep(min(0.5 * max(0, _fails.get(acct, (0, 0))[0] - 5), 8))  # progressive delay, never a hard lockout
    with db() as con:
        u = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        ok = verify_auth(body.auth, u["auth_hash"] if u else DUMMY_HASH) and u is not None and not u["disabled"]
        if not ok:
            fail(key); fail(acct)
            raise HTTPException(401, "E-posta veya ana parola hatalı")
        _fails.pop(key, None); _fails.pop(acct, None)
        log(con, u["id"], None, "user.login", client_ip(request))
        return {"token": new_session(con, u["id"]), "user": user_public(u)}


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
        raise HTTPException(403, "Mevcut ana parola hatalı")
    with db() as con:
        con.execute("UPDATE users SET salt=?,iters=?,auth_hash=?,enc_private_key=? WHERE id=?",
                    (body.new_salt, body.new_iters, hash_auth(body.new_auth), body.enc_private_key, u["id"]))
        con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?", (u["id"], u["_th"]))
        log(con, u["id"], None, "user.password_change")
    return {"ok": True}


# ---------------------------------------------------------------- admin
@app.get("/api/admin/users")
def list_users(_=Depends(admin_user)):
    with db() as con:
        rows = con.execute("SELECT id,email,name,is_admin,disabled,created_at FROM users ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/users/{uid}/disable")
def disable_user(uid: str, disable: bool = True, u=Depends(admin_user)):
    if uid == u["id"]:
        raise HTTPException(400, "Kendinizi devre dışı bırakamazsınız")
    with db() as con:
        con.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disable else 0, uid))
        if disable:
            con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        log(con, u["id"], None, "user.disable" if disable else "user.enable", uid)
    return {"ok": True}


@app.post("/api/admin/users/{uid}/admin")
def set_admin(uid: str, admin: bool, u=Depends(admin_user)):
    with db() as con:
        if not admin and con.execute("SELECT COUNT(*) c FROM users WHERE is_admin=1 AND disabled=0").fetchone()["c"] <= 1:
            raise HTTPException(400, "En az bir yönetici kalmalı")
        con.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if admin else 0, uid))
        log(con, u["id"], None, "user.admin" if admin else "user.unadmin", uid)
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
        raise HTTPException(404, "Bu e-postayla kayıtlı kullanıcı yok (önce davet edin)")
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
        con.execute("INSERT INTO vaults VALUES(?,?,?,?)", (vid, body.enc_name, u["id"], time.time()))
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
            raise HTTPException(404, "Kullanıcı bulunamadı")
        if body.user_id == u["id"]:
            raise HTTPException(400, "Zaten üyesiniz")
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
            raise HTTPException(404, "Bekleyen davet yok")
        log(con, u["id"], vid, "member.accept")
    return {"ok": True}


@app.put("/api/vaults/{vid}/members/{uid}")
def set_role(vid: str, uid: str, body: SetRole, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner")
        if body.role != "owner" and _last_owner(con, vid, uid):
            raise HTTPException(400, "Kasada en az bir sahip kalmalı")
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
            raise HTTPException(400, "Son sahip çıkarılamaz; önce kasayı silin veya başka sahip atayın")
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
            raise HTTPException(409, "Üye listesi değişti, tekrar deneyin")
        ids = {r["id"] for r in con.execute("SELECT id FROM items WHERE vault_id=?", (vid,))}
        if {i["id"] for i in body.items} != ids:
            raise HTTPException(409, "Kayıt listesi değişti, tekrar deneyin")
        con.execute("UPDATE vaults SET enc_name=? WHERE id=?", (body.enc_name, vid))
        for uid, wk in body.wrapped_keys.items():
            con.execute("UPDATE members SET wrapped_key=? WHERE vault_id=? AND user_id=?", (wk, vid, uid))
        for it in body.items:
            if len(it["data"]) > MAX_BLOB:
                raise HTTPException(413, "Kayıt çok büyük")
            con.execute("UPDATE items SET data=?, rev=rev+1 WHERE id=? AND vault_id=?", (it["data"], it["id"], vid))
        log(con, u["id"], vid, "vault.rotate")
    return {"ok": True}


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
        con.execute("INSERT INTO items VALUES(?,?,?,0,1,?,?,?,?)", (iid, vid, body.data, u["id"], u["id"], now, now))
        log(con, u["id"], vid, "item.create", iid)
        return item_out(con.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone())


@app.put("/api/vaults/{vid}/items/{iid}")
def update_item(vid: str, iid: str, body: ItemIn, u=Depends(current_user)):
    with db() as con:
        need(con, vid, u, "owner", "editor")
        row = con.execute("SELECT * FROM items WHERE id=? AND vault_id=?", (iid, vid)).fetchone()
        if not row:
            raise HTTPException(404, "Kayıt bulunamadı")
        if body.rev is not None and body.rev != row["rev"]:
            raise HTTPException(409, "Kayıt başkası tarafından değiştirildi; yenileyin")
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
            raise HTTPException(404, "Kayıt bulunamadı")
        if not row["trashed"]:
            raise HTTPException(400, "Önce çöp kutusuna taşıyın")
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


@app.exception_handler(sqlite3.IntegrityError)
def integrity(_, exc):
    return JSONResponse({"detail": "Veri çakışması"}, status_code=409)


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
