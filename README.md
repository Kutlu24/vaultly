# Vaultly — team password manager

A self-hosted, end-to-end encrypted (zero-knowledge) password vault for small teams and associations.

## Features
- **Zero-knowledge**: master password → PBKDF2 (600k iterations) → 512 bits. One half is the encryption key and never leaves the browser; the other half is the "auth" value sent to the server. The server only ever sees ciphertext.
- **Shared vaults** with roles (Owner / Editor / Viewer). Every vault has its own AES-256-GCM key, wrapped per member with RSA-OAEP.
- **Key rotation on removal**: when a member is removed, the vault key is replaced and every item is re-encrypted, so the removed person cannot read future data with their old key.
- **Invitations need consent**: a share stays pending until the invitee accepts; the invite card shows who invited them and who owns the vault.
- Login / Note / Card items, custom fields, favorites, trash, password history
- **TOTP (2FA) codes** (supports `otpauth://`), password generator, strength meter
- **Security Scan**: weak, reused and old passwords, accounts without 2FA, Have I Been Pwned breach check (k-anonymity: only a 5-character hash prefix leaves the browser)
- Invite-only sign-up, admin panel, activity logs, protection against concurrent edits
- CSV import (Chrome / Bitwarden / Proton Pass / 1Password) and export, auto-lock, clipboard cleared after 30 s
- Public-key fingerprint to verify who you are sharing with

## Run it
```
pip install fastapi uvicorn
KASA_DATA=./data uvicorn server.main:app --port 8000     # or: docker compose up -d
```
**HTTPS is required** (the browser crypto API needs a secure context; `localhost` is exempt), e.g. `tailscale serve --bg --https=8445 http://127.0.0.1:8011`.
The first person to register becomes the administrator; everyone else joins through Admin → Create invite.

## Tests
`node tests/e2e.mjs` (API + real encryption code) and `node tests/ui.mjs` (headless Chrome). Both need a running server (`KASA_URL`, default `http://localhost:8099`).

## Limitations
- No master-password recovery, by design. Not even the administrator can reset it.
- No browser extension, mobile app or autofill yet.
- If a member already opened or copied passwords before being removed, those passwords should be changed.
- Back up `data/secret.key` and `data/kasa.db`.

## Deploying
### Fly.io (what the public instance uses)
`fly.toml` is ready: one machine plus a `kasa_data` volume.

```
fly auth login
fly apps create <your-app-name> --org personal     # then set `app = "<your-app-name>"` in fly.toml
fly volumes create kasa_data --size 1 --region fra --app <your-app-name>
fly deploy --ha=false --app <your-app-name>
```
Fly's proxy sets `Fly-Client-IP`, which clients cannot forge. `fly.toml` reads it via `KASA_CLIENT_IP_HEADER` and only trusts it from Fly's private network (`KASA_TRUSTED_PROXIES`). After deploying, check that failed logins are counted per real client IP.
Back up the volume (snapshots are on by default) and occasionally download `kasa.db` and `secret.key` with `fly ssh sftp`.

### Render
`render.yaml` is included (Starter plan + 1 GB persistent disk, single instance). Render's **free** plan has no persistent disk, so the SQLite database would be wiped on every restart; do not use it.

### Client IP / reverse proxy settings
These control the login rate limits, which key on the client IP:

| Variable | Meaning |
| --- | --- |
| `KASA_PROXY_HOPS` (default `0`) | Number of trusted proxies appending to `X-Forwarded-For`. `0` = use the socket address. Too low and everyone looks like the proxy (shared limit); too high and forged IPs are accepted. |
| `KASA_CLIENT_IP_HEADER` | A header your platform proxy sets itself (e.g. `fly-client-ip`). Takes priority over `X-Forwarded-For`. |
| `KASA_TRUSTED_PROXIES` | Comma-separated CIDRs allowed to supply those headers (default: loopback + private ranges). Narrow it to your proxy's exact address when you can, e.g. `172.17.0.1/32`. |

Login throttling: 8 failures per IP+account per 5 minutes, and 30 failures per account per 15 minutes (IPs that previously logged in successfully are exempt from the account-wide cap). Blocked requests get `429` with `Retry-After`.
