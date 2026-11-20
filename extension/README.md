# Vaultly browser extension (Chrome, Edge, Brave, Opera)

Install (until it is in a web store):
1. Download `vaultly-extension.zip` from Vaultly → Settings → Browser extension, and unzip it.
2. Open `chrome://extensions` (Edge: `edge://extensions`), turn on **Developer mode**, click **Load unpacked** and pick the unzipped `vaultly-extension` folder.
3. Pin the Vaultly icon, click it, keep the server address, enter your email, press **Connect** and allow access to the server.
4. Unlock with your master password (and 2FA code if it is on).

Security model: the master password derives the keys inside the popup and is never stored. After unlocking, the server
session token and the vault keys are kept in `chrome.storage.session` (memory only, gone when the browser closes, the
computer locks or is idle for 15 minutes, or you press Lock). Only login items are loaded. Filling happens only when you
press **Fill**; a login saved for a different site asks first. Persistent storage holds only the server address and your email.

`crypto.js` is a copy of `../web/crypto.js`; `python3 tools/build_extension.py` refreshes it and builds the zip.
`fill.js` and `match.js` come from the homekit vault extension (exact host match, https never downgraded).
