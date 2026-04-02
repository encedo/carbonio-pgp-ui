# carbonio-pgp-ui — CLAUDE.md

## Purpose
Carbonio UI module — PGP encrypt/decrypt/sign/verify via Encedo HEM HSM.
Loaded by Carbonio Shell as a standard iris module.

## Build & Deploy

```bash
npm run build          # → dist/
bash build-zip.sh      # → carbonio-pgp-ui.zip (includes install-pgp-ui.sh)

rsync -av carbonio-pgp-ui.zip root@mailserver:/tmp/
ssh root@mailserver 'cd /tmp && unzip -o carbonio-pgp-ui.zip && sudo bash install-pgp-ui.sh'
```

**Re-register after Carbonio update** (if plugin disappears from Settings):
```bash
ssh root@mailserver 'sudo bash /tmp/install-pgp-ui.sh --reregister'
```

`install-pgp-ui.sh` copies `dist/` to `/opt/zextras/web/iris/carbonio-pgp-ui/<commit>/`
and updates `components.json`. Hard-reload browser (Ctrl+Shift+R) to activate.

## Source layout (current state)

```
src/
  app.tsx                      ← Shell registrations (addRoute, addSettingsView, registerFunctions)
  store/
    HsmContext.tsx             ← HEM instance, token cache, authorize(), connect/disconnect
  components/
    HsmPasswordModal.tsx       ← unlock modal with "save for session" checkbox
    HsmUrlModal.tsx            ← HSM URL input → localStorage
    KeygenModal.tsx            ← keygen flow + WKD publish offer
    WkdImportModal.tsx         ← WKD lookup → show key info → confirm → import to HSM
  views/
    PgpSettingsView.tsx        ← main settings panel (HSM status, My Keys, Peer Keys)
  lib/
    wkd-fetch.ts               ← WKD HTTP fetch + pure OpenPGP binary parser (no openpgp.js)
    webcrypto-patch.ts         ← patches globalThis.crypto = window.crypto before openpgp.js loads
  types/
    hem.d.ts                   ← HEM SDK TypeScript declarations
    encedo-pgp.d.ts            ← encedo-pgp.browser.js declarations
```

## Sibling repos (must be present at build time)
```
../hem-sdk-js/hem-sdk.browser.js              ← HEM SDK browser bundle
../encedo-pgp-js/dist/encedo-pgp.browser.js   ← PGP logic (openpgp.js + cert-builder etc.)
```

`encedo-pgp.browser.js` is **always dynamic-imported** (never static import) because
openpgp.js initialises WebCrypto at module-eval time and Carbonio Shell's webpack
polyfills `globalThis` without `window.crypto`. Fix: call `patchWebCrypto()` just before
each `await import('...encedo-pgp.browser.js')`.

## HsmContext — token management

- Tokens cached in `useRef<Map>` with 8h TTL (30s safety margin)
- `authorize(scope)` — returns cached token or fetches fresh one
- Scopes used:
  - `keymgmt:list` — search/list keys (obtained at connect, cached)
  - `keymgmt:imp`  — importPublicKey (obtained at connect, cached)
  - `keymgmt:gen`  — createKeyPair (obtained at connect, cached)
  - `keymgmt:del`  — deleteKey (obtained lazily via authorize(), cached)
  - `keymgmt:use:<kid>` — getPubKey, sign, ecdh (per-key, obtained lazily, cached)
- Password kept in `useRef` (not React state) — not lost between renders
- sessionStorage opt-in: `pgp-hsm-password` (set by HsmPasswordModal checkbox)

## DESCR schema (mirrors encedo-pgp-js/keychain.js)

```
ETSPGP:self,<email>,sign,<iat>[,<exp>]   ← own Ed25519
ETSPGP:self,<email>,ecdh,<iat>[,<exp>]   ← own X25519
ETSPGP:peer,<email>,sign                 ← peer Ed25519
ETSPGP:peer,<email>,ecdh                 ← peer X25519
```

All DESCR values are **base64-encoded** when passed to HEM API (`encodeDescr()`).
Search prefix: `ETSPGP:` (base64 = `RVRTUGDQ:` — actually searched as plain prefix via hem.searchKeys).

## Implemented features (Phase 1)

### HSM Connection card
- URL stored in localStorage, editable via HsmUrlModal
- Unlock via HsmPasswordModal (password modal) → obtains list/imp/gen tokens
- Connected/Unlocked/Locked badges, Lock button, Refresh keys button

### My Keys table
- Columns: Email | Key ID (sign) | Key ID (ecdh) | Created | WKD | Actions
- WKD column: pill "Local only" / "Published" (publish not yet wired)
- Buttons: ↑ Publish (disabled), ✕ Revoke (disabled) — Phase 2

### Keygen (KeygenModal)
- Email dropdown from Carbonio account: `account.name` + `zimbraMailAlias` + `zimbraAllowFromAddress` + identities
- Expiry: No expiry / 1y / 2y / 3y (default 2y)
- Generates Ed25519 + X25519 on HSM with DESCR tags
- Calls `buildCertificate()` from encedo-pgp.browser.js (dynamic import)
- After success: offers WKD publish → calls `publishKey(wkdBase, email, cert)`
- WKD base URL: `https://<window.location.hostname>/wkd`

### Peer Keys (WkdImportModal)
- Phase 1: WKD fetch (wkd-fetch.ts, no openpgp.js) → parse raw OpenPGP packets
- Phase 2: show Ed25519 + X25519 key fingerprints → confirm dialog
- Phase 3: import both keys to HSM via `hem.importPublicKey()` with `keymgmt:imp` token
- ✕ Remove: confirm modal → `hem.deleteKey()` with `keymgmt:del` token (both kidSign + kidEcdh)

### hem-sdk-js additions
- Added `deleteKey(token, kid)` → `DELETE /api/keymgmt/delete/:kid`
- Rebuilt `hem-sdk.browser.js` via rollup

## carbonio.webpack.js
- `NormalModuleReplacementPlugin`: strips `node:` prefix from hem-sdk.js imports
- `resolve.fallback`: stubs `https/http/url/net/tls` as false

## Carbonio Shell API used
```ts
// app.tsx
addRoute({ id, app, route: 'pgp', appView: PgpSettingsView, ... })
addSettingsView({ id, app, route: 'pgp', component: PgpSettingsView, ... })
registerFunctions({ 'pgp:encrypt', 'pgp:sign-encrypt', 'pgp:decrypt' })  // stubs

// components (runtime, not in TS types — use @ts-expect-error)
useUserAccount()   // → { name, identities, ... }
useUserSettings()  // → { attrs: { zimbraMailAlias, zimbraAllowFromAddress, ... } }
```

## Known issues / TODO
- `patchWebCrypto()` called before every openpgp.js dynamic import — still getting
  "WebCrypto API not available" in some cases; needs further debugging with console logs
- ↑ Publish / ✕ Revoke for own keys: not yet implemented (Phase 2)
- WKD status per key (published/local): not yet fetched from WKD server
- Peer key Refresh: removed (was placeholder, no clear use case)
- `useUserAccount` / `useUserSettings` not in carbonio-shell-ui TS types → `@ts-expect-error`

## Server info
- Carbonio host: `mailserver` (mailserver.encedo.com)
- Iris path: `/opt/zextras/web/iris/`
- WKD proxy: `https://mailserver.encedo.com/wkd/api/...` (nginx → port 8089)
- Shell version: 14.0.1
- Mails-ui version: 1.31.4

## Phase plan
- **Phase 1** ✅ Settings panel: HSM connect, keygen, key list, WKD import/remove peer keys
- **Phase 2**: Compose integration — Sign+Encrypt button (registerComponents → mails-ui)
- **Phase 3**: Message view — Decrypt/Verify banner
