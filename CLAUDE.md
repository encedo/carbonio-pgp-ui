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

## Source layout

```
src/
  app.tsx                      ← Shell registrations (addRoute, registerFunctions, window globals)
  store/
    HsmContext.tsx             ← HEM instance, token cache, authorize(), connect/disconnect
                                  _singleton exported — survives React unmount/remount
  components/
    HsmPasswordModal.tsx       ← unlock modal with "save for session" checkbox
    HsmUrlModal.tsx            ← HSM URL input → localStorage
    KeygenModal.tsx            ← keygen flow + WKD publish offer
    WkdImportModal.tsx         ← WKD lookup → show key info → confirm → import to HSM
  views/
    PgpSettingsView.tsx        ← main settings panel (HSM status, My Keys, Peer Keys)
  lib/
    wkd-fetch.ts               ← WKD HTTP fetch + pure OpenPGP binary parser (no openpgp.js)
                                  validates Ed25519 + X25519 OIDs, rejects Ed448/other curves
    webcrypto-patch.ts         ← patches globalThis.crypto = window.crypto before openpgp.js loads
  types/
    hem.d.ts                   ← HEM SDK TypeScript declarations
```

Note: `src/types/encedo-pgp.d.ts` was removed — types are now in sidecar
`../encedo-pgp-js/dist/encedo-pgp.browser.js.d.ts`.

## Sibling repos (must be present at build time)
```
../hem-sdk-js/hem-sdk.browser.js              ← HEM SDK browser bundle
../encedo-pgp-js/dist/encedo-pgp.browser.js   ← PGP logic (openpgp.js + cert-builder etc.)
../carbonio-mails-ui/                         ← forked mails-ui (Phase 2+)
```

`encedo-pgp.browser.js` is **always dynamic-imported** (never static import) because
openpgp.js initialises WebCrypto at module-eval time and Carbonio Shell's webpack
polyfills `globalThis` without `window.crypto`.
Fix: call `patchWebCrypto()` just before each `await import('...encedo-pgp.browser.js')`.
**Definitive fix**: call `preloadEncedoPgp()` inside `connect()` after successful auth —
module evaluates once in correct context, cached by webpack, all subsequent imports free.

## HsmContext — singleton pattern (CRITICAL)

State is stored in module-level `_singleton` (not React state) to survive route changes.
`HsmProvider` initializes `useState` from `_singleton` on every mount/remount.

```ts
export const _singleton = {
  password:   '',           // HSM password in memory
  tokenCache: new Map(),    // scope → { token, expiresAt }
  state: { ... HsmState }, // hem, listToken, impToken, genToken, connected, unlocked, url
};
```

`HsmProvider` is mounted at module level in `app.tsx` inside `PgpView` (stable reference).
**Never define `HsmProvider` wrapper inside a function component** — React will remount it.

## app.tsx — window globals for mails-ui bridge

```ts
window.__encedoPgpGetHsm    = () => _singleton.state;   // HSM state (unlocked, hem, etc.)
window.__encedoPgpCheckWkd  = (email) => wkdFetch(email).then(r => r !== null);
```

These are consumed by `carbonio-mails-ui/src/views/app/detail-panel/edit/edit-utils-hooks/use-pgp-handlers.tsx`.

## Token management

- Tokens cached in `_singleton.tokenCache` with 8h TTL (30s safety margin)
- `authorize(scope)` — returns cached token or fetches fresh one
- Scopes used:
  - `keymgmt:list` — search/list keys (obtained at connect, cached)
  - `keymgmt:imp`  — importPublicKey (obtained at connect, cached)
  - `keymgmt:gen`  — createKeyPair (obtained at connect, cached)
  - `keymgmt:del`  — deleteKey (obtained lazily via authorize(), cached)
  - `keymgmt:use:<kid>` — getPubKey, sign, ecdh (per-key, obtained lazily, cached)
- Password kept in `_singleton.password` (not React state)
- sessionStorage opt-in: `pgp-hsm-password` (set by HsmPasswordModal checkbox)

## DESCR schema (mirrors encedo-pgp-js/keychain.js)

```
ETSPGP:self,<email>,sign,<iat>[,<exp>]   ← own Ed25519
ETSPGP:self,<email>,ecdh,<iat>[,<exp>]   ← own X25519
ETSPGP:peer,<email>,sign                 ← peer Ed25519
ETSPGP:peer,<email>,ecdh                 ← peer X25519
```

All DESCR values are **base64-encoded** when passed to HEM API (`encodeDescr()`).
`iat` and `exp` are Unix timestamps. `exp` is preserved in cert via `expiryTimestamp` opt
passed to `buildCertificate()` — generates Key Expiration Time subpacket (type 9).

## WKD auth — X-Auth-Token

`publishKey` and `revokeKey` read `ZM_AUTH_TOKEN` cookie and send it as `X-Auth-Token`.
encedo-wkd server validates via Carbonio SOAP when `carbonio_url` is set in its config.

## Implemented features (Phase 1 ✅)

### HSM Connection card
- URL stored in localStorage, editable via HsmUrlModal (click on URL field)
- Unlock via HsmPasswordModal → obtains list/imp/gen tokens
- Connected/Unlocked/Locked badges, Lock button, Refresh keys button
- State persists across navigation (singleton pattern)

### My Keys table
- Columns: Email | Key ID (sign) | Key ID (ecdh) | Created | Expires | WKD | Actions
- WKD status: checked in parallel after loadKeys via wkdFetch → pill Checking/Local/Published
- ↑ Publish — rebuilds cert from HSM keys + publishKey to WKD
- ↻ Rotate — revoke WKD + delete HSM keys + generate new + publish (preserves expiry TTL)
- ✕ Revoke — revoke WKD (ignore 404) + deleteKey × 2 from HSM
- onPublished callback → updates WKD status immediately (no reload needed)

### Keygen (KeygenModal)
- Email dropdown from Carbonio account: `account.name` + `zimbraMailAlias` + `zimbraAllowFromAddress` + identities
- Emails with existing keys excluded from dropdown (`disabledEmails` prop)
- Expiry: No expiry / 1y / 2y / 3y (default 2y) → baked into cert as Key Expiration Time subpkt
- Generates Ed25519 + X25519 on HSM with DESCR tags
- Calls `buildCertificate()` from encedo-pgp.browser.js (dynamic import)
- After success: offers WKD publish → calls `publishKey(wkdBase, email, cert, authToken)`

### Peer Keys (WkdImportModal)
- WKD fetch (wkd-fetch.ts, no openpgp.js) → parse raw OpenPGP packets
- Validates OIDs: rejects non-Ed25519 signing keys and non-X25519 ECDH keys
- Shows Ed25519 + X25519 key fingerprints → confirm dialog
- Imports both keys to HSM via `hem.importPublicKey()` with `keymgmt:imp` token
- ✕ Remove: confirm modal → `hem.deleteKey()` with `keymgmt:del` token (both kids)

## Phase 2 — Compose integration (IN PROGRESS)

### What's done
- `carbonio-mails-ui` forked at `../carbonio-mails-ui/`
- `MailsEditorV2` extended with `isPgpSign?`, `isPgpEncrypt?` fields
- Store actions `setIsPgpSign`, `setIsPgpEncrypt` added
- Hooks `useEditorIsPgpSign`, `useEditorIsPgpEncrypt` added
- `use-pgp-handlers.tsx` — polls HSM unlock state (2s), checks WKD per recipient (debounce 600ms)
- `pgp-buttons.tsx` — Sign icon + Lock icon buttons in composer toolbar
- `edit-view.tsx` — `<PgpButtons editorId={editorId} />` added obok Save/Send

### TODO Phase 2
- Intercept `onSendClick` in `use-send-handlers.tsx` — sign/encrypt before send
- Sign: `signCleartextMessage` or build MIME signed message via HSM
- Encrypt: `encryptAndSign` or `encryptMessage` for each recipient via WKD/HSM
- Deploy mails-ui build to server

## carbonio.webpack.js
- `NormalModuleReplacementPlugin`: strips `node:` prefix from hem-sdk.js imports
- `resolve.fallback`: stubs `https/http/url/net/tls` as false

## Carbonio Shell API used
```ts
// app.tsx
addRoute({ id, app, route: 'pgp', appView: PgpView, ... })
registerFunctions({ 'pgp:encrypt', 'pgp:sign-encrypt', 'pgp:decrypt' })  // stubs

// components (runtime, not in TS types — use @ts-expect-error)
useUserAccount()   // → { name, identities, ... }
useUserSettings()  // → { attrs: { zimbraMailAlias, zimbraAllowFromAddress, ... } }
```

## Server info
- Carbonio host: `mailserver` (mailserver.encedo.com)
- Iris path: `/opt/zextras/web/iris/`
- WKD proxy: `https://mailserver.encedo.com/wkd/api/...` (nginx → port 8089)
- Shell version: 14.0.1
- Mails-ui version: 1.31.7 (forked)

## Known issues / TODO
- Phase 2: sign/encrypt on send not yet implemented
- Phase 3: Decrypt/Verify banner in message view — not started
- `useUserAccount` / `useUserSettings` not in carbonio-shell-ui TS types → `@ts-expect-error`
