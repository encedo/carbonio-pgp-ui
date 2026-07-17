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
  app.tsx                      ← Shell registrations + all window globals for mails-ui bridge
  store/
    HsmContext.tsx             ← HEM instance, token cache, authorize(), connect/disconnect
                                  _singleton exported — survives React unmount/remount
  components/
    HsmPasswordModal.tsx       ← unlock modal with "save for session" checkbox
    HsmUrlModal.tsx            ← HSM URL input → localStorage
    KeygenModal.tsx            ← keygen flow + WKD publish offer
    WkdImportModal.tsx         ← peer key lookup (WKD, then keyserver fallback) → show info+source → import to HSM
  views/
    PgpSettingsView.tsx        ← main settings panel (HSM status, My Keys, Peer Keys)
                                  registers window.__encedoPgpRequestUnlock
  lib/
    pgp-prefs.ts               ← alwaysSign / alwaysEncrypt / autoDecrypt in localStorage
                                  mirrored read-only by mails-ui src/commons/pgp-prefs.ts
    wkd-fetch.ts               ← WKD HTTP fetch + pure OpenPGP binary parser (no openpgp.js)
                                  validates Ed25519 + X25519 OIDs, computes v4 fingerprint
    webcrypto-patch.ts         ← patches globalThis.crypto = window.crypto before openpgp.js loads
  types/
    hem.d.ts                   ← HEM SDK TypeScript declarations
```

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

**Never define `HsmProvider` wrapper inside a function component** — React will remount it.

## app.tsx — window globals for mails-ui bridge

All crypto bridge functions are defined in `app.tsx` at module evaluation time (not inside React):

```ts
window.__encedoPgpGetHsm         = () => _singleton.state
window.__encedoPgpCheckWkd       = (email) => wkdFetch(email).then(r => r !== null)
window.__encedoPgpSignOnly        = async (params) => { ... }   // sign cleartext via HSM
window.__encedoPgpEncryptAndSign  = async (params) => { ... }   // RFC 3156 encrypt+sign
window.__encedoPgpDecrypt         = async (params) => { ... }   // decrypt/verify
// __encedoPgpRequestUnlock registered by PgpSettingsView.tsx (needs React context)
```

## Crypto architecture — single shared openpgp (since 2026-07-14)

`encedo-pgp.browser.js` no longer embeds openpgp — encedo-pgp-js marks `openpgp` as a
rollup `external`, so the bundle emits `import … from 'openpgp'` and webpack resolves it
to **the same** openpgp instance `app.tsx` imports. One instance, so the old corruption
(`ZBASE32` / `PacketList.fromBinary` → undefined, caused by webpack re-processing an
*embedded* openpgp) is gone.

Consequence: app.tsx can and does call the library's high-level functions directly —
e.g. `readValidatedWkdKey` for WKD key validation. There is no longer a reason to
reimplement openpgp logic locally to dodge the corrupted bundle. Keep using the library
for shared crypto so our patches (minimal MPI encoding, WKD validation, …) apply here too.

Still true: the pure-byte HSM helpers (`buildHsmSignaturePkt`, `signCleartextMessage`,
`buildCertificate`, `hsmDecryptPkesk`) use no openpgp API; app.tsx's HSM ECDH decrypt runs
via `window.crypto.subtle` directly. The multi-key HSM decrypt orchestration in app.tsx is
bespoke (RFC 3156 MIME, recipientEmail filtering) and stays local.

**Do NOT re-embed openpgp** in the rollup build to "make it standalone" — that reintroduces
the two-instance corruption. pgp-test.html supplies openpgp via an import map instead.

## Token management

- Tokens cached in `_singleton.tokenCache` with 8h TTL (30s safety margin)
- `authorize(scope)` — returns cached token or fetches fresh one
- Scopes used (all acquired lazily except list):
  - `keymgmt:list` — search/list keys (obtained at connect)
  - `keymgmt:imp`  — importPublicKey (lazy)
  - `keymgmt:gen`  — createKeyPair (lazy)
  - `keymgmt:del`  — deleteKey (lazy)
  - `keymgmt:use:<kid>` — getPubKey, sign, ecdh (per key, lazy)

## DESCR schema (mirrors encedo-pgp-js/keychain.js)

```
ETSPGP:self,<email>,sign,<iat>[,<exp>]   ← own Ed25519
ETSPGP:self,<email>,ecdh,<iat>[,<exp>]   ← own X25519
ETSPGP:peer,<email>,sign                 ← peer Ed25519
ETSPGP:peer,<email>,ecdh                 ← peer X25519
```

All DESCR values are **base64-encoded** when passed to HEM API (`encodeDescr()`).
`iat` and `exp` are Unix timestamps.

## WKD auth — X-Auth-Token

`publishKey` and `revokeKey` read `ZM_AUTH_TOKEN` cookie from `document.cookie`
and send it as `X-Auth-Token` header. encedo-wkd server validates via Carbonio SOAP.
ZM_AUTH_TOKEN is HttpOnly so cannot be read in JS — server.py also reads it from
the `Cookie:` header directly.

## Auto-unlock modal flow

1. `carbonio-mails-ui` catches "HSM not connected" error from `__encedoPgpDecrypt`
2. Calls `window.__encedoPgpRequestUnlock(callback)`
3. `PgpSettingsView` opens `HsmPasswordModal`
4. After successful unlock: calls `callback()` which retries the decrypt

## Carbonio Shell API used
```ts
addRoute({ id, app, route: 'pgp', appView: PgpView, ... })
registerFunctions({ 'pgp:encrypt', 'pgp:sign-encrypt', 'pgp:decrypt' })  // stubs
useUserAccount()   // → { name, identities, ... }
useUserSettings()  // → { attrs: { zimbraMailAlias, zimbraAllowFromAddress, ... } }
```

## Server info
- Carbonio host: `mailserver` (mailserver.encedo.com)
- Iris path: `/opt/zextras/web/iris/`
- WKD proxy: `https://mailserver.encedo.com/wkd/api/...` (nginx → port 8089)
- Shell version: 14.0.1
- Mails-ui version: 1.31.7 (forked)

## carbonio.webpack.js
- `NormalModuleReplacementPlugin`: strips `node:` prefix from hem-sdk.js imports
- `resolve.fallback`: stubs `https/http/url/net/tls` as false
