# carbonio-pgp-ui — CLAUDE.md

## Purpose
Carbonio UI module — PGP encrypt/decrypt/sign/verify via Encedo HEM HSM.
Loaded by Carbonio Shell as a standard iris module.

## Deployment mechanism
```
/opt/zextras/web/iris/
  components.json                        ← Shell reads this on startup (array of all modules)
  carbonio-pgp-ui/
    <git-commit-hash>/                   ← built dist/* copied here by sdk deploy
      app.<contenthash>.js               ← webpack entry bundle
      *.chunk.js                         ← lazy chunks
      component.json                     ← module manifest (same as entry in components.json)
    current/                             ← symlink → <commit> (may be empty dir in older installs)
    i18n/
```

`sdk deploy -h <host>` → SSH to host, copies dist/ to `/opt/zextras/web/iris/<name>/<commit>/`,
updates `/opt/zextras/web/iris/components.json` to register the module.

After deploy the Shell picks up on next browser load (no server restart needed).

## component.json format
```json
{
  "name": "carbonio-pgp-ui",
  "js_entrypoint": "/static/iris/carbonio-pgp-ui/<commit>/app.<hash>.js",
  "description": "PGP encryption via Encedo HEM",
  "version": "0.1.0",
  "commit": "<git-commit-hash>",
  "priority": 20,
  "type": "carbonio",
  "icon": "LockOutline",
  "display": "PGP"
}
```
`attrKey` is optional — omit for now (no Zimbra feature flag needed).

## Build toolchain
```
@zextras/carbonio-ui-sdk@2.2.2   ← sdk build / sdk deploy / sdk watch
```
commands:
- `npm run build`       → `sdk build` → `dist/`
- `npm run start -- -h <host>` → `sdk watch` (webpack watch + proxy to Carbonio)
- `npm run deploy -- -h <host>` → `sdk deploy`

## Carbonio Shell API (from @zextras/carbonio-shell-ui@14.0.1)

### App-dependant (called during module init, from app.tsx):
```ts
import {
  addRoute,           // register main nav route
  addSettingsView,    // register Settings panel section
  registerComponents, // expose React components to other modules
  registerFunctions,  // expose functions to other modules
} from '@zextras/carbonio-shell-ui';
```

### Direct exports (hooks, usable anywhere):
```ts
import {
  useUserAccount,          // { name, displayName, ... } — logged-in account
  useAuthenticated,        // boolean
  useIntegratedFunction,   // call function registered by another module
  useIntegratedComponent,  // render component from another module
  getIntegratedFunction,   // non-hook version
  AuthGuard,               // route guard component
} from '@zextras/carbonio-shell-ui';
```

## Carbonio auth token
- Cookie `ZM_AUTH_TOKEN` — standard Zimbra/Carbonio session token
- Used as `X-Auth-Token` header for WKD `/api/publish` and `/api/revoke`
- Read via: `document.cookie.match(/ZM_AUTH_TOKEN=([^;]+)/)?.[1]`
- The WKD server at `https://<carbonio-domain>/wkd/` validates it via Carbonio SOAP GetInfoRequest

## HSM password auth flow
1. Check `sessionStorage.getItem('pgp-hsm-password')` (if user checked "save for session")
2. If absent → show password modal
3. Modal has checkbox "Save for this session" → on confirm: `sessionStorage.setItem('pgp-hsm-password', pw)`
4. All HEM tokens obtained fresh per operation (authorizePassword)
5. Mobile auth (HEM push/FIDO) — future phase

## HSM URL discovery
Priority order:
1. OIDC token claim `hem_url` (future)
2. `localStorage.getItem('pgp-hsm-url')` (user cached)
3. Ask user → save to localStorage

## Sibling repos (must be present at build time)
```
../hem-sdk-js/hem-sdk.js                      ← HEM SDK
../encedo-pgp-js/dist/encedo-pgp.browser.js   ← PGP logic (bundled)
```
Both are imported as relative paths and bundled into the module by webpack.

## Source layout (to be created)
```
src/
  app.tsx                  ← module entry point (React component + Shell registrations)
  store/
    hsm-store.ts           ← HEM instance, password, tokens (Zustand or React context)
  components/
    HsmPasswordModal.tsx   ← password prompt with "save for session" checkbox
    HsmUrlModal.tsx        ← HSM URL input + save to localStorage
  views/
    PgpSettingsView.tsx    ← addSettingsView target
    KeygenSection.tsx      ← keygen + WKD publish
    KeyListSection.tsx     ← list HSM keys (own + peer)
    PeerImportSection.tsx  ← import peer key from WKD
  integrations/
    PgpComposeToolbar.tsx  ← registerComponents → mails-ui compose toolbar
    PgpMessageBanner.tsx   ← registerComponents → mails-ui message view banner
```

## Integration with carbonio-mails-ui
The mails-ui module calls `useIntegratedComponent` / `useIntegratedFunction` to check if
PGP functions are available. We register:

| Key | Type | Description |
|-----|------|-------------|
| `pgp:compose-toolbar` | Component | Sign+Encrypt / Encrypt buttons in compose toolbar |
| `pgp:message-banner` | Component | Decrypt / Verify banner in message reading view |
| `pgp:encrypt` | Function | `(plaintext, toEmails) => Promise<armoredMessage>` |
| `pgp:sign-encrypt` | Function | `(plaintext, toEmail, fromEmail) => Promise<armoredMessage>` |
| `pgp:decrypt` | Function | `(armoredMessage, myEmail) => Promise<{data, valid, keyID}>` |

## Phase plan
- **Phase 1** (current): Settings panel — keygen, key list, WKD publish/revoke, peer import
- **Phase 2**: Compose integration — Sign+Encrypt button
- **Phase 3**: Message view — auto-detect ciphertext, Decrypt/Verify banner

## Server info
- Carbonio host: mailserver
- Iris path: `/opt/zextras/web/iris/`
- WKD proxy: `https://<domain>/wkd/api/...` (nginx → port 8089)
- Shell version: 14.0.1
- Mails-ui version: 1.31.4
