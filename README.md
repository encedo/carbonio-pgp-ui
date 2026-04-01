# carbonio-pgp-ui

Carbonio UI module integrating PGP encryption/decryption via [Encedo HEM](https://encedo.com) hardware security module.

Part of **Encedo Mail** — private keys never leave the HSM.

---

## Architecture

```
carbonio-pgp-ui/                     ← this repo (Carbonio React module)
../encedo-pgp-js/                    ← PGP logic (dist/encedo-pgp.browser.js)
../hem-sdk-js/                       ← HEM SDK
../encedo-wkd/                       ← WKD server
```

**Runtime deps** (peer — provided by Carbonio Shell):
- `@zextras/carbonio-shell-ui` — routes, integrations, auth
- `@zextras/carbonio-design-system` — UI components
- `react`, `react-i18next`

**Own deps** (bundled):
- `../encedo-pgp-js/dist/encedo-pgp.browser.js` — PGP + WKD + cert-builder
- `../hem-sdk-js/hem-sdk.js` — HEM API client

---

## Feature plan

### Phase 1 — Settings panel (`/pgp`)

Registered via `addRoute` + `addSettingsView`.

| Section | Actions |
|---------|---------|
| **HSM Connection** | Enter HSM URL (or detect from OIDC token), test connection |
| **Key Management** | Generate Ed25519+X25519 keypair → build cert → publish to WKD |
| **My Keys** | List own keys from HSM (`ETSPGP:self,<email>,...`) with fingerprint, created date |
| **Peer Keys** | List imported peer keys (`ETSPGP:peer,...`), import new peer from WKD |
| **Export** | Re-export+publish cert for existing HSM key pair |
| **Revoke** | Remove key from HSM + revoke from WKD |

#### Auth flow (HSM password)
1. Check if mobile auth available (HEM push/FIDO — future)
2. If not: show password modal with **"Save for this session"** checkbox
3. Password stored in `sessionStorage` if checked, cleared on tab close
4. All tokens (`keymgmt:gen`, `keymgmt:use:*`, etc.) obtained fresh per operation

#### Carbonio token (`X-Auth-Token` for WKD publish)
- Read from `document.cookie` → `ZM_AUTH_TOKEN`
- Sent as `X-Auth-Token` header to `/wkd/api/publish` (nginx-proxied on Carbonio server)

---

### Phase 2 — Mail Compose integration

Registered via `registerFunctions` / `registerComponents` into `carbonio-mails-ui`.

| Hook point | What we add |
|-----------|-------------|
| Compose toolbar | **"Sign + Encrypt"** button — calls `encryptAndSign`, replaces message body |
| Compose toolbar | **"Encrypt only"** button — calls `encryptMessage` |
| Compose (recipient change) | Auto-check WKD for recipient's key, show lock icon |

Implementation: `registerComponents('pgp-compose-toolbar', PgpComposeToolbar)` — mails-ui calls it if present.

---

### Phase 3 — Mail Read integration

| Hook point | What we add |
|-----------|-------------|
| Message body | Auto-detect `-----BEGIN PGP MESSAGE-----` → show **"Decrypt"** button |
| Message body | Auto-detect `-----BEGIN PGP SIGNED MESSAGE-----` → show **"Verify"** button |
| Decrypt result | Replace rendered body with plaintext, show sender + sig validity badge |

---

## Shell API used

```ts
import {
  addRoute,            // register /pgp route
  addSettingsView,     // register in Settings sidebar
  registerComponents,  // expose PGpComposeToolbar to mails-ui
  registerFunctions,   // expose pgp:decrypt, pgp:encrypt to other modules
  useUserAccount,      // get logged-in user email
  useAuthenticated,    // guard routes
} from '@zextras/carbonio-shell-ui';
```

---

## Dev setup

```bash
bash install-deps.sh
npm start -- -h <carbonio-host>   # watch mode, proxied to Carbonio
```

## Build & deploy

```bash
npm run build
npm run deploy -- -h <carbonio-host>
```

## Module entry point

`src/app.tsx` — exports default React component, called by Carbonio Shell loader.
Shell expects: `{ app: default, name, version }` from the module manifest.
