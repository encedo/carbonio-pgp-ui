# carbonio-pgp-ui

Carbonio UI module integrating OpenPGP encryption, decryption and signing via [Encedo HEM](https://encedo.com) hardware security module.

**Private keys never leave the HSM.** All Ed25519 signing and X25519 ECDH operations are performed on the device.

Part of **Encedo Mail**. See [ARCH.md](ARCH.md) for full system architecture.

---

## Repository layout

```
src/
  app.tsx                        ← Shell entry point: route registration, window globals
  store/
    HsmContext.tsx               ← HSM state singleton, token cache, connect/unlock/disconnect
  components/
    HsmPasswordModal.tsx         ← Unlock HSM modal (password + session save)
    HsmUrlModal.tsx              ← HSM URL input modal
    KeygenModal.tsx              ← Generate Ed25519+X25519 keys on HSM + WKD publish
    WkdImportModal.tsx           ← WKD lookup → import peer key to HSM
  views/
    PgpSettingsView.tsx          ← Main settings panel: HSM card, My Keys, Peer Keys
  lib/
    wkd-fetch.ts                 ← WKD HTTP lookup + pure OpenPGP binary parser + fingerprint
    webcrypto-patch.ts           ← Patch globalThis.crypto before openpgp.js init
  types/
    hem.d.ts                     ← HEM SDK TypeScript declarations
```

---

## Build & Deploy

```bash
npm install
npm run build                   # → dist/
bash build-zip.sh               # → carbonio-pgp-ui.zip

rsync -av carbonio-pgp-ui.zip root@mailserver:/tmp/
ssh root@mailserver 'cd /tmp && unzip -o carbonio-pgp-ui.zip && sudo bash install-pgp-ui.sh'
```

Re-register after Carbonio update (if plugin disappears):
```bash
ssh root@mailserver 'sudo bash /tmp/install-pgp-ui.sh --reregister'
```

---

## Features

| Section | Actions |
|---------|---------|
| **HSM Connection** | Enter URL, connect, unlock with password, lock, refresh |
| **My Keys** | List own key pairs, WKD publish/fingerprint status, Publish / Rotate / Revoke |
| **Peer Keys** | Import peer public keys from WKD, WKD obsolete check, Remove |
| **Mail Compose** | Sign-only and Sign+Encrypt buttons (via carbonio-mails-ui bridge) |
| **Mail Read** | Decrypt button, signature verification badge, auto-unlock modal |

---

## Window globals (consumed by carbonio-mails-ui)

| Global | Type | Purpose |
|--------|------|---------|
| `window.__encedoPgpGetHsm` | `() => HsmState` | Read HSM connection state |
| `window.__encedoPgpCheckWkd` | `(email) => Promise<boolean>` | Check WKD key availability |
| `window.__encedoPgpSignOnly` | `(PgpSendParams) => Promise<string>` | Sign message, return armored cleartext |
| `window.__encedoPgpEncryptAndSign` | `(PgpSendParams) => Promise<string>` | Encrypt+sign, return armored PGP MESSAGE |
| `window.__encedoPgpDecrypt` | `(PgpDecryptParams) => Promise<PgpDecryptResult>` | Decrypt/verify received message |
| `window.__encedoPgpRequestUnlock` | `(onUnlocked: () => void) => void` | Open unlock modal, call callback after |

---

## Sibling repos (required at build time)

```
../hem-sdk-js/hem-sdk.browser.js              ← HEM SDK browser bundle
../encedo-pgp-js/dist/encedo-pgp.browser.js   ← PGP logic (cert-builder, sign)
../carbonio-mails-ui/                         ← forked mails-ui
```

---

## HSM Token Scopes

| Scope | Used for | Acquired |
|-------|---------|---------|
| `keymgmt:list` | Search / list keys in HSM | At connect |
| `keymgmt:gen` | Generate new key pair | Lazily on first use |
| `keymgmt:imp` | Import peer public key | Lazily on first use |
| `keymgmt:del` | Delete key | Lazily on first use |
| `keymgmt:use:<kid>` | Sign, ECDH, getPubKey (per key) | Lazily per key |
