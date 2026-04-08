# Encedo Mail — Architecture

**Encedo Mail** is a PGP encryption plugin for Carbonio webmail. Private keys are stored
exclusively in the Encedo HEM hardware security module (USB PPA or EPA device). The browser
never sees a private key — only public keys, digital signatures, and ECDH shared secrets
cross the HSM API boundary.

---

## Repository Map

```
encedo-pgp/
  carbonio-pgp-ui/       ← Carbonio Shell iris module (React/TypeScript/webpack)
  carbonio-mails-ui/     ← Fork of Carbonio mails module (Phase 2+3 changes)
  encedo-pgp-js/         ← PGP crypto library (ES modules, rollup bundle)
  encedo-wkd/            ← WKD key directory server (Python stdlib)
  hem-sdk-js/            ← HEM hardware token SDK (browser JS)
```

---

## System Overview

```
Browser
  │
  ├─ Carbonio Shell (webpack runtime)
  │    ├─ carbonio-pgp-ui      ← our plugin (settings, crypto bridge)
  │    └─ carbonio-mails-ui    ← our fork (compose buttons, message view)
  │
  └─ Encedo HSM (USB device, via local network)
       └─ https://my.ence.do   ← HEM API (HTTPS, JWT-authenticated)

Carbonio Server (mailserver.encedo.com)
  ├─ nginx
  │    ├─ /                    → Carbonio webmail (HTTPS)
  │    ├─ /wkd/api/*           → encedo-wkd (port 8089, auth required)
  │    └─ openpgpkey.*:443     → encedo-wkd (port 8089, public WKD lookup)
  └─ encedo-wkd service        ← WKD key directory (Python, port 8089)
```

---

## Module: carbonio-pgp-ui

**Role:** Settings UI + crypto bridge. All HSM communication and all PGP crypto happens here.

**Entry point:** `src/app.tsx` — evaluated once when Carbonio Shell loads the module.

### Source files

| File | Role |
|------|------|
| `src/app.tsx` | Shell `addRoute`, window globals for mails-ui bridge, all crypto logic |
| `src/store/HsmContext.tsx` | HSM singleton state, token cache, connect/disconnect |
| `src/views/PgpSettingsView.tsx` | Settings panel: HSM card, My Keys table, Peer Keys table |
| `src/components/HsmPasswordModal.tsx` | Unlock HSM dialog |
| `src/components/HsmUrlModal.tsx` | HSM URL input |
| `src/components/KeygenModal.tsx` | Key generation + WKD publish wizard |
| `src/components/WkdImportModal.tsx` | WKD lookup → import peer key to HSM |
| `src/lib/wkd-fetch.ts` | WKD HTTP fetch + OpenPGP binary parser (no openpgp.js) + fingerprint |
| `src/lib/webcrypto-patch.ts` | Patch `globalThis.crypto = window.crypto` before openpgp init |

### HSM singleton pattern

State survives React unmounts (route changes) via module-level `_singleton`:

```ts
// HsmContext.tsx
export const _singleton = {
  password:   string,          // in-memory, cleared on disconnect
  tokenCache: Map<scope, { token, expiresAt }>,
  state: {
    hem:        HEM | null,    // HEM SDK instance
    listToken:  string | null, // keymgmt:list token
    impToken:   string | null, // keymgmt:imp token
    genToken:   string | null, // keymgmt:gen token
    connected:  boolean,
    unlocked:   boolean,
    url:        string,
  }
};
```

All tokens have 8h TTL with 30s safety margin. `authorizeScope(scope)` returns cached
or fetches fresh.

### Window globals (bridge to carbonio-mails-ui)

Defined at module-eval time in `app.tsx`. Available immediately after Shell loads the module.

```ts
window.__encedoPgpGetHsm()
  → HsmState — read HSM connection state synchronously

window.__encedoPgpCheckWkd(email: string)
  → Promise<boolean> — true if WKD key exists for email

window.__encedoPgpSignOnly(params: PgpSendParams)
  → Promise<string> — armored PGP SIGNED MESSAGE (cleartext signature)
  HSM calls: searchKeys, authorizePassword, exdsaSignBytes (×1)

window.__encedoPgpEncryptAndSign(params: PgpSendParams)
  → Promise<string> — armored PGP MESSAGE (RFC 3156 payload)
  HSM calls: searchKeys, authorizePassword, exdsaSignBytes (×1), (no ecdh — encrypt is local)

window.__encedoPgpDecrypt(params: PgpDecryptParams)
  → Promise<PgpDecryptResult> — { html, signerEmail, sigValid }
  HSM calls: searchKeys, authorizePassword, ecdh (×1 per matching PKESK)

window.__encedoPgpRequestUnlock(onUnlocked: () => void)
  → void — registered by PgpSettingsView; opens HsmPasswordModal, calls onUnlocked after
```

---

## Module: carbonio-mails-ui (fork)

**Role:** Mail compose + message read. Consumes window globals from carbonio-pgp-ui.

### Changed files

| File | What changed |
|------|-------------|
| `src/types/messages/index.ts` | Added `isPgpEncrypted?`, `isPgpSigned?` to `MailMessage` |
| `src/types/editor/index.ts` | Added `isPgpSign?`, `isPgpEncrypt?` to editor state |
| `src/store/editor/store.ts` | Added PGP fields to editor store |
| `src/store/editor/hooks/editor.ts` | Added `useEditorIsPgpSign`, `useEditorIsPgpEncrypt` hooks |
| `src/store/editor/editor-transformations.ts` | Added `setIsPgpSign`, `setIsPgpEncrypt` |
| `src/normalizations/normalize-message.ts` | Added `isPgpEncrypted`, `isPgpSigned` normalization |
| `src/commons/mail-message-renderer/mail-message-renderer.tsx` | PGP detection + route to PgpMessageView |
| `src/commons/mail-message-renderer/pgp-message-view.tsx` | **NEW** — decrypt/verify banner + content |
| `src/views/app/detail-panel/edit/edit-view.tsx` | Added `<PgpButtons>` to toolbar |
| `src/views/app/detail-panel/edit/parts/pgp-buttons.tsx` | **NEW** — Sign / Encrypt toolbar buttons |
| `src/views/app/detail-panel/edit/edit-utils-hooks/use-pgp-handlers.tsx` | **NEW** — WKD check, HSM state polling |
| `src/views/app/detail-panel/edit/edit-utils-hooks/pgp-send.ts` | **NEW** — build signed/encrypted MIME |
| `src/views/app/detail-panel/edit/edit-utils-hooks/use-send-handlers.ts` | Intercept send for PGP |

### Message detection (mail-message-renderer.tsx)

```ts
const isPgpEncrypted =
  message.isPgpEncrypted                              // from SOAP normalization
  || body?.contentType === 'application/pgp-encrypted'   // body is sub-part of multipart/encrypted
  || body?.contentType?.startsWith('multipart/encrypted');

const isPgpSigned =
  message.isPgpSigned
  || (body?.contentType === 'text/plain'
      && body?.content?.includes('-----BEGIN PGP SIGNED MESSAGE-----'));
```

Fallback on `body.contentType` needed because Carbonio's `generateBody()` extracts a
sub-part of multipart/encrypted, so `message.isPgpEncrypted` from SOAP normalization
may be false even for PGP messages.

### Message view (pgp-message-view.tsx)

```
PgpMessageView
  ├─ findPgpPartNumber(message)
  │    → iterates message.parts for multipart/encrypted
  │    → finds sub-part with ct = application/octet-stream OR text/plain
  │       (Proton Mail and Thunderbird use text/plain instead of octet-stream)
  │    → returns SOAP part number (e.g. "2")
  │
  ├─ fetchArmoredMessage(msgId, partNum)
  │    → GET /service/home/~/?auth=co&id=<msgId>&part=<partNum>
  │       (SOAP GetMsg does not inline binary part content)
  │
  └─ window.__encedoPgpDecrypt({ armored, mode, senderEmail })
       → decrypts / verifies
       → on "HSM not connected": calls window.__encedoPgpRequestUnlock(retry)
```

### Send flow (pgp-send.ts)

**Sign only:**
```
buildSignedMp(params)
  → window.__encedoPgpSignOnly(params)  → armored PGP SIGNED MESSAGE string
  → returns SOAP mp[] with:
       { ct: 'text/plain', content: armoredSignedMessage }
```

**Encrypt + Sign:**
```
buildEncryptedMp(params)
  → window.__encedoPgpEncryptAndSign(params)  → armored PGP MESSAGE string
  → returns SOAP mp[] with:
       { ct: 'multipart/encrypted; protocol="application/pgp-encrypted"',
         mp: [
           { ct: 'application/pgp-encrypted', content: 'Version: 1\n' },
           { ct: 'application/octet-stream', cd: 'attachment',
             filename: 'encrypted.asc', content: armoredMessage }
         ]
       }
```

The `Content-Disposition: attachment; filename="encrypted.asc"` makes the encrypted
payload downloadable — compatible with all OpenPGP clients (Kleopatra, GPG, etc.).

---

## Module: encedo-pgp-js

**Role:** PGP crypto library. Used by carbonio-pgp-ui via dynamic import.

**Critical constraint:** The rollup bundle (`dist/encedo-pgp.browser.js`) embeds openpgp.js.
When webpack processes this chunk, openpgp.js internals are corrupted:
- Constant `ZBASE32` → undefined (breaks WKD z-base32 hash)
- `PacketList.fromBinary` → undefined (breaks message parsing)

**Solution (two-openpgp architecture):**
- carbonio-pgp-ui has `openpgp@^6` as a **direct npm dep** bundled by webpack → intact
- Only pure-byte functions are called from the rollup bundle:
  - `buildHsmSignaturePkt` — constructs sig packet bytes + literal data bytes
  - `buildCertificate` / `armorCertificate` — builds/exports PGP cert
  - `signCleartextMessage` — `-----BEGIN PGP SIGNED MESSAGE-----`
- All openpgp.js API (readMessage, encrypt, decrypt, readSignature, …) called via webpack openpgp
- All RFC 6637 KDF + AES-KW + session key decode run in `app.tsx` via `window.crypto.subtle`

### Key exports

```
src/index.js
  ← cert-builder.js:  buildCertificate, armorCertificate, signCleartextMessage
  ← openpgp-bridge.js: buildHsmSignaturePkt, hsmDecryptPkesk, encryptMessage,
                        encryptAndSign, decryptMessage, decryptAndVerify,
                        verifySignedMessage, importKeyFromWKD
  ← keychain.js:      DESCR, encodeDescr, decodeDescr, findSelfSign, findSelfEcdh,
                       findPeerSign, findPeerEcdh, findOwnKeys
  ← wkd-client.js:   lookupKey, wkdHash
  ← wkd-publish.js:  publishKey, revokeKey
```

---

## Module: encedo-wkd

**Role:** WKD key directory server. Makes public keys discoverable by email clients.

**Auth:** Production: validates `X-Auth-Token` or `Cookie: ZM_AUTH_TOKEN` against Carbonio SOAP.
Standalone: no auth (port 8089 not exposed externally).

**Key validation:** On publish, server parses submitted OpenPGP binary and verifies that
at least one User ID packet (tag 13) contains the requested email (case-insensitive).
Prevents users from publishing keys with someone else's email.

---

## Crypto Deep Dive

### Key generation

```
hem.createKeyPair(genToken, label, 'ED25519', encodeDescr(DESCR.selfSign(email, iat)))
hem.createKeyPair(genToken, label, 'CURVE25519', encodeDescr(DESCR.selfEcdh(email, iat)))
```
→ HSM generates Ed25519 + X25519 keys. Private key bytes never leave device.

```
hem.getPubKey(useToken, kid_sign)  → raw 32-byte Ed25519 public key
hem.getPubKey(useToken, kid_ecdh)  → raw 32-byte X25519 public key
```
→ `buildCertificate()` constructs OpenPGP v4 packets:
  - Primary key packet: Ed25519, timestamp = `iat`
  - User ID packet: `<email>`
  - Signature packet (self-sig on UID): SHA-256 hash of cert data → `hem.exdsaSignBytes` → Ed25519 sig
  - Subkey packet: X25519, timestamp = `iat`
  - Signature packet (subkey binding sig): same pattern

`iat` baked into cert ensures fingerprint is deterministic — cert can be rebuilt from HSM.

### Sign cleartext message

```
signCleartextMessage(hem, signToken, kid_sign, keyId8, plaintext)
```
1. Hash = SHA-256(cleartext + sig trailer bytes)
2. `hem.exdsaSignBytes(signToken, kid_sign, hash, 'Ed25519')` → 64-byte raw sig
3. Encode as OpenPGP Ed25519 signature packet
4. Wrap in `-----BEGIN PGP SIGNED MESSAGE-----` cleartext format

HSM calls: `exdsaSignBytes` ×1

### Encrypt + Sign for send

```
window.__encedoPgpEncryptAndSign(params)
```
1. `hem.searchKeys(listToken, 'ETSPGP:')` → find own Ed25519 key for sender
2. `authorizeScope('keymgmt:use:<kid_sign>')` → get sign token
3. `wkdFetch(senderEmail)` → get sender's WKD cert, extract `keyId8`
4. `buildHsmSignaturePkt(hem, signToken, kid_sign, keyId8, innerMime)`:
   - innerMime = multipart/alternative MIME (plain + HTML)
   - SHA-256(innerMime + sig trailer) → `hem.exdsaSignBytes` → sig packet bytes
   - Returns `{ sigPkt: Uint8Array, dataBytes: Uint8Array }`
5. WKD lookup for each recipient → `openpgp.readKey` (webpack openpgp)
6. `openpgp.readSignature({ binarySignature: sigPkt })` → openpgp Signature object
7. `openpgp.createMessage({ binary: dataBytes })` → literal message
8. `litMsg.sign([], [], existingSig)` → signed message (OPS + LiteralData + Sig)
9. `openpgp.encrypt({ message: signedMsg, encryptionKeys })` → armored PGP MESSAGE

HSM calls: `searchKeys` ×1, `authorizePassword` ×1-2, `exdsaSignBytes` ×1
WKD calls: sender + each recipient

### Decrypt received message

```
window.__encedoPgpDecrypt({ armored, mode: 'encrypt', senderEmail })
```
1. `hem.searchKeys(listToken, 'ETSPGP:')` → find own X25519 (ECDH) key
2. `authorizeScope('keymgmt:use:<kid_ecdh>')` → get ECDH token
3. `wkdFetch(myEmail)` → get my own WKD cert, extract ECDH subkey fingerprint (20 bytes)
4. `openpgp.readMessage({ armoredMessage })` → parse PGP message (webpack openpgp)
5. `packets.filterByTag(publicKeyEncryptedSessionKey)` → find PKESK packet(s)
6. For each PKESK (legacy ECDH algo 18 format: `{ V, C.data }`):
   - Extract ephemeral public key V (33 bytes: 0x40 prefix + 32 bytes → strip prefix)
   - `btoa(ephemeral32)` → base64
   - `hem.ecdh(ecdhToken, kid_ecdh, ephemeralB64)` → 32-byte X25519 shared secret
   - RFC 6637 §8 KDF: `SHA-256(0x00000001 || Z || OID_len || OID_X25519 || 0x12 || 030108 09 || "Anonymous Sender    " || fingerprint)` → 32-byte KWK
   - AES-KW unwrap: `window.crypto.subtle.unwrapKey('raw', C.data, KWK, 'AES-KW', HMAC_SHA256, true, ['sign'])` → unwrapped bytes
   - Strip PKCS#5 encoding: `[sym_algo_byte][session_key][2-byte checksum][padding]` → session key bytes
   - `openpgp.enums.read(openpgp.enums.symmetric, algoId)` → algo name (e.g. `'aes256'`)
7. `openpgp.decrypt({ message, sessionKeys: [sessionKey], verificationKeys })` → plaintext + sigs
8. `sig.verified` → boolean sig validity
9. `extractHtmlFromMime(plaintext)` → parse nested MIME, decode base64/QP, extract text/html

HSM calls: `searchKeys` ×1, `authorizePassword` ×1-2, `ecdh` ×1 (per matching PKESK)
WKD calls: own cert (fingerprint), sender cert (sig verification)

### Verify inline signed message

```
window.__encedoPgpDecrypt({ armored, mode: 'sign', senderEmail })
```
1. `wkdFetch(senderEmail)` → sender public key bytes
2. `openpgp.readKey({ binaryKey })` → sender PublicKey (webpack openpgp)
3. `openpgp.readCleartextMessage({ cleartextMessage: armored })` → parsed message
4. `openpgp.verify({ message, verificationKeys: [senderPubKey] })` → verify
5. `sig.verified` → boolean

HSM calls: none (verify-only, public key operation)

---

## HSM API Endpoints (called by browser JS)

All calls go to `https://my.ence.do` (or configured HSM URL) via `hem-sdk-js`.
Authentication: JWT tokens obtained via `hem.authorizePassword(pw, scope)`.

| Endpoint | Method | Called when | Scope |
|----------|--------|------------|-------|
| `/api/system/checkin` | POST | On every HSM connect (startup) | none |
| `/api/auth/token` | POST | `authorizePassword(pw, scope)` for each new scope | none |
| `/api/keymgmt/search` | GET | Load keys list: settings view, send, decrypt | `keymgmt:list` |
| `/api/keymgmt/generate` | POST | Keygen (KeygenModal) | `keymgmt:gen` |
| `/api/keymgmt/import` | POST | Import peer key (WkdImportModal) | `keymgmt:imp` |
| `/api/keymgmt/delete` | DELETE | Revoke / Rotate / Remove peer | `keymgmt:del` |
| `/api/keymgmt/pubkey` | GET | Get raw public key bytes for cert build | `keymgmt:use:<kid>` |
| `/api/crypto/sign` | POST | Ed25519 signature (cert build, message sign) | `keymgmt:use:<kid>` |
| `/api/crypto/ecdh` | POST | X25519 shared secret (decrypt) | `keymgmt:use:<kid>` |

### Token caching strategy

Tokens are cached in `_singleton.tokenCache` with 8h TTL. After successful unlock:
- `keymgmt:list`, `keymgmt:imp`, `keymgmt:gen` obtained immediately and cached
- `keymgmt:use:<kid>` obtained lazily on first use, cached per kid

On each send or decrypt:
- If token for that kid is in cache and not expired → reuse (zero `/api/auth/token` calls)
- If expired or missing → one `/api/auth/token` call per scope needed

### Typical HSM call sequence for Decrypt

```
1. POST /api/system/checkin           (if not yet connected)
2. POST /api/auth/token               (keymgmt:list, if not cached)
3. GET  /api/keymgmt/search           (find own ECDH key)
4. POST /api/auth/token               (keymgmt:use:<kid_ecdh>, if not cached)
5. POST /api/crypto/ecdh              (X25519 shared secret for session key)
   → KDF + AES-KW done in browser (window.crypto.subtle)
```

### Typical HSM call sequence for Sign + Encrypt (send)

```
1. GET  /api/keymgmt/search           (find own sign key)
2. POST /api/auth/token               (keymgmt:use:<kid_sign>, if not cached)
3. POST /api/crypto/sign              (Ed25519 sig for inner MIME payload)
   → WKD lookups for sender + recipients (public, no HSM)
   → openpgp.encrypt() in browser (no HSM)
```

### Typical HSM call sequence for Key Generation

```
1. POST /api/auth/token               (keymgmt:gen)
2. POST /api/keymgmt/generate         (Ed25519 key)
3. POST /api/keymgmt/generate         (X25519 key)
4. POST /api/auth/token               (keymgmt:use:<kid_sign>)
5. POST /api/auth/token               (keymgmt:use:<kid_ecdh>)
6. GET  /api/keymgmt/pubkey           (get Ed25519 public key bytes)
7. GET  /api/keymgmt/pubkey           (get X25519 public key bytes)
8. POST /api/crypto/sign              (self-sig on User ID packet)
9. POST /api/crypto/sign              (subkey binding sig)
   → POST /wkd/api/publish (Carbonio server, not HSM)
```

---

## WKD Protocol

WKD (Web Key Directory) allows email clients to auto-discover recipient public keys.

### Lookup (client → server)

```
Advanced method (preferred):
  GET https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<localpart>

Direct method (fallback):
  GET https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<localpart>

hash = z-base32(SHA-1(lowercase(localpart)))
```

### Publish (Carbonio plugin → encedo-wkd)

```
POST https://mailserver.encedo.com/wkd/api/publish
X-Auth-Token: <ZM_AUTH_TOKEN>
Content-Type: application/json

{ "email": "user@domain.com", "pubkey_base64": "<base64 binary OpenPGP cert>" }
```

Server validates: User ID packet in cert must contain the requested email.

---

## MIME Structures

### Outgoing signed (Sign-only mode)

```
Content-Type: text/plain; charset=utf-8

-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

<plaintext>
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

### Outgoing encrypted+signed (RFC 3156)

```
Content-Type: multipart/encrypted;
  protocol="application/pgp-encrypted"; boundary="<boundary>"

--<boundary>
Content-Type: application/pgp-encrypted

Version: 1

--<boundary>
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="encrypted.asc"

-----BEGIN PGP MESSAGE-----
...
-----END PGP MESSAGE-----
--<boundary>--
```

The PGP MESSAGE contains (inside SEIPD packet):
```
OPS (One-Pass Signature) packet
Literal Data packet
  Content-Type: multipart/alternative; boundary="<inner>"
  --<inner>
  Content-Type: text/plain; charset=utf-8
  <plain text>
  --<inner>
  Content-Type: text/html; charset=utf-8
  <html body>
  --<inner>--
Signature packet (Ed25519)
```

### Interoperability

| Client | Receives as | Notes |
|--------|------------|-------|
| Our Carbonio plugin | Decrypts via HSM ECDH | Full support |
| Thunderbird | Shows encrypted.asc attachment, can decrypt with GPG key | Downloads attachment |
| Proton Mail | Auto-decrypts | Full support (sends text/plain instead of octet-stream) |
| Kleopatra / GPG CLI | `gpg --decrypt encrypted.asc` | Standard RFC 3156 |

Proton Mail and Thunderbird use `Content-Type: text/plain` for the ciphertext part
instead of `application/octet-stream` (RFC 3156 strict). Our parser accepts both.

---

## OpenPGP Version Notes

The system uses OpenPGP v4 (RFC 4880) throughout:
- Ed25519 primary key (algo 22, OID 1.3.6.1.4.1.11591.15.1)
- X25519 ECDH subkey (algo 18, OID 1.3.6.1.4.1.3029.1.5.1)
- v4 fingerprint: SHA-1(0x99 || uint16be(bodyLen) || body), 20 bytes
- Session key algo 9 = AES-256

openpgp.js v6.3.0 is used. The library also supports v6 (RFC 9580) keys and
algo 25 (new X25519) — our parser handles both PKESK formats.
