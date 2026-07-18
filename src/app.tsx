import * as openpgp from 'openpgp';
// @ts-expect-error — carbonio-shell-ui types incomplete but hooks exist at runtime
import { addRoute, registerFunctions } from '@zextras/carbonio-shell-ui';
import { HsmProvider, _singleton, decodeDescr } from './store/HsmContext';
import { patchWebCrypto } from './lib/webcrypto-patch';
import { wkdFetch, wkdLookupParse, parseKeyInfo } from './lib/wkd-fetch';
import { keyserverFetch, keyserverFetchByKeyId, keyserverFetchBinary } from './lib/keyservers';
import { getPgpPrefs } from './lib/pgp-prefs';
import { PgpSettingsView } from './views/PgpSettingsView';

const APP_ID = 'carbonio-pgp-ui';

// ── Inline ECDH decryption helpers (all in webpack/window context) ────────────

const OID_X25519 = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

async function rfc6637kdfLocal(Z: Uint8Array, fingerprint: Uint8Array): Promise<Uint8Array> {
  // SHA-256( 00 00 00 01 || Z || OID_len || OID || 0x12 || 03 01 08 09 || "Anonymous Sender    " || fingerprint )
  const data = concatBytes(
    new Uint8Array([0x00, 0x00, 0x00, 0x01]),
    Z,
    new Uint8Array([OID_X25519.length]),
    OID_X25519,
    new Uint8Array([0x12]),              // ECDH algo id
    new Uint8Array([0x03, 0x01, 8, 9]), // KDF params: SHA-256, AES-256
    new TextEncoder().encode('Anonymous Sender    '), // exactly 20 bytes
    fingerprint,
  );
  // Use data.slice().buffer to ensure we have a standalone ArrayBuffer (data may be a view)
  const hash = await window.crypto.subtle.digest('SHA-256', data.slice(0).buffer);
  return new Uint8Array(hash).slice(0, 32); // AES-256 KWK = 32 bytes, slice() gives own buffer
}

async function aesKwUnwrapLocal(kwk: Uint8Array, wrappedKey: Uint8Array): Promise<Uint8Array> {
  // .slice(0) creates a copy with its own standalone ArrayBuffer (avoids subarray buffer issues)
  const kek = await window.crypto.subtle.importKey(
    'raw', kwk.slice(0).buffer, { name: 'AES-KW' }, false, ['unwrapKey']
  );
  // HMAC as target algo accepts arbitrary key lengths (unlike AES)
  const unwrapped = await window.crypto.subtle.unwrapKey(
    'raw', wrappedKey.slice(0).buffer, kek, 'AES-KW', { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']
  );
  return new Uint8Array(await window.crypto.subtle.exportKey('raw', unwrapped));
}

/** Strip RFC 4880 §13.5 session key encoding: [sym_algo][key][2-byte checksum][pkcs5 pad] */
function stripSessionKeyEncoding(padded: Uint8Array): Uint8Array {
  const padLen = padded[padded.length - 1];
  if (padLen < 1 || padLen > 8) throw new Error(`Invalid PKCS#5 padding byte: ${padLen}`);
  return padded.slice(1, padded.length - padLen - 2);
}

/** Full ECDH session key decryption — all crypto in webpack/window context, only ECDH call to HSM */
async function localDecryptPkesk(
  ephemeralWithPrefix: Uint8Array,
  wrappedKey: Uint8Array,
  fingerprint: Uint8Array,
  algoId: number,
  hem: any, token: string, kid_ecdh: string,
): Promise<{ data: Uint8Array; algorithm: openpgp.SessionKey['algorithm'] }> {
  // Strip 0x40 native prefix if present
  const ephemeral32 = (ephemeralWithPrefix.length === 33 && ephemeralWithPrefix[0] === 0x40)
    ? ephemeralWithPrefix.slice(1)
    : ephemeralWithPrefix;
  const ephemeralB64 = btoa(String.fromCharCode(...Array.from(ephemeral32)));
  const sharedSecret: Uint8Array = await hem.ecdh(token, kid_ecdh, ephemeralB64);
  const kwk = await rfc6637kdfLocal(sharedSecret, fingerprint);
  sharedSecret.fill(0);
  const unwrapped = await aesKwUnwrapLocal(kwk, wrappedKey);
  kwk.fill(0);
  const sessionKeyData = stripSessionKeyEncoding(unwrapped);
  const algoName = openpgp.enums.read(openpgp.enums.symmetric, algoId) as openpgp.SessionKey['algorithm'];
  return { data: sessionKeyData, algorithm: algoName };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function authorizeScope(scope: string): Promise<string> {
  const { hem } = _singleton.state;
  if (!hem) throw new Error('HSM not connected');
  const cached = _singleton.tokenCache.get(scope);
  if (cached && Date.now() < cached.expiresAt) return cached.token;
  const TOKEN_TTL = 8 * 3600;
  // Pass '' — HEM reuses cached derived keys from connect(); password never stored here.
  const token = await hem.authorizePassword('', scope, TOKEN_TTL);
  _singleton.tokenCache.set(scope, { token, expiresAt: Date.now() + TOKEN_TTL * 1000 - 30_000 });
  return token;
}

async function getPgp() {
  patchWebCrypto();
  return import('../../encedo-pgp-js/dist/encedo-pgp.browser.js');
}

// Full-debug logging for the PGP decrypt/verify flow. Flip PGP_DEBUG to false for a
// production build (or set window.__encedoPgpDebug = false before load to silence at
// runtime). All lines are prefixed [pgp] in the browser console.
const PGP_DEBUG = ((): boolean => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const w = window as any;
    return w.__encedoPgpDebug !== undefined ? !!w.__encedoPgpDebug : true;
  } catch { return true; }
})();
function dlog(...args: unknown[]): void {
  // eslint-disable-next-line no-console
  if (PGP_DEBUG) console.log('[pgp]', ...args);
}

/**
 * Fetch a WKD key and validate it for `email` using the library's
 * readValidatedWkdKey. Since encedo-pgp.browser.js now imports openpgp as an
 * external (the single shared instance), the returned key is a normal
 * openpgp.PublicKey usable directly with openpgp.encrypt/verify here.
 */
async function readValidatedWkdKey(
  keyBytes: Uint8Array,
  email: string,
  opts: { requireEncryptionKey?: boolean } = {}
): Promise<openpgp.PublicKey> {
  const { readValidatedWkdKey: validate } = await getPgp();
  return validate(keyBytes, email, opts) as Promise<openpgp.PublicKey>;
}

/**
 * Resolve and validate a recipient's public key. Tries WKD first (key served from the
 * recipient's own domain over TLS — strongest binding), then the configured VKS
 * keyservers (keys.openpgp.org verifies the address). The same validation (UID↔email +
 * usable encryption key) applies whatever the source, so an RSA key from a keyserver is
 * accepted just like an Ed25519/X25519 WKD key.
 */
async function resolveRecipientKey(email: string): Promise<openpgp.PublicKey> {
  // Gather published keys from both sources (WKD first, then keyservers).
  const sources: Uint8Array[] = [];
  const wkd = await wkdFetch(email);
  if (wkd) sources.push(wkd);
  const armored = await keyserverFetch(email);
  if (armored) { try { sources.push((await openpgp.readKey({ armoredKey: armored })).write()); } catch { /* skip */ } }
  if (!sources.length) throw new Error(`No key found for ${email} (WKD or keyservers)`);

  // If this address is a trusted peer, encrypt to the published key that matches the key you
  // imported/pinned into the HSM — NOT simply the first source. Otherwise, when WKD and the
  // keyserver serve different keys, we could encrypt to a different key than the one you trust
  // (e.g. WKD serves a stale key while you imported the recipient's real key from a keyserver).
  const peer = (await getTrustedPeers()).get(email.toLowerCase());
  if (peer && (peer.kidSign || peer.kidEcdh)) {
    try {
      const hemRaw = await getPeerHemRaw(email, peer);
      const mine = peer.kidSign ? hemRaw.sign : hemRaw.ecdh;
      for (const bytes of sources) {
        try {
          const info = await parseKeyInfo(email, bytes);
          const pub = peer.kidSign ? info.signRaw32 : info.ecdhRaw32;
          if (bytesEqual(mine, pub)) { dlog('resolveRecipientKey: using trusted-peer-matching key for', email); return readValidatedWkdKey(bytes, email); }
        } catch { /* try next source */ }
      }
      throw new Error(`The trusted key for ${email} is no longer published (WKD/keyserver now serve a different key). Re-import or remove the peer key before encrypting.`);
    } catch (e) {
      // Only a genuine "trusted key gone" is fatal; an HSM read hiccup falls back to source order.
      if (e instanceof Error && e.message.startsWith('The trusted key')) throw e;
      dlog('resolveRecipientKey: peer match unavailable, falling back to source order:', e instanceof Error ? e.message : e);
    }
  }

  return readValidatedWkdKey(sources[0], email);
}

/** True if a usable key for this address can be found via WKD or a configured keyserver. */
async function isRecipientKeyAvailable(email: string): Promise<boolean> {
  if (await wkdFetch(email)) return true;
  return (await keyserverFetch(email)) !== null;
}

// Trusted peers = keys the user deliberately imported into the HSM (ETSPGP:peer). A message
// to such an address is "TRUSTED" — but only if the live WKD key still matches the key we
// stored (fingerprint/raw-key pinning): if the WKD key was swapped, that's 'mismatch' and
// encryption is refused. Cached per session; refreshed at unlock and after an import.
type PeerEntry = { kidSign?: string; kidEcdh?: string };
let _peerCache: Map<string, PeerEntry> | null = null;
const _peerHemRaw = new Map<string, { sign?: Uint8Array; ecdh?: Uint8Array }>();

function clearPeerCaches(): void {
  _peerCache = null;
  _peerHemRaw.clear();
}

async function getTrustedPeers(): Promise<Map<string, PeerEntry>> {
  if (_peerCache) return _peerCache;
  const { hem, listToken } = _singleton.state;
  if (!hem || !listToken) return new Map();
  try {
    const keys = await hem.searchKeys(listToken, 'ETSPGP:');
    const map = new Map<string, PeerEntry>();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (const k of keys as any[]) {
      const d = decodeDescr(k);
      if (d?.role === 'peer' && d.email) {
        const e = map.get(d.email.toLowerCase()) ?? {};
        if (d.keyType === 'sign') e.kidSign = k.kid;
        if (d.keyType === 'ecdh') e.kidEcdh = k.kid;
        map.set(d.email.toLowerCase(), e);
      }
    }
    _peerCache = map;
    return map;
  } catch {
    return new Map();
  }
}

/** Raw public-key bytes of a peer as stored in the HSM (cached), used for pinning. */
async function getPeerHemRaw(email: string, entry: PeerEntry): Promise<{ sign?: Uint8Array; ecdh?: Uint8Array }> {
  const key = email.toLowerCase();
  const cached = _peerHemRaw.get(key);
  if (cached) return cached;
  const { hem } = _singleton.state;
  // getPubKey may resolve to a raw base64 string OR an object { pubkey } — normalise, then
  // decode. (Passing the object straight to atob was yielding garbage → false mismatch.)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const toB64 = (r: any): string => (typeof r === 'string' ? r : r?.pubkey ?? '');
  const b64ToBytes = (b64: string): Uint8Array => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const out: { sign?: Uint8Array; ecdh?: Uint8Array } = {};
  try {
    // We pin on the primary (sign) key, so only fetch that; fall back to ECDH only if the
    // peer has no sign key.
    if (entry.kidSign) out.sign = b64ToBytes(toB64(await hem!.getPubKey(await authorizeScope(`keymgmt:use:${entry.kidSign}`), entry.kidSign)));
    else if (entry.kidEcdh) out.ecdh = b64ToBytes(toB64(await hem!.getPubKey(await authorizeScope(`keymgmt:use:${entry.kidEcdh}`), entry.kidEcdh)));
  } catch { /* leave what we got */ }
  _peerHemRaw.set(key, out);
  return out;
}

function bytesEqual(a?: Uint8Array, b?: Uint8Array): boolean {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

type RecipientKeyStatus = 'trusted' | 'mismatch' | 'available' | 'unavailable';
async function recipientKeyStatus(email: string): Promise<RecipientKeyStatus> {
  const peer = (await getTrustedPeers()).get(email.toLowerCase());
  if (peer && (peer.kidSign || peer.kidEcdh)) {
    // Trusted peer — pin: a live published key must still match the key stored in the HSM.
    // The peer may have been imported from WKD OR from a keyserver (VKS), and a domain can
    // even publish a different key to each, so compare against BOTH sources and trust if the
    // HSM key still matches EITHER. Pinning against WKD only gave a false "mismatch" for a
    // peer imported from a keyserver whose WKD key differs.
    try {
      const hemRaw = await getPeerHemRaw(email, peer);
      // Pin on the PRIMARY (signing) key only — that is the identity. The ECDH subkey is
      // bound to it by a signature (an attacker can't forge that), and it may be legitimately
      // rotated, so comparing it would give false mismatches. Mirrors the PGP panel's check.
      const mine = peer.kidSign ? hemRaw.sign : hemRaw.ecdh;
      const published: Uint8Array[] = [];
      try { const wkd = await wkdLookupParse(email); published.push(peer.kidSign ? wkd.signRaw32 : wkd.ecdhRaw32); }
      catch (e) { dlog('trusted-check: no WKD key for', email, '-', e instanceof Error ? e.message : e); }
      try { const ks = await keyserverFetchBinary(email); if (ks) { const info = await parseKeyInfo(email, ks.bytes); published.push(peer.kidSign ? info.signRaw32 : info.ecdhRaw32); } }
      catch (e) { dlog('trusted-check: no keyserver key for', email, '-', e instanceof Error ? e.message : e); }
      if (!published.length) {
        // Can't fetch any live key to compare — don't silently trust a pinned key we can't re-verify.
        return 'unavailable';
      }
      const ok = published.some((p) => bytesEqual(mine, p));
      dlog('trusted-check:', email, '| hemSign=', mine?.length, '| sources=', published.length, '| match=', ok);
      return ok ? 'trusted' : 'mismatch';
    } catch {
      return 'unavailable';
    }
  }
  return (await isRecipientKeyAvailable(email)) ? 'available' : 'unavailable';
}

// ── Window globals — consumed by carbonio-mails-ui ────────────────────────────

// One-time call secret — required by all sensitive window globals.
// __encedoPgpRegister() returns the secret and self-deletes; only the first caller gets it.
// Prevents accidental misuse by other Iris modules or supply-chain scripts.
const _callSecret: string = Array.from(
  crypto.getRandomValues(new Uint8Array(16))
).map(b => b.toString(16).padStart(2, '0')).join('');

function requireSecret(provided: unknown): void {
  if (provided !== _callSecret) throw new Error('Unauthorized: invalid call token');
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpRegister = (): string => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  delete (window as any).__encedoPgpRegister;
  return _callSecret;
};

// Expose ONLY the safe connection flags — never the live `hem` instance (which holds the
// cached derived keys and can sign/ecdh) nor the tokens. Returning the raw _singleton.state
// let any script on the page do `__encedoPgpGetHsm().hem.exdsaSignBytes(...)`, bypassing the
// call-secret. mails-ui only reads `unlocked` / `connected`.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpGetHsm = () => {
  const { connected, unlocked, url } = _singleton.state;
  return { connected, unlocked, url };
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpCheckWkd = (email: string) => isRecipientKeyAvailable(email);
// Richer per-recipient status for the composer: 'trusted' (key imported into the HSM),
// 'available' (found live via WKD/keyserver) or 'unavailable'.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpRecipientStatus = (email: string) => recipientKeyStatus(email);
// Invalidate the trusted-peer cache after a peer key is imported/removed in the PGP panel.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpRefreshPeers = () => { clearPeerCaches(); };

/**
 * Verify an inbound RFC 3156 multipart/signed message (e.g. from Thunderbird): a DETACHED
 * signature over the exact canonical bytes of the signed MIME part. Verify-only, no HSM.
 * The caller (mails-ui) passes the byte-exact signed part (base64) + the armored signature +
 * the sender address; we fetch the sender's public key (WKD → keyserver) and verify.
 */
interface VerifyDetachedParams { signedB64: string; armoredSignature: string; senderEmail: string; }
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpVerifyDetached = async (params: VerifyDetachedParams, callSecret?: unknown): Promise<{ valid: boolean | null; signerEmail: string | null; html: string }> => {
  requireSecret(callSecret);
  const { signedB64, armoredSignature, senderEmail } = params;
  // The signed part is itself a MIME (sub)tree — render it for display regardless of the
  // signature outcome, reusing the same extractor as the decrypt path.
  const signedText = (() => { try { return new TextDecoder().decode(Uint8Array.from(atob(signedB64), (c) => c.charCodeAt(0))); } catch { return ''; } })();
  const html = signedText ? extractHtmlFromMime(signedText) : '';
  if (!senderEmail) return { valid: null, signerEmail: null, html };

  // Read the signature first so we know WHICH key issued it. The signer may have signed
  // with a key that differs from what a by-email lookup returns for their address (e.g. a
  // Thunderbird key vs the HSM/WKD key), so we must verify against the issuer's key, not
  // just "a key for this address".
  let signature: openpgp.Signature;
  try { signature = await openpgp.readSignature({ armoredSignature }); }
  catch (e) { dlog('verifyDetached: bad signature:', e instanceof Error ? e.message : e); return { valid: null, signerEmail: senderEmail, html }; }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const issuerId = (signature.packets?.[0] as any)?.issuerKeyID?.toHex?.() ?? null;

  // Gather candidate keys: the by-email key (WKD → keyserver) and, if it doesn't match the
  // issuer, the exact issuer key by keyID from the keyservers.
  const candidates: openpgp.PublicKey[] = [];
  const addArmored = async (armored: string | null): Promise<void> => {
    if (!armored) return;
    try { candidates.push(await openpgp.readKey({ armoredKey: armored })); } catch { /* skip */ }
  };
  const wkdBytes = await wkdFetch(senderEmail);
  if (wkdBytes) {
    try { candidates.push(await readValidatedWkdKey(wkdBytes, senderEmail, { requireEncryptionKey: false })); }
    catch (e) { dlog('verifyDetached: WKD key rejected:', e instanceof Error ? e.message : e); }
  }
  await addArmored(await keyserverFetch(senderEmail));
  const matches = (k: openpgp.PublicKey): boolean =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    !!issuerId && k.getKeys().some((sub: any) => sub.getKeyID().toHex() === issuerId);
  if (issuerId && !candidates.some(matches)) await addArmored(await keyserverFetchByKeyId(issuerId));

  const keyIds = candidates.map((k) => k.getKeyID().toHex()).join(',');
  const signer = issuerId ? candidates.find(matches) : candidates[0];
  if (!signer) {
    dlog('verifyDetached: no key matching issuer', issuerId, '| candidates=', keyIds || '(none)');
    return { valid: null, signerEmail: senderEmail, html };
  }

  try {
    const signedBytes = Uint8Array.from(atob(signedB64), (c) => c.charCodeAt(0));
    const message = await openpgp.createMessage({ binary: signedBytes });
    const result = await openpgp.verify({ message, signature, verificationKeys: [signer] });
    const sig = result.signatures[0];
    let valid: boolean | null = null;
    try { valid = sig ? await sig.verified : null; } catch (e) { dlog('verifyDetached: sig.verified threw:', e instanceof Error ? e.message : e); valid = false; }
    dlog('verifyDetached:', senderEmail, '| issuer=', issuerId, '| signedBytes=', signedBytes.length, '| valid=', valid);
    return { valid, signerEmail: senderEmail, html };
  } catch (e) {
    dlog('verifyDetached: verify error:', e instanceof Error ? e.message : e);
    return { valid: false, signerEmail: senderEmail, html };
  }
};

// Navigate the Carbonio SPA to the PGP section (this module's primary-bar route).
// Used by mails-ui when a Decrypt is attempted before the HSM is connected and the
// in-place unlock modal isn't available (the PGP view isn't mounted after a reload).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpOpenSettings = (): void => {
  // Primary-bar apps live at /<shellBase>/<route>; take the first path segment as base.
  const base = window.location.pathname.split('/').filter(Boolean)[0] ?? 'carbonio';
  const url = `/${base}/pgp`;
  if (window.location.pathname !== url) {
    window.history.pushState({}, '', url);
    // Nudge react-router (used by the shell) to react to the URL change without a reload.
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
};

export type PgpAttachment = {
  filename: string;
  contentType: string;
  base64: string; // raw base64 (no line wrapping)
};

// Inline image referenced from the HTML body via cid:<contentId>.
export type PgpInlineImage = PgpAttachment & { contentId: string };

export type PgpSendParams = {
  senderEmail: string;
  recipientEmails: string[];
  plainText: string;
  richText: string;
  attachments?: PgpAttachment[];   // encrypted inside the message (encrypt+sign path)
  inlineImages?: PgpInlineImage[]; // cid: images embedded in a multipart/related
  subject?: string;                // when set, embedded as an encrypted protected header
};

/**
 * Sign plain text with sender's HSM key (inline cleartext signature).
 * Returns the armored PGP SIGNED MESSAGE string.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpSignOnly = async (params: PgpSendParams, callSecret?: unknown): Promise<string> => {
  requireSecret(callSecret);
  const { hem, listToken } = _singleton.state;
  if (!hem || !listToken) throw new Error('HSM not connected');
  if (_singleton.userEmails.size > 0 && !_singleton.userEmails.has(params.senderEmail)) {
    throw new Error(`Unauthorized: senderEmail does not match logged-in user`);
  }

  const { signCleartextMessage } = await getPgp();

  const allKeys = await hem.searchKeys(listToken, 'ETSPGP:');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfSignKey = allKeys.find((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'sign' && d?.email === params.senderEmail; });
  if (!selfSignKey) throw new Error(`No PGP sign key found for ${params.senderEmail}`);

  const signToken = await authorizeScope(`keymgmt:use:${selfSignKey.kid}`);

  // keyId8 from the WKD-published cert — authoritative, so the signature's issuer keyID
  // matches the key recipients fetch from WKD (identical to the encrypt+sign path).
  // buildCertificate here produced a different keyId (different creation time baked into
  // the fingerprint), so the signature referenced a key nobody could find → "could not
  // find signing key" and it never verified.
  const senderKeyBytes = await wkdFetch(params.senderEmail);
  if (!senderKeyBytes) throw new Error(`No WKD key for sender ${params.senderEmail} — publish key first`);
  const senderPubKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const keyId8: Uint8Array = (senderPubKey.keyPacket.getKeyID() as any).write();

  return signCleartextMessage(hem, signToken, selfSignKey.kid, keyId8, params.plainText);
};

/**
 * Encrypt + sign message for all recipients + sender.
 * Returns the armored PGP MESSAGE string (RFC 3156 payload).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpEncryptAndSign = async (params: PgpSendParams, callSecret?: unknown): Promise<string> => {
  requireSecret(callSecret);
  const { hem, listToken } = _singleton.state;
  if (!hem || !listToken) throw new Error('HSM not connected');
  if (_singleton.userEmails.size > 0 && !_singleton.userEmails.has(params.senderEmail)) {
    throw new Error(`Unauthorized: senderEmail does not match logged-in user`);
  }

  const { buildHsmSignaturePkt } = await getPgp();

  const allKeys = await hem.searchKeys(listToken, 'ETSPGP:');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfSignKey = allKeys.find((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'sign' && d?.email === params.senderEmail; });
  if (!selfSignKey) throw new Error(`No PGP sign key found for ${params.senderEmail}`);

  const signToken = await authorizeScope(`keymgmt:use:${selfSignKey.kid}`);

  // keyId8 from WKD cert — authoritative, avoids buildCertificate (extra /sign calls)
  const senderKeyBytes = await wkdFetch(params.senderEmail);
  if (!senderKeyBytes) throw new Error(`No WKD key for sender ${params.senderEmail} — publish key first`);
  const senderPubKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const keyId8: Uint8Array = (senderPubKey.keyPacket.getKeyID() as any).write();

  // Inner MIME payload to encrypt. The whole thing (body + any attachments) is
  // encrypted as one opaque blob, so attachments never leave in clear and are
  // unaffected by the server re-serialising the outer multipart/encrypted.
  const randomBoundary = (): string => Array.from(crypto.getRandomValues(new Uint8Array(12)))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  const attachments = params.attachments ?? [];
  const inlineImages = params.inlineImages ?? [];
  const sanitizeName = (n: string): string => n.replace(/["\r\n]/g, '_');
  const wrap76 = (b64: string): string => (b64.replace(/\s/g, '').match(/.{1,76}/g) ?? []).join('\r\n');

  // Inline images are embedded as data: URIs directly in the HTML (each cid: reference
  // is replaced by the image bytes). This is the most portable option: it renders in
  // ProtonMail/Gmail/Thunderbird with no cid resolution, which some clients fail to do
  // for a multipart/related nested inside an encrypted blob. The whole HTML is inside
  // the encrypted payload, so the (long) data: lines reach the recipient byte-for-byte.
  let richHtml = params.richText;
  let inlineEmbedded = 0;
  for (const img of inlineImages) {
    const dataUri = `data:${img.contentType || 'application/octet-stream'};base64,${img.base64.replace(/\s/g, '')}`;
    const before = richHtml;
    richHtml = richHtml.split(`cid:${img.contentId}`).join(dataUri);
    if (richHtml !== before) inlineEmbedded += 1;
  }
  const htmlPart = ['Content-Type: text/html; charset=utf-8', '', richHtml].join('\r\n');

  const altBoundary = randomBoundary();
  const content = [
    `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
    '',
    `--${altBoundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    params.plainText,
    `--${altBoundary}`,
    htmlPart,
    `--${altBoundary}--`,
    '',
  ].join('\r\n');

  // Optionally attach the sender's own public key (application/pgp-keys) so the recipient
  // can verify the signature without hunting for the key — e.g. Thunderbird otherwise shows
  // "signed with a key you don't have yet". ON by default; off (with wildcard) leaks less.
  const extraParts: string[] = [];
  if (getPgpPrefs().attachOwnKey) {
    const armoredSelf = senderPubKey.armor();
    const selfName = `OpenPGP_${senderPubKey.getKeyID().toHex().toUpperCase()}.asc`;
    extraParts.push([
      `Content-Type: application/pgp-keys; name="${selfName}"`,
      `Content-Disposition: attachment; filename="${selfName}"`,
      'Content-Description: OpenPGP public key',
      '',
      armoredSelf,
    ].join('\r\n'));
  }

  // ...then wrapped in multipart/mixed when there are standard attachments or the pubkey.
  let innerMime = content;
  if (attachments.length > 0 || extraParts.length > 0) {
    const mixedBoundary = randomBoundary();
    const attachmentParts = attachments.map((a) => [
      `Content-Type: ${a.contentType || 'application/octet-stream'}; name="${sanitizeName(a.filename)}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${sanitizeName(a.filename)}"`,
      '',
      wrap76(a.base64),
    ].join('\r\n'));
    const allParts = [...attachmentParts, ...extraParts];
    innerMime = [
      `Content-Type: multipart/mixed; boundary="${mixedBoundary}"`,
      '',
      `--${mixedBoundary}`,
      content,
      ...allParts.map((p) => `--${mixedBoundary}\r\n${p}`),
      `--${mixedBoundary}--`,
      '',
    ].join('\r\n');
  }

  // Protected headers ("memory hole", protected-headers="v1"): when subject encryption is on,
  // embed the real Subject INSIDE the encrypted payload's root part so it never appears in
  // clear on the wire/server. The outer message carries only a placeholder subject (set by
  // mails-ui). The subject is inside the signed content too, so its integrity is protected.
  if (params.subject) {
    const enc2047 = (s: string): string => (/[^\x00-\x7F]/.test(s) ? `=?utf-8?B?${btoa(unescape(encodeURIComponent(s)))}?=` : s);
    const nl = innerMime.indexOf('\r\n');
    innerMime = `${innerMime.slice(0, nl)}; protected-headers="v1"\r\nSubject: ${enc2047(params.subject)}${innerMime.slice(nl)}`;
  }

  dlog('encrypt: attachments=', attachments.length, '| inlineImages=', inlineImages.length, '| inlineEmbedded(data-uri)=', inlineEmbedded,
    '| attachOwnKey=', extraParts.length > 0, '| protectedSubject=', !!params.subject, '| inner MIME bytes=', innerMime.length,
    '| structure=', (attachments.length || extraParts.length) ? 'multipart/mixed' : 'multipart/alternative');

  // Build HSM signature packet (pure HSM, no openpgp.js inside rollup bundle)
  const { sigPkt, dataBytes } = await buildHsmSignaturePkt(hem, signToken, selfSignKey.kid, keyId8, innerMime);

  // Resolve recipient public keys via WKD, then configured keyservers (RSA keys from a
  // keyserver work here — openpgp encrypts to them locally; only HEM import is Ed25519/X25519).
  const emailSet = [...new Set([...params.recipientEmails, params.senderEmail])];
  const encryptionKeys: openpgp.PublicKey[] = [];
  for (const email of emailSet) {
    // Defense in depth: never encrypt to a trusted peer whose published key no longer
    // matches the key pinned in the HSM (the composer already disables it, but don't
    // rely on the UI alone).
    if ((await recipientKeyStatus(email)) === 'mismatch') {
      throw new Error(`Key fingerprint mismatch for ${email} — the published key does not match your trusted key; not encrypting.`);
    }
    encryptionKeys.push(await resolveRecipientKey(email));
  }

  // Assemble signed message and encrypt — all openpgp calls use webpack instance
  const existingSig = await openpgp.readSignature({ binarySignature: sigPkt });
  const litMsg = await openpgp.createMessage({ binary: dataBytes, format: 'binary' });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const signedMsg = await (litMsg as any).sign([], [], existingSig);
  // `wildcard` (throw-keyids) is a user preference: on = hide recipient key IDs (lets BCC
  // stay hidden in one copy) but Thunderbird/RNP then can't decrypt (it won't trial-decrypt
  // anonymous recipients — GnuPG/ProtonMail do); off (default) = real key IDs, every client
  // decrypts. mails-ui gates BCC on the same preference.
  return openpgp.encrypt({
    message: signedMsg,
    encryptionKeys,
    wildcard: getPgpPrefs().wildcard,
    config: { preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed },
  });
};

export type PgpSignedEmlParams = {
  senderEmail: string;
  senderName?: string;
  to: Array<{ email: string; name?: string }>;
  cc?: Array<{ email: string; name?: string }>;
  subject: string;
  plainText: string;
  richText: string;
  attachments?: PgpAttachment[];   // signed (in clear) inside the multipart/signed body
  inlineImages?: PgpInlineImage[]; // embedded as data: URIs in the HTML
};

/**
 * Build a complete RFC 3156 multipart/signed message (raw RFC822), signed via the HSM.
 *
 * Returns the full .eml (headers + body). mails-ui uploads it to FileUploadServlet and
 * sends it with `SendMsg <m aid="…"/>`, which delivers the bytes verbatim (only the top
 * header block — Date, Message-ID-if-absent — is touched; the MIME body is byte-exact).
 * That is the ONLY Carbonio send path that preserves a detached signature — the ordinary
 * mp-tree SendMsg re-serialises the visible MIME and breaks the signature. See the
 * `carbonio-soap-send-model` note.
 *
 * The signed part uses base64 Content-Transfer-Encoding on the text parts so arbitrarily
 * long lines (e.g. data: inline images) survive transport and the signed bytes are stable.
 * The signature is a detached binary (type 0x00) signature — the same HSM primitive the
 * encrypt+sign path uses — over the exact canonical (CRLF) bytes of the signed entity.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpBuildSignedEml = async (params: PgpSignedEmlParams, callSecret?: unknown): Promise<string> => {
  requireSecret(callSecret);
  const { hem, listToken } = _singleton.state;
  if (!hem || !listToken) throw new Error('HSM not connected');
  if (_singleton.userEmails.size > 0 && !_singleton.userEmails.has(params.senderEmail)) {
    throw new Error(`Unauthorized: senderEmail does not match logged-in user`);
  }

  const { buildHsmSignaturePkt } = await getPgp();

  const allKeys = await hem.searchKeys(listToken, 'ETSPGP:');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfSignKey = allKeys.find((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'sign' && d?.email === params.senderEmail; });
  if (!selfSignKey) throw new Error(`No PGP sign key found for ${params.senderEmail}`);
  const signToken = await authorizeScope(`keymgmt:use:${selfSignKey.kid}`);

  // keyId8 from the WKD cert — authoritative, so the signature's issuer keyID matches the
  // key recipients fetch from WKD (same rationale as the sign-only / encrypt+sign paths).
  const senderKeyBytes = await wkdFetch(params.senderEmail);
  if (!senderKeyBytes) throw new Error(`No WKD key for sender ${params.senderEmail} — publish key first`);
  const senderPubKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const keyId8: Uint8Array = (senderPubKey.keyPacket.getKeyID() as any).write();

  const rb = (): string => Array.from(crypto.getRandomValues(new Uint8Array(12))).map((b) => b.toString(16).padStart(2, '0')).join('');
  const toCrlf = (s: string): string => s.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');
  const wrap76 = (b64: string): string => (b64.replace(/\s/g, '').match(/.{1,76}/g) ?? []).join('\r\n');
  const b64utf8 = (s: string): string => wrap76(btoa(unescape(encodeURIComponent(s))));
  const sanitizeName = (n: string): string => n.replace(/["\r\n]/g, '_');
  // RFC 2047 encoded-word for non-ASCII header values (subject / display names).
  const encHdr = (s: string): string => (/[^\x00-\x7F]/.test(s) ? `=?utf-8?B?${btoa(unescape(encodeURIComponent(s)))}?=` : s);
  const addr = (a: { email: string; name?: string }): string => (a.name ? `${encHdr(a.name)} <${a.email}>` : a.email);

  // Inline images → data: URIs in the HTML (portable; no multipart/related / cid resolution).
  let richHtml = params.richText;
  for (const img of params.inlineImages ?? []) {
    const dataUri = `data:${img.contentType || 'application/octet-stream'};base64,${img.base64.replace(/\s/g, '')}`;
    richHtml = richHtml.split(`cid:${img.contentId}`).join(dataUri);
  }

  const altB = rb();
  const alternative = [
    `Content-Type: multipart/alternative; boundary="${altB}"`,
    '',
    `--${altB}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64utf8(params.plainText),
    `--${altB}`,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64utf8(richHtml),
    `--${altB}--`,
  ].join('\r\n');

  // Optional real attachments (signed in clear) + own public key → wrap in multipart/mixed.
  const attachments = params.attachments ?? [];
  const extraParts: string[] = [];
  if (getPgpPrefs().attachOwnKey) {
    const selfName = `OpenPGP_${senderPubKey.getKeyID().toHex().toUpperCase()}.asc`;
    extraParts.push([
      `Content-Type: application/pgp-keys; name="${selfName}"`,
      `Content-Disposition: attachment; filename="${selfName}"`,
      'Content-Description: OpenPGP public key',
      '',
      senderPubKey.armor(),
    ].join('\r\n'));
  }

  let signedContent = alternative;
  if (attachments.length > 0 || extraParts.length > 0) {
    const mixedB = rb();
    const attachmentParts = attachments.map((a) => [
      `Content-Type: ${a.contentType || 'application/octet-stream'}; name="${sanitizeName(a.filename)}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${sanitizeName(a.filename)}"`,
      '',
      wrap76(a.base64),
    ].join('\r\n'));
    const allParts = [alternative, ...attachmentParts, ...extraParts];
    signedContent = [
      `Content-Type: multipart/mixed; boundary="${mixedB}"`,
      '',
      ...allParts.map((p) => `--${mixedB}\r\n${p}`),
      `--${mixedB}--`,
    ].join('\r\n');
  }
  // Canonicalise the whole signed entity to CRLF — this is the byte-exact input to the
  // signature AND what we place verbatim in the message (openpgp's armor() uses LF).
  signedContent = toCrlf(signedContent);

  const { sigPkt } = await buildHsmSignaturePkt(hem, signToken, selfSignKey.kid, keyId8, signedContent);
  const armoredSig = toCrlf((await openpgp.readSignature({ binarySignature: sigPkt })).armor());

  const sigB = rb();
  const body = [
    `--${sigB}`,
    signedContent,
    `--${sigB}`,
    'Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"',
    'Content-Description: OpenPGP digital signature',
    'Content-Disposition: attachment; filename="OpenPGP_signature.asc"',
    '',
    armoredSig,
    `--${sigB}--`,
    '',
  ].join('\r\n');

  const domain = params.senderEmail.split('@')[1] ?? 'localhost';
  const headers = [
    `From: ${params.senderName ? `${encHdr(params.senderName)} <${params.senderEmail}>` : params.senderEmail}`,
    `To: ${params.to.map(addr).join(', ')}`,
    ...((params.cc ?? []).length ? [`Cc: ${(params.cc ?? []).map(addr).join(', ')}`] : []),
    `Subject: ${encHdr(params.subject)}`,
    `Message-ID: <${rb()}${rb().slice(0, 8)}@${domain}>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/signed; micalg="pgp-sha256"; protocol="application/pgp-signature"; boundary="${sigB}"`,
  ].join('\r\n');

  dlog('buildSignedEml:', params.senderEmail, '| to=', params.to.length, 'cc=', (params.cc ?? []).length,
    '| attachments=', attachments.length, '| inlineImages=', (params.inlineImages ?? []).length,
    '| signedContent bytes=', signedContent.length);
  return `${headers}\r\n\r\n${body}`;
};

/**
 * Extract displayable HTML from a decrypted MIME plaintext.
 * Handles nested multipart, base64 and quoted-printable transfer encodings.
 * Prefers text/html; falls back to text/plain. Inline images (cid:) are embedded
 * as data: URIs and attachments are appended as download links.
 */
function extractHtmlFromMime(plaintext: string): string {
  interface MimePart {
    ct: string;          // content-type (lowercased, no params)
    cte: string;         // content-transfer-encoding
    body: string;        // raw (undecoded) body
    cid: string | null;  // Content-ID without <> (inline image reference)
    disposition: string; // 'inline' | 'attachment' | ''
    filename: string | null;
  }

  const MIME_MAX_DEPTH = 8;
  function parseParts(text: string, depth = 0): MimePart[] {
    if (depth >= MIME_MAX_DEPTH) return [];
    const headerEnd = text.search(/\r?\n\r?\n/);
    if (headerEnd === -1) return [];
    const headerBlock = text.slice(0, headerEnd);
    const body = text.slice(headerEnd).replace(/^\r?\n/, '');

    const ctMatch = headerBlock.match(/^content-type:\s*([^\s;]+)/im);
    const ct = ctMatch ? ctMatch[1].toLowerCase() : '';
    const cteMatch = headerBlock.match(/^content-transfer-encoding:\s*(\S+)/im);
    const cte = cteMatch ? cteMatch[1].toLowerCase() : '7bit';
    const cidMatch = headerBlock.match(/^content-id:\s*<?([^>\r\n]+)>?/im);
    const cid = cidMatch ? cidMatch[1].trim() : null;
    const cdMatch = headerBlock.match(/^content-disposition:\s*([^\s;]+)/im);
    const disposition = cdMatch ? cdMatch[1].toLowerCase() : '';
    const nameMatch = headerBlock.match(/(?:filename|name)="?([^";\r\n]+)"?/i);
    const filename = nameMatch ? nameMatch[1].trim() : null;

    if (ct.startsWith('multipart/')) {
      const boundaryMatch = headerBlock.match(/boundary="?([^";\r\n]+)"?/i);
      if (!boundaryMatch) return [];
      const boundary = boundaryMatch[1].trim();
      const parts: MimePart[] = [];
      const re = new RegExp(`--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:--)?`, 'g');
      const indices: number[] = [];
      let m: RegExpExecArray | null;
      while ((m = re.exec(body)) !== null) indices.push(m.index + m[0].length);
      for (let i = 0; i < indices.length - 1; i++) {
        const chunk = body.slice(indices[i]).replace(/^\r?\n/, '');
        const end = body.indexOf(`--${boundary}`, indices[i]);
        const partText = end !== -1 ? body.slice(indices[i], end).replace(/^\r?\n/, '') : chunk;
        parts.push(...parseParts(partText, depth + 1));
      }
      return parts;
    }
    return [{ ct, cte, body, cid, disposition, filename }];
  }

  function decodeText(part: MimePart): string {
    if (part.cte === 'base64') {
      try {
        const binary = atob(part.body.replace(/\s/g, ''));
        const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
        return new TextDecoder('utf-8').decode(bytes);
      } catch { return part.body; }
    }
    if (part.cte === 'quoted-printable') {
      const unfolded = part.body.replace(/=\r?\n/g, '');
      const bytes: number[] = [];
      let i = 0;
      while (i < unfolded.length) {
        if (unfolded[i] === '=' && i + 2 < unfolded.length) {
          bytes.push(parseInt(unfolded.slice(i + 1, i + 3), 16));
          i += 3;
        } else {
          bytes.push(unfolded.charCodeAt(i));
          i++;
        }
      }
      return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
    }
    return part.body;
  }

  /** Base64 payload of a part, suitable for a data: URI. */
  function base64Payload(part: MimePart): string {
    if (part.cte === 'base64') return part.body.replace(/\s/g, '');
    // Re-encode other transfer encodings to base64.
    const decoded = decodeText(part);
    try { return btoa(unescape(encodeURIComponent(decoded))); }
    catch { return btoa(decoded); }
  }

  function escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  const parts = parseParts(plaintext);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dlog('mime: parts=', parts.map(p => ({ ct: p.ct, cte: p.cte, cid: p.cid, disp: p.disposition, file: p.filename })) as any);

  // Inline images referenced by cid: → data: URI map.
  const cidMap = new Map<string, string>();
  for (const p of parts) {
    if (p.cid && p.ct.startsWith('image/')) {
      cidMap.set(p.cid, `data:${p.ct};base64,${base64Payload(p)}`);
    }
  }

  // Attachments: explicit attachments, or named non-body parts that aren't inline images.
  const attachments = parts.filter(p =>
    (p.disposition === 'attachment' || (p.filename && !p.cid)) &&
    p.ct !== 'text/html' && p.ct !== 'text/plain' && !p.ct.startsWith('multipart/')
  );

  const attachmentsHtml = attachments.length
    ? `<div style="margin-top:12px;padding-top:10px;border-top:1px solid #e2e8f0">
         <div style="font-size:12px;font-weight:600;color:#718096;margin-bottom:6px">📎 Attachments (${attachments.length})</div>
         ${attachments.map(a => {
           const name = a.filename || `attachment.${(a.ct.split('/')[1] || 'bin')}`;
           const href = `data:${a.ct};base64,${base64Payload(a)}`;
           return `<div><a href="${href}" download="${escapeHtml(name)}" style="color:#2b6cb0;font-size:13px;text-decoration:none">⬇ ${escapeHtml(name)}</a> <span style="color:#a0aec0;font-size:12px">(${a.ct})</span></div>`;
         }).join('')}
       </div>`
    : '';

  const htmlPart = parts.find(p => p.ct === 'text/html');
  if (htmlPart) {
    let html = decodeText(htmlPart);
    // Embed inline images: rewrite cid: references to data: URIs.
    for (const [cid, dataUri] of cidMap) {
      html = html.replace(new RegExp(`cid:${cid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g'), dataUri);
    }
    return html + attachmentsHtml;
  }
  const textPart = parts.find(p => p.ct === 'text/plain');
  if (textPart) {
    return `<pre style="white-space:pre-wrap">${escapeHtml(decodeText(textPart))}</pre>${attachmentsHtml}`;
  }
  // Fallback: show raw (still surface any attachments we found).
  return `<pre style="white-space:pre-wrap">${escapeHtml(plaintext)}</pre>${attachmentsHtml}`;
}

// ── Decrypt window global ─────────────────────────────────────────────────────

type PgpDecryptParams = {
  armored: string;          // armored PGP MESSAGE (encrypt) or PGP SIGNED MESSAGE (sign)
  mode: 'encrypt' | 'sign';
  senderEmail?: string;     // for sig verification
  recipientEmail?: string;  // our address the mail was sent to — direct key lookup, no WKD scan
};

type PgpDecryptResult = {
  html: string;
  signerEmail: string | null;
  sigValid: boolean | null;
};

// Render a verified/plain signed message body as readable HTML: keep line breaks but use
// the surrounding message font (not the raw monospace <pre>), which reads like an email.
function signedBodyHtml(text: string): string {
  const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<div style="white-space:pre-wrap;word-break:break-word;font-family:inherit;font-size:14px;line-height:1.55">${escaped}</div>`;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpDecrypt = async (params: PgpDecryptParams, callSecret?: unknown): Promise<PgpDecryptResult> => {
  requireSecret(callSecret);
  const { hem, listToken } = _singleton.state;
  dlog('decrypt: mode=', params.mode, '| sender=', params.senderEmail, '| recipient=', params.recipientEmail,
    '| armored bytes=', params.armored?.length, '| hsm connected=', !!hem);

  if (params.mode === 'sign') {
    // Inline cleartext — verify only, no HSM needed
    if (!params.senderEmail) { dlog('sign: no senderEmail → cannot verify'); return { html: `<pre>${params.armored}</pre>`, signerEmail: null, sigValid: null }; }

    const senderKeyBytes = await wkdFetch(params.senderEmail);
    dlog('sign: wkdFetch(', params.senderEmail, ') →', senderKeyBytes ? `${senderKeyBytes.length} bytes` : 'null (not found / blocked)');
    if (!senderKeyBytes) return { html: `<pre>${params.armored}</pre>`, signerEmail: params.senderEmail, sigValid: null };

    const cleartextMsg = await openpgp.readCleartextMessage({ cleartextMessage: params.armored });
    // Only trust the signature if the sender's WKD key actually claims that address.
    let senderPubKey: openpgp.PublicKey | null = null;
    try { senderPubKey = await readValidatedWkdKey(senderKeyBytes, params.senderEmail, { requireEncryptionKey: false }); dlog('sign: sender key validated, keyID=', senderPubKey.getKeyID().toHex()); }
    catch (e) { senderPubKey = null; dlog('sign: sender key REJECTED by validation:', e instanceof Error ? e.message : e); }
    if (!senderPubKey) {
      return { html: signedBodyHtml(cleartextMsg.getText()), signerEmail: params.senderEmail, sigValid: null };
    }
    const result = await openpgp.verify({ message: cleartextMsg, verificationKeys: [senderPubKey] });
    const sig = result.signatures[0];
    let sigValid: boolean | null = null;
    try { sigValid = sig ? await sig.verified : null; dlog('sign: signature verified =', sigValid); }
    catch (e) { sigValid = false; dlog('sign: signature verify FAILED:', e instanceof Error ? e.message : e, '| sig keyID=', (sig?.keyID as any)?.toHex?.()); }
    const text = result.data as string;
    return { html: signedBodyHtml(text), signerEmail: params.senderEmail, sigValid };
  }

  // Encrypted message — HSM needed
  if (!hem || !listToken) throw new Error('HSM not connected — unlock HSM to decrypt');

  const allKeys = await hem.searchKeys(listToken, 'ETSPGP:');
  // Find ALL own ECDH keys (user may have keys for multiple email addresses)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfEcdhKeys = allKeys.filter((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'ecdh'; });
  dlog('encrypt: HSM keys total=', allKeys.length, '| self ECDH keys=', selfEcdhKeys.length,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    '→', selfEcdhKeys.map((k: any) => decodeDescr(k)?.email));
  if (!selfEcdhKeys.length) throw new Error('No ECDH key found in HSM');

  // Build email → candidate map from DESCR (no WKD needed — fingerprints resolved lazily via cache)
  interface EcdhCandidate { kid: string; email: string; token: string }
  const ecdhByEmail = new Map<string, EcdhCandidate>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const ecdhKey of selfEcdhKeys as any[]) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const myEmail = decodeDescr(ecdhKey as any)?.email;
    if (!myEmail) continue;
    const token = await authorizeScope(`keymgmt:use:${ecdhKey.kid}`);
    ecdhByEmail.set(myEmail, { kid: ecdhKey.kid, email: myEmail, token });
  }
  if (!ecdhByEmail.size) throw new Error('No self ECDH key found in HSM');

  /** Returns ECDH subkey fingerprint for the given email — fetches WKD once then caches. */
  async function getEcdhFingerprint(email: string): Promise<Uint8Array | null> {
    const cached = _singleton.ecdhFingerprintCache.get(email);
    if (cached) return cached;
    const keyBytes = await wkdFetch(email);
    if (!keyBytes) return null;
    const subkeys = (await openpgp.readKey({ binaryKey: keyBytes })).getSubkeys();
    if (!subkeys.length) return null;
    const fpHex = subkeys[0].getFingerprint();
    const fp = Uint8Array.from(fpHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));
    _singleton.ecdhFingerprintCache.set(email, fp);
    return fp;
  }

  // Parse message using webpack openpgp
  const message = await openpgp.readMessage({ armoredMessage: params.armored });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pkeskPackets = (message.packets as any).filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
  dlog('encrypt: PKESK packets=', pkeskPackets.length,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    '| recipient keyIDs=', pkeskPackets.map((p: any) => p.publicKeyID?.toHex?.()));
  if (!pkeskPackets.length) throw new Error('No PKESK packet found');

  // Prefer a direct hit on recipientEmail (O(1)), but fall back to ALL self ECDH keys
  // when it doesn't match one of ours. This is what lets us open a message in Sent:
  // there recipientEmail is the *recipient's* address (not ours), yet the copy is also
  // encrypted to the sender's own key (senderEmail is in emailSet), so trying all self
  // keys finds it.
  // Prefer the recipient's key (received mail) and the sender's key (our own — Sent mail);
  // only fall back to every self key if neither matches, to avoid a WKD-fingerprint fetch
  // storm when the account holds many keys.
  const byRecipient = params.recipientEmail ? ecdhByEmail.get(params.recipientEmail) : undefined;
  const bySender = params.senderEmail ? ecdhByEmail.get(params.senderEmail) : undefined;
  const preferred = [byRecipient, bySender].filter((c): c is EcdhCandidate => !!c)
    .filter((c, i, arr) => arr.findIndex(x => x.kid === c.kid) === i);
  const candidatesToTry: EcdhCandidate[] = preferred.length ? preferred : [...ecdhByEmail.values()];
  dlog('decrypt: candidates=', candidatesToTry.map(c => c.email), '| fallback-to-all=', preferred.length === 0);

  let sessionKey: openpgp.SessionKey | null = null;
  let lastErr: unknown = null;
  for (const pkesk of pkeskPackets) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const pkeskAny = pkesk as any;
    const encKeys = Object.keys(pkeskAny.encrypted ?? {});
    let ephemeral: Uint8Array;
    let wrapped: Uint8Array;
    let algoId: number;
    // Legacy ECDH (algo 18): { V: MPI with 0x40 prefix, C: ECDHSymmetricKey with .data }
    // New X25519 (algo 25):  { ephemeralPublicKey: 32 bytes, C: ECDHXSymmetricKey with .wrappedKey }
    if (encKeys.includes('V')) {
      ephemeral = pkeskAny.encrypted.V;
      wrapped = pkeskAny.encrypted.C.data;
      algoId = pkeskAny.sessionKeyAlgorithm ?? openpgp.enums.symmetric.aes256;
    } else if (encKeys.includes('ephemeralPublicKey')) {
      ephemeral = pkeskAny.encrypted.ephemeralPublicKey;
      wrapped = pkeskAny.encrypted.C.wrappedKey;
      algoId = pkeskAny.sessionKeyAlgorithm ?? openpgp.enums.symmetric.aes256;
    } else {
      lastErr = new Error(`Unknown PKESK encrypted structure: keys=${encKeys.join(',')}`);
      continue;
    }
    for (const candidate of candidatesToTry) {
      const fingerprint = await getEcdhFingerprint(candidate.email);
      if (!fingerprint) { dlog('encrypt: no WKD fingerprint for', candidate.email, '→ skip'); continue; }
      try {
        sessionKey = await localDecryptPkesk(ephemeral, wrapped, fingerprint, algoId, hem, candidate.token, candidate.kid);
        dlog('encrypt: session key obtained via ECDH with', candidate.email, '| algoId=', algoId);
        break;
      } catch (e) {
        lastErr = e;
        dlog('encrypt: ECDH decrypt with', candidate.email, 'failed:', e instanceof Error ? e.message : e);
      }
    }
    if (sessionKey) break;
  }
  if (!sessionKey) throw new Error(`Decryption failed: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);

  // Decrypt + verify in one call if sender key is available
  let signerEmail: string | null = params.senderEmail ?? null;
  let sigValid: boolean | null = null;
  let plaintext: string;

  if (signerEmail) {
    // Gather the sender's key from BOTH WKD and the keyservers (by email): a sender may sign
    // with a key published to keys.openpgp.org that differs from their WKD key (e.g. a
    // Thunderbird key vs the HSM/WKD key for the same address). Each candidate is validated to
    // claim this address before we'd trust a "signature valid" badge.
    const verificationKeys: openpgp.PublicKey[] = [];
    const seenFp = new Set<string>();
    const addValidated = async (bytes: Uint8Array | null | undefined, src: string): Promise<void> => {
      if (!bytes) return;
      try {
        const vk = await readValidatedWkdKey(bytes, signerEmail, { requireEncryptionKey: false });
        const fp = vk.getFingerprint();
        if (seenFp.has(fp)) return;
        seenFp.add(fp);
        verificationKeys.push(vk);
        dlog('verify: sender key validated (', src, ') | primary keyID=', vk.getKeyID().toHex(),
          '| subkey IDs=', vk.getSubkeys().map((s) => s.getKeyID().toHex()));
      } catch (e) {
        dlog('verify: sender', src, 'key failed validation:', e instanceof Error ? e.message : e);
      }
    };
    const senderKeyBytes = await wkdFetch(signerEmail);
    dlog('verify: wkdFetch(', signerEmail, ') →', senderKeyBytes ? `${senderKeyBytes.length} bytes` : 'null (not found / CSP-blocked)');
    await addValidated(senderKeyBytes, 'WKD');
    const armoredKs = await keyserverFetch(signerEmail);
    if (armoredKs) {
      try { await addValidated((await openpgp.readKey({ armoredKey: armoredKs })).write(), 'keyserver'); }
      catch (e) { dlog('verify: keyserver key parse failed:', e instanceof Error ? e.message : e); }
    }
    if (!verificationKeys.length) {
      // eslint-disable-next-line no-console
      console.warn('[pgp] verify: no sender key for', signerEmail, '(WKD or keyserver) — signature shown as unverified, not invalid');
    }
    const decrypted = await openpgp.decrypt({ message, sessionKeys: [sessionKey], verificationKeys });
    plaintext = decrypted.data as string;
    dlog('verify: decrypted OK | plaintext bytes=', plaintext.length, '| signatures in message=', decrypted.signatures.length, '| verificationKeys=', verificationKeys.length);
    const sig = decrypted.signatures[0];
    if (!sig) {
      sigValid = null;
      // eslint-disable-next-line no-console
      console.warn('[pgp] verify: no signature packet in decrypted message');
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const issuer: string = (sig.keyID as any)?.toHex?.() ?? '';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const haveIssuer = verificationKeys.some((k) => k.getKeys().some((s: any) => s.getKeyID().toHex() === issuer));
      try {
        await sig.verified;
        sigValid = true;
        dlog('verify: SIGNATURE VALID ✓ | keyID=', issuer);
      } catch (e) {
        // The message may be signed by a key that differs from the sender's WKD key (e.g. a
        // Thunderbird key vs the HSM key for the same address). Fetch the exact signing key by
        // its issuer keyID from the keyservers (validated to claim the sender address) and
        // re-verify against it. "No key for the issuer anywhere" is unverified (null), not
        // invalid (false) — only a genuine mismatch against the issuer's own key is invalid.
        if (issuer && !haveIssuer) {
          const armored = await keyserverFetchByKeyId(issuer);
          let byIdKey: openpgp.PublicKey | null = null;
          if (armored) {
            try {
              const kb = (await openpgp.readKey({ armoredKey: armored })).write();
              byIdKey = await readValidatedWkdKey(kb, signerEmail, { requireEncryptionKey: false });
            } catch (ve) {
              dlog('verify: keyserver key for issuer', issuer, 'rejected:', ve instanceof Error ? ve.message : ve);
            }
          }
          if (!byIdKey) {
            sigValid = null;
            // eslint-disable-next-line no-console
            console.warn('[pgp] verify: no key claiming', signerEmail, 'for issuer keyID', issuer, '— unverified (not invalid)');
          } else {
            try {
              const d2 = await openpgp.decrypt({ message, sessionKeys: [sessionKey], verificationKeys: [...verificationKeys, byIdKey] });
              plaintext = d2.data as string;
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              const sig2 = d2.signatures.find((s) => ((s.keyID as any)?.toHex?.() ?? '') === issuer) ?? d2.signatures[0];
              await sig2.verified;
              sigValid = true;
              dlog('verify: SIGNATURE VALID ✓ via keyserver | keyID=', issuer);
            } catch (e2) {
              sigValid = false;
              // eslint-disable-next-line no-console
              console.warn('[pgp] verify FAILED (issuer key from keyserver):', e2 instanceof Error ? e2.message : e2, '| keyID:', issuer);
            }
          }
        } else if (!verificationKeys.length) {
          // No sender key at all → cannot verify; unverified, not invalid.
          sigValid = null;
          // eslint-disable-next-line no-console
          console.warn('[pgp] verify: no sender key available for issuer keyID', issuer, '— unverified');
        } else {
          // We DO have the issuer's key and it still failed → a genuine bad signature.
          sigValid = false;
          // eslint-disable-next-line no-console
          console.warn('[pgp] verify FAILED:', e instanceof Error ? e.message : e,
            '| signature keyID:', issuer,
            '| fetched sender key IDs:', verificationKeys.map((k) => k.getKeyID().toHex()),
            '| sender subkey IDs:', verificationKeys.flatMap((k) => k.getSubkeys().map((s) => s.getKeyID().toHex())));
        }
      }
    }
  } else {
    const decrypted = await openpgp.decrypt({ message, sessionKeys: [sessionKey] });
    plaintext = decrypted.data as string;
  }

  const html = extractHtmlFromMime(plaintext);
  return { html, signerEmail, sigValid };
};

// Defined at module level so the reference is stable — HsmProvider never unmounts.
function PgpView() {
  return <HsmProvider><PgpSettingsView /></HsmProvider>;
}

export default function App() {
  // Register main nav route
  addRoute({
    id: APP_ID,
    app: APP_ID,
    route: 'pgp',
    position: 200,
    visible: true,
    label: 'PGP',
    primaryBar: 'LockOutline',
    appView: PgpView,
    badge: { show: false },
  });

  // Register stub functions for mails-ui integration (Phase 2 & 3)
  registerFunctions({
    'pgp:encrypt': {
      id: `${APP_ID}:pgp:encrypt`,
      fn: () => { throw new Error('PGP encrypt: HSM not yet connected'); },
    },
    'pgp:sign-encrypt': {
      id: `${APP_ID}:pgp:sign-encrypt`,
      fn: () => { throw new Error('PGP sign+encrypt: HSM not yet connected'); },
    },
    'pgp:decrypt': {
      id: `${APP_ID}:pgp:decrypt`,
      fn: () => { throw new Error('PGP decrypt: HSM not yet connected'); },
    },
  });

  return null;
}
