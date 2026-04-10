import * as openpgp from 'openpgp';
// @ts-expect-error — carbonio-shell-ui types incomplete but hooks exist at runtime
import { addRoute, registerFunctions } from '@zextras/carbonio-shell-ui';
import { HsmProvider, _singleton, decodeDescr } from './store/HsmContext';
import { patchWebCrypto } from './lib/webcrypto-patch';
import { wkdFetch } from './lib/wkd-fetch';
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

/** Fetch WKD key and return parsed openpgp.PublicKey (uses webpack openpgp). */
async function wkdReadKey(email: string) {
  const keyBytes = await wkdFetch(email);
  if (!keyBytes) throw new Error(`No WKD key found for ${email}`);
  return openpgp.readKey({ binaryKey: keyBytes });
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpGetHsm = () => _singleton.state;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpCheckWkd = (email: string) => wkdFetch(email).then(r => r !== null);

export type PgpSendParams = {
  senderEmail: string;
  recipientEmails: string[];
  plainText: string;
  richText: string;
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

  const { signCleartextMessage, buildCertificate } = await getPgp();

  const allKeys = await hem.searchKeys(listToken, 'ETSPGP:');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfSignKey = allKeys.find((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'sign' && d?.email === params.senderEmail; });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfEcdhKey = allKeys.find((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'ecdh' && d?.email === params.senderEmail; });
  if (!selfSignKey || !selfEcdhKey) throw new Error(`No PGP keys found for ${params.senderEmail}`);

  const signToken = await authorizeScope(`keymgmt:use:${selfSignKey.kid}`);
  const ecdhToken = await authorizeScope(`keymgmt:use:${selfEcdhKey.kid}`);
  const { keyId } = await buildCertificate(hem, signToken, selfSignKey.kid, selfEcdhKey.kid, params.senderEmail, { ecdhToken });

  return signCleartextMessage(hem, signToken, selfSignKey.kid, keyId, params.plainText);
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

  // Inner MIME payload to encrypt
  const boundary = Array.from(crypto.getRandomValues(new Uint8Array(12)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const innerMime = [
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    params.plainText,
    `--${boundary}`,
    'Content-Type: text/html; charset=utf-8',
    '',
    params.richText,
    `--${boundary}--`,
    '',
  ].join('\r\n');


  // Build HSM signature packet (pure HSM, no openpgp.js inside rollup bundle)
  const { sigPkt, dataBytes } = await buildHsmSignaturePkt(hem, signToken, selfSignKey.kid, keyId8, innerMime);

  // Resolve recipient public keys via wkdFetch (webpack context, works fine)
  const emailSet = [...new Set([...params.recipientEmails, params.senderEmail])];
  const encryptionKeys: openpgp.PublicKey[] = [];
  for (const email of emailSet) {
    encryptionKeys.push(await wkdReadKey(email));
  }

  // Assemble signed message and encrypt — all openpgp calls use webpack instance
  const existingSig = await openpgp.readSignature({ binarySignature: sigPkt });
  const litMsg = await openpgp.createMessage({ binary: dataBytes, format: 'binary' });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const signedMsg = await (litMsg as any).sign([], [], existingSig);
  return openpgp.encrypt({
    message: signedMsg,
    encryptionKeys,
    config: { preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed },
  });
};

/**
 * Extract displayable HTML from a decrypted MIME plaintext.
 * Handles nested multipart, base64 and quoted-printable transfer encodings.
 * Prefers text/html; falls back to text/plain.
 */
function extractHtmlFromMime(plaintext: string): string {
  // Split into MIME parts — walk recursively, collect text/html and text/plain leaves
  interface MimePart { ct: string; cte: string; body: string }

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
    return [{ ct, cte, body }];
  }

  function decodeBody(part: MimePart): string {
    if (part.cte === 'base64') {
      try { return atob(part.body.replace(/\s/g, '')); } catch { return part.body; }
    }
    if (part.cte === 'quoted-printable') {
      return part.body
        .replace(/=\r?\n/g, '')
        .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    }
    return part.body;
  }

  const parts = parseParts(plaintext);
  const htmlPart = parts.find(p => p.ct === 'text/html');
  if (htmlPart) return decodeBody(htmlPart);
  const textPart = parts.find(p => p.ct === 'text/plain');
  if (textPart) return `<pre style="white-space:pre-wrap">${decodeBody(textPart).replace(/</g, '&lt;')}</pre>`;
  // Fallback: show raw
  return `<pre style="white-space:pre-wrap">${plaintext.replace(/</g, '&lt;')}</pre>`;
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpDecrypt = async (params: PgpDecryptParams, callSecret?: unknown): Promise<PgpDecryptResult> => {
  requireSecret(callSecret);
  const { hem, listToken } = _singleton.state;

  if (params.mode === 'sign') {
    // Inline cleartext — verify only, no HSM needed
    if (!params.senderEmail) return { html: `<pre>${params.armored}</pre>`, signerEmail: null, sigValid: null };

    const senderKeyBytes = await wkdFetch(params.senderEmail);
    if (!senderKeyBytes) return { html: `<pre>${params.armored}</pre>`, signerEmail: params.senderEmail, sigValid: null };

    const senderPubKey = await openpgp.readKey({ binaryKey: senderKeyBytes });
    const cleartextMsg = await openpgp.readCleartextMessage({ cleartextMessage: params.armored });
    const result = await openpgp.verify({ message: cleartextMsg, verificationKeys: [senderPubKey] });
    const sig = result.signatures[0];
    let sigValid: boolean | null = null;
    try { sigValid = sig ? await sig.verified : null; } catch { sigValid = false; }
    const text = result.data as string;
    return { html: `<pre style="white-space:pre-wrap">${text.replace(/</g, '&lt;')}</pre>`, signerEmail: params.senderEmail, sigValid };
  }

  // Encrypted message — HSM needed
  if (!hem || !listToken) throw new Error('HSM not connected — unlock HSM to decrypt');

  const allKeys = await hem.searchKeys(listToken, 'ETSPGP:');
  // Find ALL own ECDH keys (user may have keys for multiple email addresses)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfEcdhKeys = allKeys.filter((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'ecdh'; });
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
  if (!pkeskPackets.length) throw new Error('No PKESK packet found');

  // If recipientEmail known: direct lookup (O(1), single cache hit).
  // Otherwise: try all self ECDH keys (each fingerprint fetched once then cached).
  const candidatesToTry: EcdhCandidate[] = params.recipientEmail
    ? [ecdhByEmail.get(params.recipientEmail)].filter((c): c is EcdhCandidate => !!c)
    : [...ecdhByEmail.values()];

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
      if (!fingerprint) continue;
      try {
        sessionKey = await localDecryptPkesk(ephemeral, wrapped, fingerprint, algoId, hem, candidate.token, candidate.kid);
        break;
      } catch (e) {
        lastErr = e;
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
    const senderKeyBytes = await wkdFetch(signerEmail);
    const verificationKeys = senderKeyBytes ? [await openpgp.readKey({ binaryKey: senderKeyBytes })] : [];
    const decrypted = await openpgp.decrypt({ message, sessionKeys: [sessionKey], verificationKeys });
    plaintext = decrypted.data as string;
    if (verificationKeys.length) {
      const sig = decrypted.signatures[0];
      try { sigValid = sig ? await sig.verified : null; } catch { sigValid = false; }
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
