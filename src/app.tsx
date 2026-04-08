import * as openpgp from 'openpgp';
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
  try {
    // Strip 0x40 native prefix if present
    const ephemeral32 = (ephemeralWithPrefix.length === 33 && ephemeralWithPrefix[0] === 0x40)
      ? ephemeralWithPrefix.slice(1)
      : ephemeralWithPrefix;
    console.error('[pgp-decrypt] step1 ephemeral32.length:', ephemeral32.length, 'fingerprint.length:', fingerprint.length);
    const ephemeralB64 = btoa(String.fromCharCode(...Array.from(ephemeral32)));
    console.error('[pgp-decrypt] step2 ephemeralB64.length:', ephemeralB64.length);
    const sharedSecret: Uint8Array = await hem.ecdh(token, kid_ecdh, ephemeralB64);
    console.error('[pgp-decrypt] step3 sharedSecret.length:', sharedSecret?.length, sharedSecret?.constructor?.name);
    const sharedSecretCopy = new Uint8Array(sharedSecret); // ensure own buffer
    const kwk = await rfc6637kdfLocal(sharedSecretCopy, fingerprint);
    console.error('[pgp-decrypt] step4 kwk.length:', kwk.length);
    const unwrapped = await aesKwUnwrapLocal(kwk, wrappedKey);
    console.error('[pgp-decrypt] step5 unwrapped.length:', unwrapped.length);
    const sessionKeyData = stripSessionKeyEncoding(unwrapped);
    console.error('[pgp-decrypt] step6 sessionKeyData.length:', sessionKeyData.length);
    const algoName = openpgp.enums.read(openpgp.enums.symmetric, algoId) as openpgp.SessionKey['algorithm'];
    console.error('[pgp-decrypt] step7 algoName:', algoName);
    return { data: sessionKeyData, algorithm: algoName };
  } catch (e) {
    console.error('[pgp-decrypt] localDecryptPkesk internal error at step above:', e instanceof Error ? e.message : String(e), e);
    throw e;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function authorizeScope(scope: string): Promise<string> {
  const { hem } = _singleton.state;
  if (!hem) throw new Error('HSM not connected');
  const pw = _singleton.password;
  if (!pw) throw new Error('Password not available — unlock HSM first');
  const cached = _singleton.tokenCache.get(scope);
  if (cached && Date.now() < cached.expiresAt) return cached.token;
  const TOKEN_TTL = 8 * 3600;
  const token = await hem.authorizePassword(pw, scope, TOKEN_TTL);
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
(window as any).__encedoPgpSignOnly = async (params: PgpSendParams): Promise<string> => {
  const { hem, listToken } = _singleton.state;
  if (!hem || !listToken) throw new Error('HSM not connected');

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
(window as any).__encedoPgpEncryptAndSign = async (params: PgpSendParams): Promise<string> => {
  const { hem, listToken } = _singleton.state;
  if (!hem || !listToken) throw new Error('HSM not connected');

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

  function parseParts(text: string): MimePart[] {
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
        parts.push(...parseParts(partText));
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
};

type PgpDecryptResult = {
  html: string;
  signerEmail: string | null;
  sigValid: boolean | null;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__encedoPgpDecrypt = async (params: PgpDecryptParams): Promise<PgpDecryptResult> => {
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
  // Find own ECDH key
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const selfEcdhKey = allKeys.find((k: any) => { const d = decodeDescr(k); return d?.role === 'self' && d?.keyType === 'ecdh'; });
  if (!selfEcdhKey) throw new Error('No ECDH key found in HSM');

  const ecdhToken = await authorizeScope(`keymgmt:use:${selfEcdhKey.kid}`);

  // Find email from decodeDescr
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ecdhDescr = decodeDescr(selfEcdhKey as any);
  const myEmail = ecdhDescr?.email;
  if (!myEmail) throw new Error('Cannot determine email from ECDH key descriptor');

  const myKeyBytes = await wkdFetch(myEmail);
  if (!myKeyBytes) throw new Error(`No WKD key for ${myEmail} — cannot get fingerprint for decryption`);
  const myPubKey = await openpgp.readKey({ binaryKey: myKeyBytes });
  const ecdhSubkeys = myPubKey.getSubkeys();
  if (!ecdhSubkeys.length) throw new Error('No ECDH subkey in WKD cert');
  const ecdhSubkey = ecdhSubkeys[0];
  const ecdhFingerprint = Uint8Array.from(
    ecdhSubkey.getFingerprint().match(/.{2}/g)!.map((b: string) => parseInt(b, 16))
  );

  // Parse message using webpack openpgp
  const message = await openpgp.readMessage({ armoredMessage: params.armored });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pkeskPackets = (message.packets as any).filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
  if (!pkeskPackets.length) throw new Error('No PKESK packet found');

  let sessionKey: openpgp.SessionKey | null = null;
  let lastErr: unknown = null;
  for (const pkesk of pkeskPackets) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const pkeskAny = pkesk as any;
      const pkAlgo: number = pkeskAny.publicKeyAlgorithm;
      const encKeys = Object.keys(pkeskAny.encrypted ?? {});
      console.error('[pgp-decrypt] pkesk algo:', pkAlgo, 'encrypted keys:', encKeys,
        'sessionKeyAlgorithm:', pkeskAny.sessionKeyAlgorithm,
        'V?.length:', pkeskAny.encrypted?.V?.length,
        'ephPub?.length:', pkeskAny.encrypted?.ephemeralPublicKey?.length,
        'C?.data?.length:', pkeskAny.encrypted?.C?.data?.length,
        'C?.wrappedKey?.length:', pkeskAny.encrypted?.C?.wrappedKey?.length,
      );
      // Legacy ECDH (algo 18): { V: MPI with 0x40 prefix, C: ECDHSymmetricKey with .data }
      // New X25519 (algo 25):  { ephemeralPublicKey: 32 bytes, C: ECDHXSymmetricKey with .wrappedKey }
      let ephemeral: Uint8Array;
      let wrapped: Uint8Array;
      let algoId: number;
      if (encKeys.includes('V')) {
        // Legacy ECDH format
        ephemeral = pkeskAny.encrypted.V;
        wrapped = pkeskAny.encrypted.C.data;
        algoId = pkeskAny.sessionKeyAlgorithm ?? openpgp.enums.symmetric.aes256;
      } else if (encKeys.includes('ephemeralPublicKey')) {
        // New X25519 format — ephemeralPublicKey is already 32 bytes (no 0x40 prefix)
        ephemeral = pkeskAny.encrypted.ephemeralPublicKey;
        wrapped = pkeskAny.encrypted.C.wrappedKey;
        algoId = pkeskAny.sessionKeyAlgorithm ?? openpgp.enums.symmetric.aes256;
      } else {
        throw new Error(`Unknown PKESK encrypted structure: keys=${encKeys.join(',')}`);
      }
      console.error('[pgp-decrypt] ephemeral.length:', ephemeral?.length, 'wrapped.length:', wrapped?.length, 'algoId:', algoId);
      const raw = await localDecryptPkesk(ephemeral, wrapped, ecdhFingerprint, algoId, hem, ecdhToken, selfEcdhKey.kid);
      console.error('[pgp-decrypt] sessionKey obtained, algoName:', raw.algorithm, 'dataLen:', raw.data?.length);
      sessionKey = raw;
      break;
    } catch (e) {
      lastErr = e;
      console.error('[pgp-decrypt] PKESK failed:', e instanceof Error ? e.message : String(e), e);
    }
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
