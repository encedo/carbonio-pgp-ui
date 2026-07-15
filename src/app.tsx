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

/** Fetch and validate a recipient's WKD key. */
async function wkdReadKey(email: string): Promise<openpgp.PublicKey> {
  const keyBytes = await wkdFetch(email);
  if (!keyBytes) throw new Error(`No WKD key found for ${email}`);
  return readValidatedWkdKey(keyBytes, email);
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

  // Inner MIME payload to encrypt. The whole thing (body + any attachments) is
  // encrypted as one opaque blob, so attachments never leave in clear and are
  // unaffected by the server re-serialising the outer multipart/encrypted.
  const randomBoundary = (): string => Array.from(crypto.getRandomValues(new Uint8Array(12)))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  const altBoundary = randomBoundary();
  const altPart = [
    `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
    '',
    `--${altBoundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    params.plainText,
    `--${altBoundary}`,
    'Content-Type: text/html; charset=utf-8',
    '',
    params.richText,
    `--${altBoundary}--`,
    '',
  ].join('\r\n');

  const attachments = params.attachments ?? [];
  const inlineImages = params.inlineImages ?? [];
  const sanitizeName = (n: string): string => n.replace(/["\r\n]/g, '_');
  const wrap76 = (b64: string): string => (b64.replace(/\s/g, '').match(/.{1,76}/g) ?? []).join('\r\n');

  // Body wrapped in multipart/related when there are inline images, so the HTML's
  // cid: references resolve to the embedded image parts.
  let content = altPart;
  if (inlineImages.length > 0) {
    const relBoundary = randomBoundary();
    const inlineParts = inlineImages.map((img) => [
      `--${relBoundary}`,
      `Content-Type: ${img.contentType || 'application/octet-stream'}; name="${sanitizeName(img.filename)}"`,
      'Content-Transfer-Encoding: base64',
      `Content-ID: <${img.contentId}>`,
      `Content-Disposition: inline; filename="${sanitizeName(img.filename)}"`,
      '',
      wrap76(img.base64),
    ].join('\r\n'));
    content = [
      `Content-Type: multipart/related; type="text/html"; boundary="${relBoundary}"`,
      '',
      `--${relBoundary}`,
      altPart,
      ...inlineParts,
      `--${relBoundary}--`,
      '',
    ].join('\r\n');
  }

  // ...then wrapped in multipart/mixed when there are standard attachments.
  let innerMime = content;
  if (attachments.length > 0) {
    const mixedBoundary = randomBoundary();
    const attachmentParts = attachments.map((a) => [
      `--${mixedBoundary}`,
      `Content-Type: ${a.contentType || 'application/octet-stream'}; name="${sanitizeName(a.filename)}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${sanitizeName(a.filename)}"`,
      '',
      wrap76(a.base64),
    ].join('\r\n'));
    innerMime = [
      `Content-Type: multipart/mixed; boundary="${mixedBoundary}"`,
      '',
      `--${mixedBoundary}`,
      content,
      ...attachmentParts,
      `--${mixedBoundary}--`,
      '',
    ].join('\r\n');
  }

  dlog('encrypt: attachments=', attachments.length, '| inlineImages=', inlineImages.length, '| inner MIME bytes=', innerMime.length,
    '| structure=', attachments.length ? 'multipart/mixed' : inlineImages.length ? 'multipart/related' : 'multipart/alternative');

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
      return { html: `<pre style="white-space:pre-wrap">${cleartextMsg.getText().replace(/</g, '&lt;')}</pre>`, signerEmail: params.senderEmail, sigValid: null };
    }
    const result = await openpgp.verify({ message: cleartextMsg, verificationKeys: [senderPubKey] });
    const sig = result.signatures[0];
    let sigValid: boolean | null = null;
    try { sigValid = sig ? await sig.verified : null; dlog('sign: signature verified =', sigValid); }
    catch (e) { sigValid = false; dlog('sign: signature verify FAILED:', e instanceof Error ? e.message : e, '| sig keyID=', (sig?.keyID as any)?.toHex?.()); }
    const text = result.data as string;
    return { html: `<pre style="white-space:pre-wrap">${text.replace(/</g, '&lt;')}</pre>`, signerEmail: params.senderEmail, sigValid };
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
  const direct = params.recipientEmail ? ecdhByEmail.get(params.recipientEmail) : undefined;
  const candidatesToTry: EcdhCandidate[] = direct ? [direct] : [...ecdhByEmail.values()];
  dlog('decrypt: recipient direct-hit=', !!direct, '| candidate ECDH keys=', candidatesToTry.map(c => c.email));

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
    const senderKeyBytes = await wkdFetch(signerEmail);
    dlog('verify: wkdFetch(', signerEmail, ') →', senderKeyBytes ? `${senderKeyBytes.length} bytes` : 'null (not found / CSP-blocked)');
    // Validate the sender key claims this address before trusting a "signature valid" badge.
    let verificationKeys: openpgp.PublicKey[] = [];
    if (!senderKeyBytes) {
      // eslint-disable-next-line no-console
      console.warn('[pgp] verify: could not fetch sender WKD key for', signerEmail, '— signature cannot be verified (shown as unverified, not invalid)');
    } else {
      try {
        const vk = await readValidatedWkdKey(senderKeyBytes, signerEmail, { requireEncryptionKey: false });
        verificationKeys = [vk];
        dlog('verify: sender key validated | primary keyID=', vk.getKeyID().toHex(),
          '| subkey IDs=', vk.getSubkeys().map(s => s.getKeyID().toHex()));
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[pgp] verify: sender WKD key failed validation:', e instanceof Error ? e.message : e);
      }
    }
    const decrypted = await openpgp.decrypt({ message, sessionKeys: [sessionKey], verificationKeys });
    plaintext = decrypted.data as string;
    dlog('verify: decrypted OK | plaintext bytes=', plaintext.length, '| signatures in message=', decrypted.signatures.length, '| verificationKeys=', verificationKeys.length);
    if (verificationKeys.length) {
      const sig = decrypted.signatures[0];
      if (!sig) {
        sigValid = null;
        // eslint-disable-next-line no-console
        console.warn('[pgp] verify: no signature packet in decrypted message');
      } else {
        try {
          await sig.verified;
          sigValid = true;
          dlog('verify: SIGNATURE VALID ✓ | keyID=', (sig.keyID as any)?.toHex?.());
        } catch (e) {
          sigValid = false;
          // eslint-disable-next-line no-console
          console.warn('[pgp] verify FAILED:', e instanceof Error ? e.message : e,
            '| signature keyID:', (sig.keyID as any)?.toHex?.(),
            '| fetched sender key IDs:', verificationKeys.map(k => k.getKeyID().toHex()),
            '| sender subkey IDs:', verificationKeys.flatMap(k => k.getSubkeys().map(s => s.getKeyID().toHex())));
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
