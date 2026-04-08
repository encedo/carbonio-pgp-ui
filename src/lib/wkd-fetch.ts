/**
 * wkd-fetch.ts — WKD key lookup + OpenPGP binary parser
 *
 * Intentionally has NO dependency on openpgp.js.
 * Uses only browser fetch + a pure-JS SHA-1 for the WKD z-base32 hash.
 * This avoids the "WebCrypto API is not available" crash from openpgp at
 * module-init time when loaded inside Carbonio Shell.
 */

// ── SHA-1 via crypto.subtle ───────────────────────────────────────────────────

async function sha1(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-1', data.buffer as ArrayBuffer);
  return new Uint8Array(buf);
}

// ── Z-Base-32 ────────────────────────────────────────────────────────────────

const ZBASE32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function zbase32(bytes: Uint8Array): string {
  let buf = 0, bits = 0, out = '';
  for (const byte of bytes) {
    buf = (buf<<8)|byte; bits += 8;
    while (bits >= 5) { bits -= 5; out += ZBASE32[(buf>>bits)&0x1f]; }
  }
  if (bits > 0) out += ZBASE32[(buf<<(5-bits))&0x1f];
  return out;
}

// ── WKD fetch ────────────────────────────────────────────────────────────────

export async function wkdFetch(email: string): Promise<Uint8Array | null> {
  const atIdx = email.indexOf('@');
  if (atIdx < 0) return null;
  const local  = email.slice(0, atIdx);
  const domain = email.slice(atIdx + 1);
  const hash   = zbase32(await sha1(new TextEncoder().encode(local.toLowerCase())));
  const lEnc   = encodeURIComponent(local);

  // Advanced method first
  try {
    const url = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${lEnc}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
  } catch { /* fall through */ }

  // Direct method
  try {
    const url = `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${lEnc}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
  } catch { /* not found */ }

  return null;
}

// ── OpenPGP v4 binary packet parser ─────────────────────────────────────────
// Only what we need: extract raw 32-byte Ed25519 (algo 22) and X25519 (algo 18) keys.

const TAG_PUBLIC_KEY    = 6;
const TAG_PUBLIC_SUBKEY = 14;
const ALGO_EDDSA = 22;
const ALGO_ECDH  = 18;

// Supported OIDs (byte sequences after the OID length byte in the packet body)
// Ed25519:  1.3.6.1.4.1.11591.15.1  — 9 bytes
// X25519:   1.3.6.1.4.1.3029.1.5.1  — 10 bytes
const OID_ED25519 = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]);
const OID_X25519  = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);

function oidMatches(body: Uint8Array, expected: Uint8Array): boolean {
  const oidLen = body[6];
  if (oidLen !== expected.length) return false;
  for (let i = 0; i < oidLen; i++) {
    if (body[7 + i] !== expected[i]) return false;
  }
  return true;
}

function parsePackets(data: Uint8Array): Array<{ tag: number; body: Uint8Array }> {
  const packets: Array<{ tag: number; body: Uint8Array }> = [];
  let i = 0;
  while (i < data.length) {
    const ctb = data[i++];
    if ((ctb & 0x80) === 0) break;
    let tag: number, len: number;
    if (ctb & 0x40) {
      // New format
      tag = ctb & 0x3f;
      const first = data[i++];
      if (first < 192)      { len = first; }
      else if (first < 224) { len = ((first-192)<<8)+data[i++]+192; }
      else if (first === 255) { len=(data[i]<<24)|(data[i+1]<<16)|(data[i+2]<<8)|data[i+3]; i+=4; }
      else break; // partial body — not expected in key data
    } else {
      // Old format
      tag = (ctb>>2)&0xf;
      const lt = ctb&0x3;
      if      (lt===0) { len=data[i++]; }
      else if (lt===1) { len=(data[i++]<<8)|data[i++]; }
      else if (lt===2) { len=(data[i]<<24)|(data[i+1]<<16)|(data[i+2]<<8)|data[i+3]; i+=4; }
      else             { len=data.length-i; }
    }
    packets.push({ tag, body: data.slice(i, i+len) });
    i += len;
  }
  return packets;
}

// Extract raw 32-byte key material from a v4 public key/subkey packet body.
// Returns null if the packet is not an Ed25519 or X25519 key.
function extractRaw32(body: Uint8Array): Uint8Array | null {
  if (body.length < 8 || body[0] !== 4) return null;
  const algo = body[5];
  if (algo !== ALGO_EDDSA && algo !== ALGO_ECDH) return null;
  const oidLen = body[6];
  const mpiOff = 7 + oidLen; // offset to MPI (bit-count + data)
  if (mpiOff + 2 >= body.length) return null;
  // MPI: 2 bytes bit-count, then ceil(bits/8) bytes
  // For native-prefixed 32-byte key: bit-count=263, data=0x40 + 32 bytes
  const mpiData = body.slice(mpiOff + 2);
  const start = mpiData[0] === 0x40 ? 1 : 0; // strip native point prefix
  if (mpiData.length < start + 32) return null;
  return mpiData.slice(start, start + 32);
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function shortHex(bytes: Uint8Array): string {
  const h = toHex(bytes).slice(0, 16);
  return h.replace(/(.{4})(?=.)/g, '$1 ');
}

// ── Result ────────────────────────────────────────────────────────────────────

/** Compute OpenPGP v4 fingerprint: SHA-1( 0x99 || uint16be(bodyLen) || body ) */
async function fingerprintV4(body: Uint8Array): Promise<string> {
  const len = body.length;
  const data = new Uint8Array(3 + len);
  data[0] = 0x99;
  data[1] = (len >> 8) & 0xff;
  data[2] = len & 0xff;
  data.set(body, 3);
  const hash = await sha1(data);
  // Display as uppercase hex grouped every 4 chars with space
  const hex = toHex(hash);
  return hex.replace(/(.{4})(?=.)/g, '$1 ');
}

export interface WkdKeyInfo {
  email: string;
  signRaw32: Uint8Array;
  ecdhRaw32: Uint8Array;
  signHex: string;        // first 16 chars grouped for display
  ecdhHex: string;
  fingerprint: string;    // primary key fingerprint (40-char grouped hex)
  ecdhFingerprint: string; // ECDH subkey fingerprint (40-char grouped hex)
}

export async function wkdLookupParse(email: string): Promise<WkdKeyInfo> {
  const keyBytes = await wkdFetch(email);
  if (!keyBytes) throw new Error(`No WKD key found for ${email}`);

  const packets = parsePackets(keyBytes);
  let signRaw32: Uint8Array | null = null;
  let ecdhRaw32:  Uint8Array | null = null;
  let primaryBody: Uint8Array | null = null;
  let ecdhBody:    Uint8Array | null = null;

  for (const pkt of packets) {
    if (pkt.tag === TAG_PUBLIC_KEY && pkt.body[5] === ALGO_EDDSA) {
      if (!oidMatches(pkt.body, OID_ED25519))
        throw new Error(`Unsupported EdDSA curve in WKD key for ${email} (only Ed25519 is supported)`);
      signRaw32 = extractRaw32(pkt.body);
      primaryBody = pkt.body;
    }
    if (pkt.tag === TAG_PUBLIC_SUBKEY && pkt.body[5] === ALGO_ECDH) {
      if (!oidMatches(pkt.body, OID_X25519))
        throw new Error(`Unsupported ECDH curve in WKD key for ${email} (only X25519 / Curve25519 is supported)`);
      ecdhRaw32 = extractRaw32(pkt.body);
      ecdhBody  = pkt.body;
    }
  }

  if (!signRaw32 || !primaryBody) throw new Error(`Ed25519 signing key not found in WKD response for ${email}`);
  if (!ecdhRaw32 || !ecdhBody)   throw new Error(`X25519 ECDH key not found in WKD response for ${email}`);

  const [fingerprint, ecdhFingerprint] = await Promise.all([
    fingerprintV4(primaryBody),
    fingerprintV4(ecdhBody),
  ]);

  return {
    email,
    signRaw32,
    ecdhRaw32,
    signHex: shortHex(signRaw32),
    ecdhHex: shortHex(ecdhRaw32),
    fingerprint,
    ecdhFingerprint,
  };
}
