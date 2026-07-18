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

// Per-session cache of WKD key bytes, keyed by lower-cased email. WKD keys are
// stable within a session, so this avoids re-fetching a recipient's (or our own)
// key on every send/decrypt. Populated lazily on first use and cleared when HSM
// keys change (see clearWkdCache).
// Value is the key bytes, or null = "looked up this session, not found" — negative caching
// avoids re-hitting WKD (and the browser re-logging a CORS error) for every keystroke/send
// when a domain has no WKD key for the address.
const wkdKeyCache = new Map<string, Uint8Array | null>();

/** Drop all cached WKD keys — call after any HSM key change (keygen/import/delete/rotate/publish). */
export function clearWkdCache(): void {
  wkdKeyCache.clear();
}

export async function wkdFetch(email: string): Promise<Uint8Array | null> {
  const atIdx = email.indexOf('@');
  if (atIdx < 0) return null;
  const key = email.toLowerCase();
  if (wkdKeyCache.has(key)) return wkdKeyCache.get(key) ?? null;

  const local  = email.slice(0, atIdx);
  const domain = email.slice(atIdx + 1);
  const hash   = zbase32(await sha1(new TextEncoder().encode(local.toLowerCase())));
  const lEnc   = encodeURIComponent(local);

  // Advanced method first. If the openpgpkey.<domain> host RESPONDS (even with a 404), it
  // is authoritative — no key for this address — so we skip the direct method. The direct
  // fallback hits the bare domain, which on a CORS-less 404 makes the browser log an error.
  let advancedResponded = false;
  try {
    const url = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${lEnc}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    advancedResponded = true;
    if (res.ok) { const b = new Uint8Array(await res.arrayBuffer()); wkdKeyCache.set(key, b); return b; }
  } catch { /* advanced host unreachable — try the direct method */ }

  // Direct method — only when the advanced host didn't respond at all.
  if (!advancedResponded) {
    try {
      const url = `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${lEnc}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) { const b = new Uint8Array(await res.arrayBuffer()); wkdKeyCache.set(key, b); return b; }
    } catch { /* not found */ }
  }

  wkdKeyCache.set(key, null); // remember the miss so we don't re-hit WKD this session
  return null;
}

// ── OpenPGP v4 binary packet parser ─────────────────────────────────────────
// Only what we need: extract raw 32-byte Ed25519 (algo 22) and X25519 (algo 18) keys.

const TAG_PUBLIC_KEY    = 6;
const TAG_PUBLIC_SUBKEY = 14;
const ALGO_EDDSA = 22;
const ALGO_ECDH  = 18;
const ALGO_ECDSA = 19; // NIST-curve signing key (P-256/384/521)

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

// NIST + secp256k1 curve OIDs (as they appear in an OpenPGP ECDSA/ECDH packet, without the
// 1-byte length prefix) → HEM key type + human label. The HEM stores these as SECP*R1 / SECP256K1.
const NIST_CURVES: Array<{ oid: Uint8Array; type: string; label: string }> = [
  { oid: new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]), type: 'SECP256R1', label: 'NIST P-256' },
  { oid: new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x22]),                   type: 'SECP384R1', label: 'NIST P-384' },
  { oid: new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x23]),                   type: 'SECP521R1', label: 'NIST P-521' },
  { oid: new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x0a]),                   type: 'SECP256K1', label: 'secp256k1' },
];

// Read the first MPI value from a v4 ECC packet body (the public point). Returns the raw
// value bytes (no 2-byte bit-count prefix). For 25519 this is 0x40||<32>; for NIST/k1 it is
// the SEC1 uncompressed point 0x04||X||Y.
function extractMpiValue(body: Uint8Array): Uint8Array | null {
  if (body.length < 8 || body[0] !== 4) return null;
  const oidLen = body[6];
  const mpiOff = 7 + oidLen;
  if (mpiOff + 2 > body.length) return null;
  const bits = (body[mpiOff] << 8) | body[mpiOff + 1];
  const nbytes = (bits + 7) >> 3;
  const start = mpiOff + 2;
  if (start + nbytes > body.length) return null;
  return body.slice(start, start + nbytes);
}

// Resolve an ECC public key/subkey packet to { HEM type, curve label, import bytes }.
// import bytes = what the HEM import expects (per the hem-api-tester reference): the raw
// 32-byte value for Ed25519/X25519 (native 0x40 prefix stripped) or the COMPRESSED SEC1
// point (0x02/0x03||X — 33/49/67 B) for NIST / secp256k1. OpenPGP certs carry the
// uncompressed 0x04||X||Y form, so NIST points are compressed here (prefix from Y parity).
// Returns null for non-ECC or unsupported curves (brainpool, Ed448/X448 v6, …).
function resolveEccKey(body: Uint8Array): { hemType: string; label: string; bytes: Uint8Array } | null {
  const algo = body[5];
  const mpi = extractMpiValue(body);
  if (!mpi) return null;
  if (algo === ALGO_EDDSA && oidMatches(body, OID_ED25519)) {
    const raw = mpi[0] === 0x40 ? mpi.slice(1) : mpi;
    return raw.length === 32 ? { hemType: 'ED25519', label: 'Ed25519', bytes: raw } : null;
  }
  if (algo === ALGO_ECDH && oidMatches(body, OID_X25519)) {
    const raw = mpi[0] === 0x40 ? mpi.slice(1) : mpi;
    return raw.length === 32 ? { hemType: 'CURVE25519', label: 'Curve25519', bytes: raw } : null;
  }
  if (algo === ALGO_ECDSA || algo === ALGO_ECDH) {
    for (const c of NIST_CURVES) {
      if (!oidMatches(body, c.oid)) continue;
      if (mpi[0] === 0x02 || mpi[0] === 0x03) return { hemType: c.type, label: c.label, bytes: mpi };
      if (mpi[0] !== 0x04 || (mpi.length - 1) % 2 !== 0) return null;
      const n = (mpi.length - 1) / 2;
      const compressed = new Uint8Array(1 + n);
      compressed[0] = (mpi[mpi.length - 1] & 1) === 0 ? 0x02 : 0x03; // parity of Y
      compressed.set(mpi.slice(1, 1 + n), 1);
      return { hemType: c.type, label: c.label, bytes: compressed };
    }
  }
  return null;
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
  signRaw32: Uint8Array;   // raw sign key bytes for HSM import (32B for Ed25519; SEC1 point for NIST/k1)
  ecdhRaw32: Uint8Array;   // raw ECDH key bytes for HSM import (32B for X25519; SEC1 point for NIST/k1)
  signType: string;        // HEM key type for the sign key: ED25519 | SECP256R1 | SECP384R1 | SECP521R1 | SECP256K1
  ecdhType: string;        // HEM key type for the ECDH key: CURVE25519 | SECP256R1 | …
  curveLabel: string;      // human curve name for display (e.g. "Ed25519", "NIST P-256")
  signHex: string;         // first 16 chars grouped for display
  ecdhHex: string;
  fingerprint: string;     // primary key fingerprint (40-char grouped hex)
  ecdhFingerprint: string; // ECDH subkey fingerprint (40-char grouped hex)
}

export async function wkdLookupParse(email: string): Promise<WkdKeyInfo> {
  const keyBytes = await wkdFetch(email);
  if (!keyBytes) throw new Error(`No WKD key found for ${email}`);
  return parseKeyInfo(email, keyBytes);
}

/**
 * Parse a binary OpenPGP public key (as fetched from WKD or a keyserver) into the raw key
 * material + HEM key type the HSM import needs. Pure byte parsing — no openpgp.js.
 * Supports the ECC curves the HEM can hold: Ed25519 + X25519, NIST P-256/P-384/P-521, and
 * secp256k1 (a sign primary + an ECDH subkey). Throws a clear message for RSA/DSA/ElGamal
 * or unsupported curves (brainpool, Ed448/X448 v6).
 */
export async function parseKeyInfo(email: string, keyBytes: Uint8Array): Promise<WkdKeyInfo> {
  // OpenPGP public-key algorithm IDs (RFC 4880 §9.1 + later) → human names, for a clear
  // "can't import this key type" message. The HSM only stores Ed25519 + X25519 peer keys.
  const ALGO_NAMES: Record<number, string> = {
    1: 'RSA', 2: 'RSA', 3: 'RSA', 16: 'ElGamal', 17: 'DSA',
    18: 'ECDH', 19: 'ECDSA', 20: 'ElGamal', 22: 'EdDSA', 23: 'X25519', 25: 'Ed25519',
  };

  const packets = parsePackets(keyBytes);
  let sign: { hemType: string; label: string; bytes: Uint8Array } | null = null;
  let ecdh: { hemType: string; label: string; bytes: Uint8Array } | null = null;
  let primaryBody: Uint8Array | null = null;
  let ecdhBody:    Uint8Array | null = null;
  let primaryAlgo: number | null = null;

  for (const pkt of packets) {
    // The first public-key packet is the primary (signing) key.
    if (pkt.tag === TAG_PUBLIC_KEY && primaryBody === null) {
      primaryBody = pkt.body;
      primaryAlgo = pkt.body[5];
      if (primaryAlgo === ALGO_EDDSA || primaryAlgo === ALGO_ECDSA) sign = resolveEccKey(pkt.body);
    }
    // First ECDH subkey we can resolve is the encryption key.
    if (pkt.tag === TAG_PUBLIC_SUBKEY && pkt.body[5] === ALGO_ECDH && !ecdh) {
      const r = resolveEccKey(pkt.body);
      if (r) { ecdh = r; ecdhBody = pkt.body; }
    }
  }

  if (!sign || !primaryBody) {
    if (primaryAlgo === ALGO_EDDSA || primaryAlgo === ALGO_ECDSA) {
      throw new Error(`Cannot import ${email}: the signing key uses an unsupported curve. Supported: Ed25519 and NIST P-256/P-384/P-521 (also secp256k1).`);
    }
    const algo = primaryAlgo !== null ? (ALGO_NAMES[primaryAlgo] ?? `algorithm #${primaryAlgo}`) : 'an unknown algorithm';
    throw new Error(`Cannot import ${email}: this key uses ${algo}, which is not an elliptic-curve key. Encedo HSM stores ECC keys only, so RSA, DSA and ElGamal keys can't be imported.`);
  }
  if (!ecdh || !ecdhBody) {
    throw new Error(`Cannot import ${email}: no supported encryption (ECDH) subkey — need an X25519, NIST P-256/384/521 or secp256k1 ECDH subkey.`);
  }

  const signRaw32 = sign.bytes;
  const ecdhRaw32 = ecdh.bytes;
  const [fingerprint, ecdhFingerprint] = await Promise.all([
    fingerprintV4(primaryBody),
    fingerprintV4(ecdhBody),
  ]);

  return {
    email,
    signRaw32,
    ecdhRaw32,
    signType: sign.hemType,
    ecdhType: ecdh.hemType,
    curveLabel: sign.label,
    signHex: shortHex(signRaw32),
    ecdhHex: shortHex(ecdhRaw32),
    fingerprint,
    ecdhFingerprint,
  };
}
