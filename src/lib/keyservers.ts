/**
 * keyservers.ts — recipient public-key lookup on VKS keyservers (keys.openpgp.org & co.),
 * as a fallback to WKD when the recipient's domain doesn't publish a WKD key.
 *
 * The list of keyservers is user-editable (PGP settings) and synced to the account.
 * Only VKS servers with a verified-address policy (keys.openpgp.org) should be used as
 * auto-trusted sources — they confirm the email owns the key. Kept free of any openpgp.js
 * dependency (like wkd-fetch.ts); callers parse/validate the returned armored key.
 */
import { writePgpAccountMetadata } from './account-metadata';

/** localStorage / account-metadata key for the keyserver list (JSON array of base URLs). */
export const KEYSERVERS_META_KEY = 'pgp.keyservers';

/** keys.openpgp.org verifies the email address before serving a key — safe default. */
export const DEFAULT_KEYSERVERS = ['https://keys.openpgp.org'];

export function getKeyservers(): string[] {
  try {
    const raw = localStorage.getItem(KEYSERVERS_META_KEY);
    if (!raw) return [...DEFAULT_KEYSERVERS];
    const list = JSON.parse(raw);
    const clean = Array.isArray(list) ? list.filter((x) => typeof x === 'string' && x.trim()) : [];
    return clean.length ? clean : [...DEFAULT_KEYSERVERS];
  } catch {
    return [...DEFAULT_KEYSERVERS];
  }
}

export function setKeyservers(list: string[]): void {
  const clean = list.map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
  try {
    localStorage.setItem(KEYSERVERS_META_KEY, JSON.stringify(clean));
  } catch {
    /* storage disabled */
  }
  void writePgpAccountMetadata({ [KEYSERVERS_META_KEY]: JSON.stringify(clean) });
  clearKeyserverCache();
}

/** Copy the keyserver list from account metadata into localStorage (startup hydration). */
export function applyKeyserversFromAttrs(attrs: Record<string, string>): void {
  if (KEYSERVERS_META_KEY in attrs) {
    try {
      localStorage.setItem(KEYSERVERS_META_KEY, attrs[KEYSERVERS_META_KEY]);
    } catch {
      /* storage disabled */
    }
  }
}

// Per-session cache of the armored key (or null = not found) keyed by lower-cased email.
const cache = new Map<string, string | null>();

export function clearKeyserverCache(): void {
  cache.clear();
}

/**
 * Fetch a recipient's armored public key from the configured VKS keyservers (by-email).
 * Returns the armored key text, or null if none of the servers have it.
 */
export async function keyserverFetch(email: string): Promise<string | null> {
  const key = email.toLowerCase();
  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  for (const base of getKeyservers()) {
    try {
      const url = `${base.replace(/\/+$/, '')}/vks/v1/by-email/${encodeURIComponent(email)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
      if (res.ok) {
        const armored = await res.text();
        if (armored.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
          cache.set(key, armored);
          return armored;
        }
      }
    } catch {
      /* try next server */
    }
  }
  cache.set(key, null);
  return null;
}

/**
 * Fetch an armored public key by its 64-bit key ID (or full fingerprint) from the
 * configured VKS keyservers. Used when the signer signed with a key that differs from
 * whatever the by-email lookup returns (e.g. a Thunderbird key vs the HSM/WKD key for
 * the same address) — we must verify against the key that actually issued the signature.
 */
export async function keyserverFetchByKeyId(keyIdHex: string): Promise<string | null> {
  const id = keyIdHex.replace(/^0x/i, '').toUpperCase();
  if (!/^[0-9A-F]{16}([0-9A-F]{24})?$/.test(id)) return null;
  const path = id.length === 40 ? `by-fingerprint/${id}` : `by-keyid/${id}`;
  for (const base of getKeyservers()) {
    try {
      const url = `${base.replace(/\/+$/, '')}/vks/v1/${path}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
      if (res.ok) {
        const armored = await res.text();
        if (armored.includes('BEGIN PGP PUBLIC KEY BLOCK')) return armored;
      }
    } catch {
      /* try next server */
    }
  }
  return null;
}

/** De-armor an ASCII-armored PGP block to its binary packets (no openpgp.js). */
function dearmor(armored: string): Uint8Array {
  const m = armored.match(/-----BEGIN PGP[^-]*-----([\s\S]*?)-----END PGP[^-]*-----/);
  if (!m) throw new Error('not an ASCII-armored PGP key');
  // Keep only base64 payload lines: drop blank lines, "Header: value" lines, and the
  // "=CRC" checksum line.
  const b64 = m[1]
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.includes(':') && !l.startsWith('='))
    .join('');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Fetch a recipient's public key by email from the keyservers and return it as binary
 * packets plus the server that answered — for importing a peer key when WKD has none.
 */
export async function keyserverFetchBinary(email: string): Promise<{ bytes: Uint8Array; server: string } | null> {
  for (const base of getKeyservers()) {
    try {
      const url = `${base.replace(/\/+$/, '')}/vks/v1/by-email/${encodeURIComponent(email)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(6000) });
      if (res.ok) {
        const armored = await res.text();
        if (armored.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
          return { bytes: dearmor(armored), server: base.replace(/^https?:\/\//, '').replace(/\/+$/, '') };
        }
      }
    } catch {
      /* try next server */
    }
  }
  return null;
}
