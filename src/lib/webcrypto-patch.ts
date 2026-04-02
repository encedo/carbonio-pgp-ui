/**
 * Patch globalThis.crypto for Carbonio Shell webpack environment.
 *
 * Carbonio Shell (webpack 5) polyfills globalThis as `self`, but in some
 * execution contexts `globalThis.crypto.subtle` ends up undefined even though
 * `window.crypto.subtle` is fully available.  openpgp.js calls getWebCrypto()
 * lazily (on first crypto op), so we must patch before any openpgp operation.
 *
 * Call this function once, right before any dynamic import of encedo-pgp.browser.js.
 */
export function patchWebCrypto(): void {
  const hasCrypto   = typeof globalThis !== 'undefined' && !!globalThis.crypto;
  const hasSubtle   = hasCrypto && !!globalThis.crypto.subtle;
  const winCrypto   = typeof window !== 'undefined' ? window.crypto : undefined;
  const winSubtle   = !!winCrypto?.subtle;

  console.debug('[pgp] patchWebCrypto:', {
    globalThis_crypto:         hasCrypto,
    globalThis_crypto_subtle:  hasSubtle,
    window_crypto:             !!winCrypto,
    window_crypto_subtle:      winSubtle,
  });

  if (!hasSubtle && winSubtle) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).crypto = winCrypto;
    console.debug('[pgp] patchWebCrypto: patched globalThis.crypto = window.crypto');
  } else if (hasSubtle) {
    console.debug('[pgp] patchWebCrypto: no patch needed, globalThis.crypto.subtle OK');
  } else {
    console.warn('[pgp] patchWebCrypto: neither globalThis nor window has crypto.subtle!');
  }
}
