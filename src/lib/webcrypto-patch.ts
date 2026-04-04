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
  // openpgp.js (inside encedo-pgp.browser.js) detects the global as:
  //   const e = window ?? global ?? self ?? {}
  // and captures it in a closure at module-eval time.
  // If window.crypto.subtle or self.crypto.subtle is missing, openpgp fails.
  // We patch all three globals before the dynamic import triggers module eval.

  const nativeCrypto = (
    (typeof window !== 'undefined' && window.crypto?.subtle && window.crypto) ||
    (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle && globalThis.crypto) ||
    null
  );

  console.debug('[pgp] patchWebCrypto:', {
    globalThis_crypto:        typeof globalThis !== 'undefined' && !!globalThis.crypto,
    globalThis_crypto_subtle: typeof globalThis !== 'undefined' && !!globalThis.crypto?.subtle,
    window_crypto:            typeof window !== 'undefined' && !!window.crypto,
    window_crypto_subtle:     typeof window !== 'undefined' && !!window.crypto?.subtle,
    self_crypto:              typeof self !== 'undefined' && !!(self as Window).crypto,
    self_crypto_subtle:       typeof self !== 'undefined' && !!(self as Window).crypto?.subtle,
    nativeCrypto_found:       !!nativeCrypto,
  });

  if (!nativeCrypto) {
    console.warn('[pgp] patchWebCrypto: no crypto.subtle found anywhere!');
    return;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;

  if (!g.crypto?.subtle)  { g.crypto  = nativeCrypto; console.debug('[pgp] patched globalThis.crypto'); }
  if (typeof window !== 'undefined' && !window.crypto?.subtle) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).crypto = nativeCrypto; console.debug('[pgp] patched window.crypto');
  }
  if (typeof self !== 'undefined' && !(self as Window).crypto?.subtle) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (self as any).crypto = nativeCrypto; console.debug('[pgp] patched self.crypto');
  }

  console.debug('[pgp] patchWebCrypto done');
}
