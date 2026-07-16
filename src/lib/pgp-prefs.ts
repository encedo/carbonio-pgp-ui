/**
 * pgp-prefs.ts — user preferences for the OpenPGP module.
 *
 * Stored in localStorage so that carbonio-mails-ui (same origin, separate bundle)
 * can read them without going through the window bridge. Keys are part of the
 * contract with mails-ui `src/commons/pgp-prefs.ts` — keep both in sync.
 */

import { writePgpAccountMetadata } from './account-metadata';

export interface PgpPrefs {
  /** Sign every outgoing message with the own HSM key. */
  alwaysSign: boolean;
  /** Encrypt automatically when every recipient has a key available. */
  alwaysEncrypt: boolean;
  /** Decrypt incoming messages on open, without clicking Decrypt. */
  autoDecrypt: boolean;
}

export const PGP_PREF_KEYS: Record<keyof PgpPrefs, string> = {
  alwaysSign:    'pgp.pref.alwaysSign',
  alwaysEncrypt: 'pgp.pref.alwaysEncrypt',
  autoDecrypt:   'pgp.pref.autoDecrypt',
};

export const DEFAULT_PGP_PREFS: PgpPrefs = {
  alwaysSign:    false,
  alwaysEncrypt: false,
  autoDecrypt:   false,
};

export function getPgpPrefs(): PgpPrefs {
  try {
    return {
      alwaysSign:    localStorage.getItem(PGP_PREF_KEYS.alwaysSign)    === 'true',
      alwaysEncrypt: localStorage.getItem(PGP_PREF_KEYS.alwaysEncrypt) === 'true',
      autoDecrypt:   localStorage.getItem(PGP_PREF_KEYS.autoDecrypt)   === 'true',
    };
  } catch {
    return { ...DEFAULT_PGP_PREFS };
  }
}

export function setPgpPref(pref: keyof PgpPrefs, value: boolean): void {
  try {
    localStorage.setItem(PGP_PREF_KEYS[pref], String(value));
  } catch {
    /* private mode / storage disabled — preference simply does not persist */
  }
  // Persist to the Carbonio account too (best-effort) so it syncs across devices.
  void writePgpAccountMetadata({ [PGP_PREF_KEYS[pref]]: String(value) });
}

/**
 * Copy pref values coming from account metadata into localStorage (the synchronous
 * source of truth). Writes directly — does NOT call setPgpPref — to avoid pushing the
 * freshly-read values straight back to the account.
 */
export function applyPgpPrefsFromAttrs(attrs: Record<string, string>): void {
  for (const key of Object.values(PGP_PREF_KEYS)) {
    if (key in attrs) {
      try {
        localStorage.setItem(key, attrs[key]);
      } catch {
        /* storage disabled */
      }
    }
  }
}
