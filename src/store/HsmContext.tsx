import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
// @ts-expect-error — carbonio-shell-ui types incomplete but hooks exist at runtime
import { useUserAccount, useUserSettings } from '@zextras/carbonio-shell-ui';
import { HEM } from '../../../hem-sdk-js/hem-sdk.browser.js';
import { patchWebCrypto } from '../lib/webcrypto-patch';

// Preload encedo-pgp.browser.js as soon as we know crypto is available,
// so openpgp.js module-level code runs while window.crypto.subtle is intact.
function preloadEncedoPgp() {
  patchWebCrypto();
  import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js').catch(() => {/* ignore */});
}

// ── DESCR helpers ─────────────────────────────────────────────────────────────

export const DESCR_PREFIX = 'ETSPGP:';

export function encodeDescr(plain: string): string {
  return btoa(plain);
}

export interface ParsedDescr {
  role: 'self' | 'peer';
  email: string;
  keyType: 'sign' | 'ecdh';
  iat?: number;
  exp?: number;
}

export function parseDescr(plain: string): ParsedDescr | null {
  if (!plain.startsWith(DESCR_PREFIX)) return null;
  const parts = plain.slice(DESCR_PREFIX.length).split(',');
  if (parts.length < 3) return null;
  const [role, email, keyType, iatStr, expStr] = parts;
  if (role !== 'self' && role !== 'peer') return null;
  if (keyType !== 'sign' && keyType !== 'ecdh') return null;
  return {
    role,
    email,
    keyType,
    iat: iatStr ? Number(iatStr) : undefined,
    exp: expStr ? Number(expStr) : undefined,
  };
}

const textDecoder = new TextDecoder();

export function decodeDescr(key: { description: Uint8Array | string | null }): ParsedDescr | null {
  try {
    if (!key.description) return null;
    const plain = key.description instanceof Uint8Array
      ? textDecoder.decode(key.description)
      : key.description;
    return parseDescr(plain);
  } catch {
    return null;
  }
}

// DESCR string builders (mirrors keychain.js)
export const DESCR = {
  selfSign: (email: string, iat: number, exp?: number) =>
    `ETSPGP:self,${email},sign,${iat}${exp ? `,${exp}` : ''}`,
  selfEcdh: (email: string, iat: number, exp?: number) =>
    `ETSPGP:self,${email},ecdh,${iat}${exp ? `,${exp}` : ''}`,
};

// ── Types ─────────────────────────────────────────────────────────────────────

export interface HsmState {
  url: string;
  hem: InstanceType<typeof HEM> | null;
  listToken: string | null;
  connected: boolean;
  unlocked:  boolean;
  error:     string | null;
}

export interface HsmContextValue extends HsmState {
  setUrl: (url: string) => void;
  connect: (password: string) => Promise<void>;
  disconnect: () => void;
  authorize: (scope: string) => Promise<string>;
}

// ── Module-level singleton — survives React unmount/remount ───────────────────

const HSM_URL_KEY = 'pgp-hsm-url';
const HSM_PW_KEY  = 'pgp-hsm-password';
const TOKEN_TTL   = 8 * 3600;

// Mutable singleton — shared across all HsmProvider instances/remounts.
// Exported so app.tsx can expose HSM state to mails-ui via window globals.
// NOTE: password is never stored here — derived keys live inside the HEM instance (#derivedKeys).
export const _singleton = {
  userEmails: new Set<string>(),  // primary + aliases; synced from Carbonio account in HsmProvider
  tokenCache: new Map<string, { token: string; expiresAt: number }>(),
  ecdhFingerprintCache: new Map<string, Uint8Array>(), // email → ECDH subkey fingerprint
  state: {
    url:       localStorage.getItem(HSM_URL_KEY) ?? '',
    hem:       null,
    listToken: null,
    connected: false,
    unlocked:  false,
    error:     null,
  } as HsmState,
};

// ── Context ───────────────────────────────────────────────────────────────────

const HsmContext = createContext<HsmContextValue | null>(null);

async function authorizeWithCache(hem: InstanceType<typeof HEM>, scope: string): Promise<string> {
  const cached = _singleton.tokenCache.get(scope);
  if (cached && Date.now() < cached.expiresAt) return cached.token;
  // Pass null — HEM uses cached derived keys (set during connect); password never stored here.
  const token = await hem.authorizePassword('', scope, TOKEN_TTL);
  _singleton.tokenCache.set(scope, { token, expiresAt: Date.now() + TOKEN_TTL * 1000 - 30_000 });
  return token;
}

export function HsmProvider({ children }: { children: React.ReactNode }) {
  // Initialize React state from singleton — picks up state after remount
  const [state, setState] = useState<HsmState>(() => ({ ..._singleton.state }));

  // Sync all user emails (primary + aliases) to singleton for senderEmail validation
  const account = useUserAccount();
  const settings = useUserSettings();
  useEffect(() => {
    const emails = new Set<string>();
    const name = account?.name as string | undefined;
    if (name) emails.add(name);
    const aliases = (settings as any)?.attrs?.zimbraMailAlias;
    const allowFrom = (settings as any)?.attrs?.zimbraAllowFromAddress;
    [aliases, allowFrom].flat().filter(Boolean).forEach((e: string) => emails.add(e));
    for (const identity of (account as any)?.identities?.identity ?? []) {
      const from = identity._attrs?.zimbraPrefFromAddress;
      if (from) emails.add(from as string);
    }
    _singleton.userEmails = new Set([...emails].filter((e: string) => e.includes('@')));
  }, [account, settings]);

  // Keep singleton in sync whenever React state changes
  useEffect(() => {
    _singleton.state = state;
  }, [state]);

  const setUrl = useCallback((url: string) => {
    localStorage.setItem(HSM_URL_KEY, url);
    _singleton.state.hem?.clearKeys();
    _singleton.tokenCache.clear();
    const next: HsmState = {
      ...state,
      url,
      hem: null, listToken: null,
      connected: false, unlocked: false, error: null,
    };
    _singleton.state = next;
    setState(next);
  }, [state]);

  const connect = useCallback(async (password: string) => {
    setState(s => ({ ...s, error: null }));
    try {
      const hem = new HEM(_singleton.state.url);
      await hem.hemCheckin();
      _singleton.tokenCache.clear();

      // First call passes the real password — HEM derives and caches the X25519 keys,
      // then zeros the intermediate byte buffers. Password is not stored anywhere after this.
      const listToken = await hem.authorizePassword(password, 'keymgmt:list', TOKEN_TTL);
      _singleton.tokenCache.set('keymgmt:list', { token: listToken, expiresAt: Date.now() + TOKEN_TTL * 1000 - 30_000 });

      const next: HsmState = {
        ..._singleton.state,
        hem, listToken,
        connected: true, unlocked: true, error: null,
      };
      _singleton.state = next;
      setState(next);
      preloadEncedoPgp();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const next: HsmState = {
        ..._singleton.state,
        connected: false, unlocked: false, error: msg,
      };
      _singleton.state = next;
      setState(next);
      throw e;
    }
  }, []);

  const disconnect = useCallback(() => {
    sessionStorage.removeItem(HSM_PW_KEY);
    _singleton.state.hem?.clearKeys();
    _singleton.tokenCache.clear();
    const next: HsmState = {
      ..._singleton.state,
      hem: null, listToken: null,
      connected: false, unlocked: false, error: null,
    };
    _singleton.state = next;
    setState(next);
  }, []);

  const authorize = useCallback(async (scope: string): Promise<string> => {
    const { hem } = _singleton.state;
    if (!hem) throw new Error('HSM not connected');
    // No password needed — HEM reuses cached derived keys from connect().
    return authorizeWithCache(hem, scope);
  }, []);


  return (
    <HsmContext.Provider value={{ ...state, setUrl, connect, disconnect, authorize }}>
      {children}
    </HsmContext.Provider>
  );
}

export function useHsm(): HsmContextValue {
  const ctx = useContext(HsmContext);
  if (!ctx) throw new Error('useHsm must be used inside HsmProvider');
  return ctx;
}

export { HSM_PW_KEY };
