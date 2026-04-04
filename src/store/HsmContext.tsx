import React, { createContext, useCallback, useContext, useRef, useState } from 'react';
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
  listToken: string | null;   // keymgmt:list
  impToken:  string | null;   // keymgmt:imp
  genToken:  string | null;   // keymgmt:gen
  connected: boolean;
  unlocked:  boolean;
  error:     string | null;
}

export interface HsmContextValue extends HsmState {
  setUrl: (url: string) => void;
  connect: (password: string) => Promise<void>;
  disconnect: () => void;
  /** Obtain a fresh token for any scope (uses in-memory password) */
  authorize: (scope: string) => Promise<string>;
}

// ── Context ───────────────────────────────────────────────────────────────────

const HsmContext = createContext<HsmContextValue | null>(null);

const HSM_URL_KEY = 'pgp-hsm-url';
const HSM_PW_KEY  = 'pgp-hsm-password';

const TOKEN_TTL = 8 * 3600;  // 8 hours, in seconds

export function HsmProvider({ children }: { children: React.ReactNode }) {
  // Password kept in memory only (not in React state to avoid re-renders)
  const passwordRef = useRef<string>('');
  // Token cache: scope → { token, expiresAt (ms) }
  const tokenCache  = useRef<Map<string, { token: string; expiresAt: number }>>(new Map());

  const [state, setState] = useState<HsmState>(() => ({
    url: localStorage.getItem(HSM_URL_KEY) ?? '',
    hem: null,
    listToken: null,
    impToken:  null,
    genToken:  null,
    connected: false,
    unlocked:  false,
    error:     null,
  }));

  // Authorize with cache — reuses token if still valid, fetches new one otherwise
  const authorizeWithCache = async (hem: InstanceType<typeof HEM>, password: string, scope: string): Promise<string> => {
    const cached = tokenCache.current.get(scope);
    if (cached && Date.now() < cached.expiresAt) return cached.token;
    const token = await hem.authorizePassword(password, scope, TOKEN_TTL);
    tokenCache.current.set(scope, { token, expiresAt: Date.now() + TOKEN_TTL * 1000 - 30_000 });
    return token;
  };

  const setUrl = useCallback((url: string) => {
    localStorage.setItem(HSM_URL_KEY, url);
    passwordRef.current = '';
    tokenCache.current.clear();
    setState(s => ({
      ...s, url,
      hem: null, listToken: null, impToken: null, genToken: null,
      connected: false, unlocked: false, error: null,
    }));
  }, []);

  const connect = useCallback(async (password: string) => {
    setState(s => ({ ...s, error: null }));
    try {
      const hem = new HEM(state.url);
      await hem.hemCheckin();
      tokenCache.current.clear();

      const listToken = await authorizeWithCache(hem, password, 'keymgmt:list');

      let impToken: string | null = null;
      try { impToken = await authorizeWithCache(hem, password, 'keymgmt:imp'); } catch { /* optional */ }

      let genToken: string | null = null;
      try { genToken = await authorizeWithCache(hem, password, 'keymgmt:gen'); } catch { /* optional */ }

      passwordRef.current = password;
      if (sessionStorage.getItem(HSM_PW_KEY)) {
        sessionStorage.setItem(HSM_PW_KEY, password);
      }

      setState(s => ({ ...s, hem, listToken, impToken, genToken, connected: true, unlocked: true, error: null }));
      preloadEncedoPgp();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setState(s => ({ ...s, connected: false, unlocked: false, impToken: null, genToken: null, error: msg }));
      throw e;
    }
  }, [state.url]);

  const disconnect = useCallback(() => {
    sessionStorage.removeItem(HSM_PW_KEY);
    passwordRef.current = '';
    tokenCache.current.clear();
    setState(s => ({
      ...s,
      hem: null, listToken: null, impToken: null, genToken: null,
      connected: false, unlocked: false, error: null,
    }));
  }, []);

  const authorize = useCallback(async (scope: string): Promise<string> => {
    const { hem } = state;
    if (!hem) throw new Error('HSM not connected');
    const pw = passwordRef.current || sessionStorage.getItem(HSM_PW_KEY) || '';
    if (!pw) throw new Error('Password not available — please unlock HSM again');
    return authorizeWithCache(hem, pw, scope);
  }, [state]);

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
