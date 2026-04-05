import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
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
  impToken:  string | null;
  genToken:  string | null;
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
export const _singleton = {
  password:   '' as string,
  tokenCache: new Map<string, { token: string; expiresAt: number }>(),
  state: {
    url:       localStorage.getItem(HSM_URL_KEY) ?? '',
    hem:       null,
    listToken: null,
    impToken:  null,
    genToken:  null,
    connected: false,
    unlocked:  false,
    error:     null,
  } as HsmState,
};

// ── Context ───────────────────────────────────────────────────────────────────

const HsmContext = createContext<HsmContextValue | null>(null);

async function authorizeWithCache(hem: InstanceType<typeof HEM>, password: string, scope: string): Promise<string> {
  const cached = _singleton.tokenCache.get(scope);
  if (cached && Date.now() < cached.expiresAt) return cached.token;
  const token = await hem.authorizePassword(password, scope, TOKEN_TTL);
  _singleton.tokenCache.set(scope, { token, expiresAt: Date.now() + TOKEN_TTL * 1000 - 30_000 });
  return token;
}

export function HsmProvider({ children }: { children: React.ReactNode }) {
  // Initialize React state from singleton — picks up state after remount
  const [state, setState] = useState<HsmState>(() => ({ ..._singleton.state }));

  // Keep singleton in sync whenever React state changes
  useEffect(() => {
    _singleton.state = state;
  }, [state]);

  const setUrl = useCallback((url: string) => {
    localStorage.setItem(HSM_URL_KEY, url);
    _singleton.password = '';
    _singleton.tokenCache.clear();
    const next: HsmState = {
      ...state,
      url,
      hem: null, listToken: null, impToken: null, genToken: null,
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

      const listToken = await authorizeWithCache(hem, password, 'keymgmt:list');

      let impToken: string | null = null;
      try { impToken = await authorizeWithCache(hem, password, 'keymgmt:imp'); } catch { /* optional */ }

      let genToken: string | null = null;
      try { genToken = await authorizeWithCache(hem, password, 'keymgmt:gen'); } catch { /* optional */ }

      _singleton.password = password;
      if (sessionStorage.getItem(HSM_PW_KEY)) {
        sessionStorage.setItem(HSM_PW_KEY, password);
      }

      const next: HsmState = {
        ..._singleton.state,
        hem, listToken, impToken, genToken,
        connected: true, unlocked: true, error: null,
      };
      _singleton.state = next;
      setState(next);
      preloadEncedoPgp();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const next: HsmState = {
        ..._singleton.state,
        connected: false, unlocked: false, impToken: null, genToken: null, error: msg,
      };
      _singleton.state = next;
      setState(next);
      throw e;
    }
  }, []);

  const disconnect = useCallback(() => {
    sessionStorage.removeItem(HSM_PW_KEY);
    _singleton.password = '';
    _singleton.tokenCache.clear();
    const next: HsmState = {
      ..._singleton.state,
      hem: null, listToken: null, impToken: null, genToken: null,
      connected: false, unlocked: false, error: null,
    };
    _singleton.state = next;
    setState(next);
  }, []);

  const authorize = useCallback(async (scope: string): Promise<string> => {
    const { hem } = _singleton.state;
    if (!hem) throw new Error('HSM not connected');
    const pw = _singleton.password || sessionStorage.getItem(HSM_PW_KEY) || '';
    if (!pw) throw new Error('Password not available — please unlock HSM again');
    return authorizeWithCache(hem, pw, scope);
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
