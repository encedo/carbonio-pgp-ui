import React, { createContext, useCallback, useContext, useState } from 'react';
import { HEM } from '../../../hem-sdk-js/hem-sdk.browser.js';

// ── DESCR helpers (inlined from encedo-pgp-js/keychain.js) ──────────────────

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

// ── Types ────────────────────────────────────────────────────────────────────

export interface HsmState {
  url: string;
  hem: InstanceType<typeof HEM> | null;
  listToken: string | null;  // keymgmt:list token
  impToken: string | null;   // keymgmt:imp token (for importPublicKey)
  connected: boolean;
  unlocked: boolean;
  error: string | null;
}

export interface HsmContextValue extends HsmState {
  setUrl: (url: string) => void;
  connect: (password: string) => Promise<void>;
  disconnect: () => void;
}

// ── Context ──────────────────────────────────────────────────────────────────

const HsmContext = createContext<HsmContextValue | null>(null);

const HSM_URL_KEY = 'pgp-hsm-url';
const HSM_PW_KEY  = 'pgp-hsm-password';

export function HsmProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<HsmState>(() => ({
    url: localStorage.getItem(HSM_URL_KEY) ?? '',
    hem: null,
    listToken: null,
    impToken: null,
    connected: false,
    unlocked: false,
    error: null,
  }));

  const setUrl = useCallback((url: string) => {
    localStorage.setItem(HSM_URL_KEY, url);
    setState(s => ({ ...s, url, hem: null, listToken: null, impToken: null, connected: false, unlocked: false, error: null }));
  }, []);

  const connect = useCallback(async (password: string) => {
    setState(s => ({ ...s, error: null }));
    try {
      const hem = new HEM(state.url);
      await hem.hemCheckin();
      const listToken = await hem.authorizePassword(password, 'keymgmt:list');
      let impToken: string | null = null;
      try {
        impToken = await hem.authorizePassword(password, 'keymgmt:imp');
      } catch { /* import not available — impToken stays null */ }
      setState(s => ({ ...s, hem, listToken, impToken, connected: true, unlocked: true, error: null }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setState(s => ({ ...s, connected: false, unlocked: false, impToken: null, error: msg }));
      throw e;
    }
  }, [state.url]);

  const disconnect = useCallback(() => {
    sessionStorage.removeItem(HSM_PW_KEY);
    setState(s => ({ ...s, hem: null, listToken: null, connected: false, unlocked: false, error: null }));
  }, []);

  return (
    <HsmContext.Provider value={{ ...state, setUrl, connect, disconnect }}>
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
