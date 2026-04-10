interface HemKeyI {
  kid: string;
  label: string;
  type: string;         // 'Ed25519' | 'X25519' | ...
  description: Uint8Array | null;  // raw bytes decoded by fromB64 in SDK
}

interface HEMI {
  hemCheckin(): Promise<void>;

  authorizePassword(
    password: string | null,
    scope: string,
    expSeconds?: number
  ): Promise<string>; // returns JWT token; pass null to reuse cached derived keys

  listKeys(token: string, offset?: number, limit?: number): Promise<HemKeyI[]>;

  searchKeys(
    token: string,
    descrBase64: string,
    offset?: number,
    limit?: number
  ): Promise<HemKeyI[]>;

  getPubKey(token: string, kid: string): Promise<string>; // base64 pubkey

  createKeyPair(
    token: string,
    label: string,
    type: string,
    descr: string
  ): Promise<{ kid: string }>;

  importPublicKey(
    token: string,
    label: string,
    type: string,
    pubKeyBytes: Uint8Array,
    descr?: string | null
  ): Promise<{ kid: string }>;

  exdsaSignBytes(
    token: string,
    kid: string,
    data: Uint8Array,
    alg?: string,
    ctx?: string | null
  ): Promise<string>; // base64 signature

  exdsaVerify(
    token: string,
    kid: string,
    data: Uint8Array,
    sig: string,
    alg?: string
  ): Promise<boolean>;

  ecdh(token: string, kid: string, peerPubKeyBase64: string): Promise<string>; // base64 shared secret

  deleteKey(token: string, kid: string): Promise<void>;

  clearCache(): void;

  /** Discard cached derived keys (call on logout). Also clears JWT token cache. */
  clearKeys(): void;
}

declare module '*/hem-sdk.js' {
  export class HemError extends Error {
    code: string;
    status: number;
    data: unknown;
  }

  export type HemKey = HemKeyI;

  export class HEM implements HEMI {
    constructor(hsmUrl: string, opts?: { broker?: string; debug?: boolean });
    hemCheckin(): Promise<void>;
    authorizePassword(password: string | null, scope: string, expSeconds?: number): Promise<string>;
    listKeys(token: string, offset?: number, limit?: number): Promise<HemKeyI[]>;
    searchKeys(token: string, descrBase64: string, offset?: number, limit?: number): Promise<HemKeyI[]>;
    getPubKey(token: string, kid: string): Promise<string>;
    createKeyPair(token: string, label: string, type: string, descr: string): Promise<{ kid: string }>;
    importPublicKey(token: string, label: string, type: string, pubKeyBytes: Uint8Array, descr?: string | null): Promise<{ kid: string }>;
    exdsaSignBytes(token: string, kid: string, data: Uint8Array, alg?: string, ctx?: string | null): Promise<string>;
    exdsaVerify(token: string, kid: string, data: Uint8Array, sig: string, alg?: string): Promise<boolean>;
    ecdh(token: string, kid: string, peerPubKeyBase64: string): Promise<string>;
    deleteKey(token: string, kid: string): Promise<void>;
    clearCache(): void;
    clearKeys(): void;
  }
}

declare module '*/hem-sdk.browser.js' {
  export class HemError extends Error {
    code: string;
    status: number;
    data: unknown;
  }

  export type HemKey = HemKeyI;

  export class HEM implements HEMI {
    constructor(hsmUrl: string, opts?: { broker?: string; debug?: boolean });
    hemCheckin(): Promise<void>;
    authorizePassword(password: string | null, scope: string, expSeconds?: number): Promise<string>;
    listKeys(token: string, offset?: number, limit?: number): Promise<HemKeyI[]>;
    searchKeys(token: string, descrBase64: string, offset?: number, limit?: number): Promise<HemKeyI[]>;
    getPubKey(token: string, kid: string): Promise<string>;
    createKeyPair(token: string, label: string, type: string, descr: string): Promise<{ kid: string }>;
    importPublicKey(token: string, label: string, type: string, pubKeyBytes: Uint8Array, descr?: string | null): Promise<{ kid: string }>;
    exdsaSignBytes(token: string, kid: string, data: Uint8Array, alg?: string, ctx?: string | null): Promise<string>;
    exdsaVerify(token: string, kid: string, data: Uint8Array, sig: string, alg?: string): Promise<boolean>;
    ecdh(token: string, kid: string, peerPubKeyBase64: string): Promise<string>;
    deleteKey(token: string, kid: string): Promise<void>;
    clearCache(): void;
    clearKeys(): void;
  }
}
