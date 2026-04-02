declare module '*/hem-sdk.js' {
  export class HemError extends Error {
    code: string;
    status: number;
    data: unknown;
  }

  export interface HemKey {
    kid: string;
    label: string;
    type: string;         // 'Ed25519' | 'X25519' | ...
    description: Uint8Array | null;  // raw bytes decoded by fromB64 in SDK
  }

  export class HEM {
    constructor(hsmUrl: string, broker?: string, debug?: boolean);

    hemCheckin(): Promise<void>;

    authorizePassword(
      password: string,
      scope: string,
      expSeconds?: number
    ): Promise<string>; // returns JWT token

    listKeys(token: string, offset?: number, limit?: number): Promise<HemKey[]>;

    searchKeys(
      token: string,
      descrBase64: string,
      offset?: number,
      limit?: number
    ): Promise<HemKey[]>;

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

    clearCache(): void;
  }
}
