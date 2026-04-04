declare module '*/encedo-pgp.browser.js' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function importKeyFromWKD(hem: any, token: string, email: string): Promise<{ kidSign: string; kidEcdh: string }>;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function buildCertificate(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    hem: any,
    signToken: string,
    kidSign: string,
    kidEcdh: string,
    email: string,
    opts?: { ecdhToken?: string; timestamp?: number; expiryTimestamp?: number }
  ): Promise<{ cert: Uint8Array }>;

  export function publishKey(wkdBase: string, email: string, cert: Uint8Array): Promise<void>;

  export function revokeKey(wkdBase: string, email: string): Promise<void>;
}
