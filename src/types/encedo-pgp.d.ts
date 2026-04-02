declare module '*/encedo-pgp.browser.js' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function importKeyFromWKD(hem: any, token: string, email: string): Promise<{ kidSign: string; kidEcdh: string }>;
}
