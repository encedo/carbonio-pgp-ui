/**
 * vks-publish.ts — publish a public key to keys.openpgp.org (VKS).
 *
 * keys.openpgp.org is the keyserver most clients (Thunderbird, GnuPG) query for online key
 * discovery. Publishing there — in addition to our WKD — makes the sender's key verifiable
 * everywhere. Upload binds no address until the owner confirms a verification email, so we
 * upload the cert and then request the verification mail for the address.
 *
 * Both endpoints send `Access-Control-Allow-Origin: *`, so this works from the browser.
 */
import * as openpgp from 'openpgp';

const VKS_BASE = 'https://keys.openpgp.org';

export type VksPublishResult = {
  /** VKS status for the address: 'unpublished' until the verification email is confirmed. */
  status: string;
  /** True if a verification email was requested (owner must click the link). */
  verificationRequested: boolean;
};

export async function publishToVks(certBinary: Uint8Array, email: string): Promise<VksPublishResult> {
  const armored = (await openpgp.readKey({ binaryKey: certBinary })).armor();

  const upRes = await fetch(`${VKS_BASE}/vks/v1/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ keytext: armored }),
  });
  if (!upRes.ok) {
    throw new Error(`keys.openpgp.org upload failed: HTTP ${upRes.status}`);
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const up: any = await upRes.json();
  const token: string | undefined = up?.token;
  const emailLc = email.toLowerCase();
  const status: string = up?.status?.[emailLc] ?? up?.status?.[email] ?? 'unknown';

  // Ask keys.openpgp.org to email a verification link so the address is bound to the key
  // (without it, the key is served by fingerprint only, not by email — clients won't find it).
  let verificationRequested = false;
  if (token && status !== 'published' && status !== 'revoked') {
    try {
      const vRes = await fetch(`${VKS_BASE}/vks/v1/request-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, addresses: [email] }),
      });
      verificationRequested = vRes.ok;
    } catch {
      /* upload still succeeded; verification can be re-requested */
    }
  }

  return { status, verificationRequested };
}
