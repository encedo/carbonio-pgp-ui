/**
 * account-metadata.ts — persist PGP settings on the Carbonio account via Mailbox
 * Metadata (section "encedo-pgp"), so they follow the user across browsers/devices.
 *
 * localStorage stays the synchronous fast path everything reads from; this layer
 * hydrates it from the account at startup and pushes changes back. All calls are
 * best-effort: on any failure the local value is still kept, so the feature never
 * blocks signing/encryption.
 */
import { soapFetchV2 } from '@zextras/carbonio-ui-soap-lib';

// Custom mailbox-metadata sections must use the ZWC namespace prefix ("zwc:") and an
// alphanumeric name — Zimbra/Carbonio rejects other names ("invalid mailbox metadata
// section name").
const SECTION = 'zwc:encedopgp';
const JSNS = 'urn:zimbraMail';

// If the server rejects mailbox metadata (older/locked-down Carbonio), stop calling it
// so we don't spam the console on every change — localStorage keeps the values locally.
let accountSyncDisabled = false;

/** Metadata key for the last-used HSM (HEM) URL. */
export const HSM_URL_META_KEY = 'pgp.hsm.url';

type MetaAttrs = Record<string, string>;

interface GetMetadataReq {
  _jsns: string;
  meta: { section: string };
}
interface GetMetadataRes extends Record<string, unknown> {
  meta?: { section?: string; _attrs?: MetaAttrs } | Array<{ section?: string; _attrs?: MetaAttrs }>;
}
interface ModifyMetadataReq {
  _jsns: string;
  meta: { section: string; _attrs: MetaAttrs };
}

/** Read the PGP metadata section from the account. Returns {} on any failure. */
export async function readPgpAccountMetadata(): Promise<MetaAttrs> {
  if (accountSyncDisabled) return {};
  try {
    const res = await soapFetchV2<GetMetadataReq, GetMetadataRes>('GetMailboxMetadata', {
      _jsns: JSNS,
      meta: { section: SECTION },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = (res as any)?.Body;
    if (!body) return {};
    if ('Fault' in body) {
      accountSyncDisabled = true;
      return {};
    }
    const meta = body.GetMailboxMetadataResponse?.meta;
    const entry = Array.isArray(meta) ? meta[0] : meta;
    return entry?._attrs ?? {};
  } catch {
    accountSyncDisabled = true;
    return {};
  }
}

/** Merge the given keys into the PGP metadata section. Best-effort (never throws). */
export async function writePgpAccountMetadata(attrs: MetaAttrs): Promise<void> {
  if (accountSyncDisabled) return;
  try {
    const res = await soapFetchV2<ModifyMetadataReq, Record<string, unknown>>('ModifyMailboxMetadata', {
      _jsns: JSNS,
      meta: { section: SECTION, _attrs: attrs },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = (res as any)?.Body;
    if (body && 'Fault' in body) accountSyncDisabled = true;
  } catch {
    accountSyncDisabled = true; // stop retrying — localStorage keeps the value locally
  }
}
