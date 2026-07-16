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

const SECTION = 'encedo-pgp';
const JSNS = 'urn:zimbraMail';

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

/** Read the encedo-pgp metadata section from the account. Returns {} on any failure. */
export async function readPgpAccountMetadata(): Promise<MetaAttrs> {
  try {
    const res = await soapFetchV2<GetMetadataReq, GetMetadataRes>('GetMailboxMetadata', {
      _jsns: JSNS,
      meta: { section: SECTION },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = (res as any)?.Body;
    if (!body || 'Fault' in body) return {};
    const meta = body.GetMailboxMetadataResponse?.meta;
    const entry = Array.isArray(meta) ? meta[0] : meta;
    return entry?._attrs ?? {};
  } catch {
    return {};
  }
}

/** Merge the given keys into the encedo-pgp metadata section. Best-effort (never throws). */
export async function writePgpAccountMetadata(attrs: MetaAttrs): Promise<void> {
  try {
    await soapFetchV2<ModifyMetadataReq, Record<string, unknown>>('ModifyMailboxMetadata', {
      _jsns: JSNS,
      meta: { section: SECTION, _attrs: attrs },
    });
  } catch {
    /* best-effort — localStorage keeps the value locally */
  }
}
