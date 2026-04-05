import { useEffect, useState } from 'react';
import { Button, CustomModal, Padding, Text } from '@zextras/carbonio-design-system';
// @ts-expect-error — carbonio-shell-ui types incomplete but these hooks exist at runtime
import { useUserAccount, useUserSettings } from '@zextras/carbonio-shell-ui';
import { useHsm, DESCR, encodeDescr } from '../store/HsmContext';
import { patchWebCrypto } from '../lib/webcrypto-patch';

// ── Styles ────────────────────────────────────────────────────────────────────

const LABEL: React.CSSProperties = {
  display: 'block',
  fontSize: 12,
  fontWeight: 500,
  color: '#4a5568',
  marginBottom: 6,
};

const SELECT: React.CSSProperties = {
  width: '100%',
  padding: '8px 12px',
  border: '1px solid #e2e8f0',
  borderRadius: 6,
  fontSize: 13,
  color: '#2d3748',
  background: '#fff',
  cursor: 'pointer',
  outline: 'none',
};

const INFO_BOX: React.CSSProperties = {
  background: '#ebf8ff',
  border: '1px solid #bee3f8',
  borderRadius: 6,
  padding: '10px 14px',
  fontSize: 12,
  color: '#2b6cb0',
  lineHeight: 1.5,
  marginBottom: 16,
};

const MONO: React.CSSProperties = {
  fontFamily: 'monospace',
  fontSize: 12,
  color: '#2d3748',
  background: '#f7fafc',
  border: '1px solid #e2e8f0',
  borderRadius: 4,
  padding: '3px 6px',
  display: 'inline-block',
};

const SUCCESS_BOX: React.CSSProperties = {
  background: '#f0fff4',
  border: '1px solid #9ae6b4',
  borderRadius: 6,
  padding: '12px 16px',
  fontSize: 13,
  color: '#276749',
};

// ── Expiry options ────────────────────────────────────────────────────────────

const EXPIRY_OPTIONS = [
  { label: 'No expiry',  years: 0 },
  { label: '1 year',     years: 1 },
  { label: '2 years',    years: 2 },
  { label: '3 years',    years: 3 },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function getAccountEmails(account: ReturnType<typeof useUserAccount>, settings: ReturnType<typeof useUserSettings>): string[] {
  const emails = new Set<string>();

  // Primary email
  if (account.name) emails.add(account.name);

  // Aliases from settings
  const aliases = settings.attrs.zimbraMailAlias;
  if (typeof aliases === 'string') emails.add(aliases);
  else if (Array.isArray(aliases)) aliases.forEach(a => emails.add(a));

  const allowFrom = settings.attrs.zimbraAllowFromAddress;
  if (typeof allowFrom === 'string') emails.add(allowFrom);
  else if (Array.isArray(allowFrom)) allowFrom.forEach(a => emails.add(a));

  // Identities
  for (const identity of account.identities?.identity ?? []) {
    const from = identity._attrs?.zimbraPrefFromAddress;
    if (from) emails.add(from);
  }

  return [...emails].filter(e => e.includes('@'));
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface Props {
  open: boolean;
  onClose: () => void;
  onGenerated: () => void;
  onPublished?: (email: string) => void;  // called after successful WKD publish
  disabledEmails?: string[];  // emails that already have keys — excluded from dropdown
}

interface GeneratedKey {
  kidSign: string;
  kidEcdh: string;
  email: string;
  cert: Uint8Array;
}

type Phase = 'form' | 'generating' | 'done' | 'error';

function Spinner() {
  return (
    <>
      <style>{`@keyframes pgp-spin { to { transform: rotate(360deg); } }`}</style>
      <div style={{
        width: 18, height: 18, flexShrink: 0,
        border: '2px solid #bee3f8', borderTopColor: '#2b6cb0',
        borderRadius: '50%', animation: 'pgp-spin 1s linear infinite',
      }} />
    </>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export function KeygenModal({ open, onClose, onGenerated, onPublished, disabledEmails = [] }: Props) {
  const { hem, genToken, authorize } = useHsm();

  const account  = useUserAccount();
  const settings = useUserSettings();

  const allEmails     = getAccountEmails(account, settings);
  const availableEmails = allEmails.filter(e => !disabledEmails.includes(e));
  const wkdBase = `https://${window.location.hostname}/wkd`;

  const [email,      setEmail]      = useState('');
  const [expiryYears, setExpiryYears] = useState(2);
  const [phase,      setPhase]      = useState<Phase>('form');
  const [error,      setError]      = useState<string | null>(null);
  const [generated,  setGenerated]  = useState<GeneratedKey | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [published,  setPublished]  = useState(false);

  // Set default email when modal opens
  useEffect(() => {
    if (open) {
      setEmail(availableEmails[0] ?? '');
      setPhase('form');
      setError(null);
      setGenerated(null);
      setPublished(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // ── Keygen ────────────────────────────────────────────────────────────────

  async function handleGenerate() {
    if (!hem || !genToken) { setError('HSM not ready'); return; }
    setPhase('generating');
    setError(null);
    try {
      const iat = Math.floor(Date.now() / 1000);
      const exp = expiryYears > 0 ? iat + expiryYears * 365 * 24 * 3600 : undefined;

      // Generate keys on HSM
      const { kid: kidSign } = await hem.createKeyPair(
        genToken,
        `pgp-sign-${email}`,
        'ED25519',
        encodeDescr(DESCR.selfSign(email, iat, exp)),
      );
      const { kid: kidEcdh } = await hem.createKeyPair(
        genToken,
        `pgp-ecdh-${email}`,
        'CURVE25519',
        encodeDescr(DESCR.selfEcdh(email, iat, exp)),
      );

      // Get per-key use tokens and build OpenPGP certificate
      const useToken     = await authorize(`keymgmt:use:${kidSign}`);
      const useEcdhToken = await authorize(`keymgmt:use:${kidEcdh}`);

      patchWebCrypto();
      const { buildCertificate } = await import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js');
      const { cert } = await buildCertificate(
        hem, useToken, kidSign, kidEcdh, email,
        { ecdhToken: useEcdhToken, timestamp: iat, expiryTimestamp: exp },
      );

      setGenerated({ kidSign, kidEcdh, email, cert });
      setPhase('done');
      onGenerated();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase('error');
    }
  }

  // ── WKD Publish ───────────────────────────────────────────────────────────

  async function handlePublish() {
    if (!generated) return;
    setPublishing(true);
    try {
      patchWebCrypto();
      const authToken = document.cookie.match(/(?:^|;\s*)ZM_AUTH_TOKEN=([^;]+)/)?.[1];
      const { publishKey } = await import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js');
      await publishKey(wkdBase, generated.email, generated.cert, authToken ? decodeURIComponent(authToken) : undefined);
      setPublished(true);
      onPublished?.(generated.email);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPublishing(false);
    }
  }

  const busy = phase === 'generating' || publishing;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <CustomModal open={open} onClose={busy ? undefined : onClose} size="medium">
      <Padding all="large">
        <Text size="large" weight="bold">Generate New PGP Key</Text>
        <Padding top="medium" />

        {/* ── Form ── */}
        {phase === 'form' && (
          <>
            <div style={INFO_BOX}>
              Two key pairs will be generated on the HSM: <strong>Ed25519</strong> (signing) and{' '}
              <strong>X25519</strong> (encryption). Private keys never leave the device.
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={LABEL}>Email address</label>
              {availableEmails.length > 1 ? (
                <select style={SELECT} value={email} onChange={e => setEmail(e.target.value)}>
                  {availableEmails.map(e => <option key={e} value={e}>{e}</option>)}
                </select>
              ) : availableEmails.length === 0 ? (
                <div style={{ ...SELECT, background: '#f7fafc', cursor: 'default', color: '#a0aec0' }}>
                  All email addresses already have keys
                </div>
              ) : (
                <div style={{ ...SELECT, background: '#f7fafc', cursor: 'default', color: '#4a5568' }}>
                  {email || '—'}
                </div>
              )}
            </div>

            <div style={{ marginBottom: 8 }}>
              <label style={LABEL}>Expiry</label>
              <select
                style={SELECT}
                value={expiryYears}
                onChange={e => setExpiryYears(Number(e.target.value))}
              >
                {EXPIRY_OPTIONS.map(o => (
                  <option key={o.years} value={o.years}>{o.label}</option>
                ))}
              </select>
            </div>
          </>
        )}

        {/* ── Generating ── */}
        {phase === 'generating' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#718096', fontSize: 13 }}>
            <Spinner />
            Generating keys on HSM…
          </div>
        )}

        {/* ── Done ── */}
        {phase === 'done' && generated && (
          <>
            <div style={SUCCESS_BOX}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>Keys generated successfully</div>
              <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', fontSize: 12 }}>
                <div>
                  <div style={{ color: '#276749', marginBottom: 3 }}>Ed25519 (sign)</div>
                  <span style={MONO}>{generated.kidSign.replace(/(.{8})(?=.)/g, '$1 ').slice(0, 19)}</span>
                </div>
                <div>
                  <div style={{ color: '#276749', marginBottom: 3 }}>X25519 (ecdh)</div>
                  <span style={MONO}>{generated.kidEcdh.replace(/(.{8})(?=.)/g, '$1 ').slice(0, 19)}</span>
                </div>
              </div>
            </div>

            <Padding top="medium" />

            {!published ? (
              <>
                <Text>Publish public key to WKD so others can send you encrypted mail?</Text>
                <Padding top="small" />
                <Text size="small" color="secondary">
                  Will be published to: {wkdBase}/api/publish
                </Text>
                {error && (
                  <>
                    <Padding top="small" />
                    <Text color="error" size="small">{error}</Text>
                  </>
                )}
              </>
            ) : (
              <Text color="success">Key published to WKD successfully.</Text>
            )}
          </>
        )}

        {/* ── Error ── */}
        {phase === 'error' && (
          <Text color="error">{error}</Text>
        )}

        <Padding top="large" />
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          {phase === 'form' && (
            <>
              <Button label="Cancel"          color="secondary" onClick={onClose} />
              <Button
                label="Generate on HSM"
                color="primary"
                onClick={handleGenerate}
                disabled={!email || !genToken}
              />
            </>
          )}
          {phase === 'generating' && (
            <Button label="Cancel" color="secondary" onClick={onClose} disabled />
          )}
          {phase === 'done' && !published && (
            <>
              <Button label="Skip"            color="secondary" onClick={onClose}       disabled={publishing} />
              <Button
                label={publishing ? 'Publishing…' : '↑ Publish to WKD'}
                color="primary"
                onClick={handlePublish}
                disabled={publishing}
              />
            </>
          )}
          {(phase === 'done' && published) || phase === 'error' ? (
            <Button label="Close" color="secondary" onClick={onClose} />
          ) : null}
        </div>
      </Padding>
    </CustomModal>
  );
}
