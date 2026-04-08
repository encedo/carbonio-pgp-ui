import { useEffect, useState } from 'react';
import { Button, Text } from '@zextras/carbonio-design-system';
import { useHsm, encodeDescr } from '../store/HsmContext';
import { wkdLookupParse, WkdKeyInfo } from '../lib/wkd-fetch';
import { ModalDialog } from './ModalDialog';

// DESCR schema (mirrors keychain.js — ETSPGP:peer,<email>,sign/ecdh)
const peerSignDescr = (email: string) => encodeDescr(`ETSPGP:peer,${email},sign`);
const peerEcdhDescr = (email: string) => encodeDescr(`ETSPGP:peer,${email},ecdh`);

interface Props {
  open: boolean;
  email: string;
  onClose: () => void;
  onImported: () => void;
}

type Phase = 'fetching' | 'found' | 'importing' | 'done' | 'error';

const ROW: React.CSSProperties = {
  display: 'flex', gap: 32, fontSize: 13, marginTop: 12, flexWrap: 'wrap',
};
const LABEL: React.CSSProperties = {
  fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
  letterSpacing: '.05em', color: '#718096', marginBottom: 3,
};
const MONO: React.CSSProperties = {
  fontFamily: 'monospace', fontSize: 12, color: '#2d3748',
  background: '#f7fafc', border: '1px solid #e2e8f0',
  borderRadius: 4, padding: '3px 6px', display: 'inline-block',
};

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

export function WkdImportModal({ open, email, onClose, onImported }: Props) {
  const { hem, authorize } = useHsm();
  const [phase,   setPhase]  = useState<Phase>('fetching');
  const [keyInfo, setKeyInfo] = useState<WkdKeyInfo | null>(null);
  const [error,   setError]   = useState<string | null>(null);
  const domain = email.split('@')[1] ?? email;

  useEffect(() => {
    if (!open) return;
    setPhase('fetching');
    setKeyInfo(null);
    setError(null);

    wkdLookupParse(email)
      .then(info => { setKeyInfo(info); setPhase('found'); })
      .catch((e: unknown) => { setError(e instanceof Error ? e.message : String(e)); setPhase('error'); });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, email]);

  async function handleImport() {
    if (!keyInfo || !hem) return;
    setPhase('importing');
    try {
      const impToken = await authorize('keymgmt:imp');
      const signLabel = email.slice(0, 32);
      const ecdhLabel = `${email.slice(0, 28)}/E`;
      await hem.importPublicKey(impToken, signLabel, 'ED25519',   keyInfo.signRaw32, peerSignDescr(email));
      await hem.importPublicKey(impToken, ecdhLabel, 'CURVE25519', keyInfo.ecdhRaw32, peerEcdhDescr(email));
      setPhase('done');
      onImported();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase('error');
    }
  }

  const busy = phase === 'fetching' || phase === 'importing';

  return (
    <ModalDialog open={open} onClose={busy ? undefined : onClose} width={520}>
      <div style={{ padding: 24 }}>
        <Text size="large" weight="bold">Import Peer Key from WKD</Text>
        <div style={{ marginTop: 16 }}>

          {phase === 'fetching' && (
            <>
              <Text>Looking up key for <strong>{email}</strong> via Web Key Directory…</Text>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#718096', fontSize: 13, marginTop: 16 }}>
                <Spinner />
                Fetching from openpgpkey.{domain}…
              </div>
            </>
          )}

          {phase === 'found' && keyInfo && (
            <>
              <Text>Found PGP key for <strong>{email}</strong>. Import to HSM?</Text>
              <div style={ROW}>
                <div>
                  <div style={LABEL}>Ed25519 (sign)</div>
                  <span style={MONO}>{keyInfo.signHex}</span>
                </div>
                <div>
                  <div style={LABEL}>X25519 (ecdh)</div>
                  <span style={MONO}>{keyInfo.ecdhHex}</span>
                </div>
              </div>
            </>
          )}

          {phase === 'importing' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#718096', fontSize: 13 }}>
              <Spinner />
              Importing keys to HSM…
            </div>
          )}

          {phase === 'done' && (
            <Text color="success">Keys imported successfully to HSM.</Text>
          )}

          {phase === 'error' && (
            <Text color="error">{error}</Text>
          )}
        </div>

        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          {phase === 'found' && (
            <>
              <Button label="Cancel"        color="secondary" onClick={onClose}      />
              <Button label="Import to HSM" color="primary"   onClick={handleImport} />
            </>
          )}
          {(phase === 'done' || phase === 'error' || phase === 'fetching') && (
            <Button label="Close" color="secondary" onClick={onClose} disabled={busy} />
          )}
        </div>
      </div>
    </ModalDialog>
  );
}
