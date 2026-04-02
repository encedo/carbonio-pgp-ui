import React, { useEffect, useState } from 'react';
import { Button, CustomModal, Padding, Text } from '@zextras/carbonio-design-system';
import { useHsm } from '../store/HsmContext';
import { importKeyFromWKD } from '../../../encedo-pgp-js/dist/encedo-pgp.browser.js';

interface Props {
  open: boolean;
  email: string;
  onClose: () => void;
  onImported: () => void;
}

type Phase = 'fetching' | 'done' | 'error';

export function WkdImportModal({ open, email, onClose, onImported }: Props) {
  const { hem, impToken } = useHsm();
  const [phase, setPhase] = useState<Phase>('fetching');
  const [error, setError] = useState<string | null>(null);

  const domain = email.split('@')[1] ?? email;

  useEffect(() => {
    if (!open) return;
    if (!hem || !impToken) {
      setPhase('error');
      setError('HSM not unlocked or import not authorized.');
      return;
    }
    setPhase('fetching');
    setError(null);
    importKeyFromWKD(hem, impToken, email)
      .then(() => {
        setPhase('done');
        onImported();
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : String(e));
        setPhase('error');
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, email]);

  return (
    <>
      <style>{`@keyframes pgp-spin { to { transform: rotate(360deg); } }`}</style>
      <CustomModal open={open} onClose={onClose} size="small">
        <Padding all="large">
          <Text size="large" weight="bold">Import Peer Key from WKD</Text>
          <Padding top="medium" />
          <Text>
            Looking up key for <strong>{email}</strong> via Web Key Directory…
          </Text>
          <Padding top="medium" />

          {phase === 'fetching' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#718096', fontSize: 13 }}>
              <div style={{
                width: 18, height: 18,
                border: '2px solid #90cdf4',
                borderTopColor: '#2b6cb0',
                borderRadius: '50%',
                animation: 'pgp-spin 1s linear infinite',
                flexShrink: 0,
              }} />
              Fetching from openpgpkey.{domain}…
            </div>
          )}

          {phase === 'done' && (
            <Text color="success">Key imported successfully to HSM.</Text>
          )}

          {phase === 'error' && (
            <Text color="error">{error}</Text>
          )}

          <Padding top="large" />
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button label="Close" color="secondary" onClick={onClose} disabled={phase === 'fetching'} />
          </div>
        </Padding>
      </CustomModal>
    </>
  );
}
