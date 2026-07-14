import React, { useEffect, useRef, useState } from 'react';
import { Button, PasswordInput, Text } from '@zextras/carbonio-design-system';
import { useHsm } from '../store/HsmContext';
import { ModalDialog } from './ModalDialog';

interface Props {
  open: boolean;
  onClose: () => void;
  onUnlocked?: () => void;
}

const CONNECT_TIMEOUT_MS = 5000;

export function HsmPasswordModal({ open, onClose, onUnlocked }: Props) {
  const { connect, error } = useHsm();
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  // Set when the user aborts (ESC / Cancel) so a late-resolving connect() doesn't
  // close the modal or clear state after they've already backed out.
  const cancelledRef = useRef(false);

  async function handleUnlock() {
    if (!password) return;
    cancelledRef.current = false;
    setLoading(true);
    setLocalError(null);
    try {
      await Promise.race([
        connect(password),
        new Promise((_resolve, reject) => {
          setTimeout(
            () => reject(new Error(`Connection timed out after ${CONNECT_TIMEOUT_MS / 1000}s — check HSM URL / network`)),
            CONNECT_TIMEOUT_MS,
          );
        }),
      ]);
      if (cancelledRef.current) return;
      setPassword('');
      onUnlocked?.();
      onClose();
    } catch (e) {
      if (cancelledRef.current) return;
      setLocalError(e instanceof Error ? e.message : String(e));
    } finally {
      if (!cancelledRef.current) setLoading(false);
    }
  }

  // Interrupt a hanging connect and dismiss (ESC or Cancel). Works even while the
  // Unlock request is still in flight so the modal is never stuck.
  function handleCancel() {
    cancelledRef.current = true;
    setLoading(false);
    onClose();
  }

  // ESC dismisses regardless of which control has focus (or none).
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        cancelledRef.current = true;
        setLoading(false);
        onClose();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const displayError = localError ?? error;

  return (
    <ModalDialog open={open} onClose={handleCancel} width={400}>
      <div style={{ padding: '24px' }}>
        <Text size="large" weight="bold">🔑 Unlock HSM</Text>
        <div style={{ marginTop: 16 }}>
          <PasswordInput
            label="HSM Password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            autoFocus
            hasError={!!displayError}
            onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') handleUnlock(); }}
          />
        </div>
        {displayError && (
          <div style={{ marginTop: 8 }}>
            <Text size="small" color="error">{displayError}</Text>
          </div>
        )}
        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button label="Cancel" color="secondary" onClick={handleCancel} />
          <Button
            label="Unlock"
            color="primary"
            onClick={handleUnlock}
            disabled={!password || loading}
            loading={loading}
          />
        </div>
      </div>
    </ModalDialog>
  );
}
