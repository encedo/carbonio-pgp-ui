import React, { useState } from 'react';
import { Button, Checkbox, PasswordInput, Text } from '@zextras/carbonio-design-system';
import { useHsm, HSM_PW_KEY } from '../store/HsmContext';
import { ModalDialog } from './ModalDialog';

interface Props {
  open: boolean;
  onClose: () => void;
  onUnlocked?: () => void;
}

export function HsmPasswordModal({ open, onClose, onUnlocked }: Props) {
  const { connect, error } = useHsm();
  const [password, setPassword] = useState(() => sessionStorage.getItem(HSM_PW_KEY) ?? '');
  const [saveForSession, setSaveForSession] = useState(false);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  async function handleUnlock() {
    if (!password) return;
    setLoading(true);
    setLocalError(null);
    try {
      if (saveForSession) {
        sessionStorage.setItem(HSM_PW_KEY, password);
      }
      await connect(password);
      onUnlocked?.();
      onClose();
    } catch (e) {
      setLocalError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  const displayError = localError ?? error;

  return (
    <ModalDialog open={open} onClose={onClose} width={400}>
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
        <div style={{ marginTop: 16 }}>
          <Checkbox
            label="Save for this browser session"
            value={saveForSession}
            onClick={() => setSaveForSession(v => !v)}
          />
        </div>
        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button label="Cancel" color="secondary" onClick={onClose} disabled={loading} />
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
