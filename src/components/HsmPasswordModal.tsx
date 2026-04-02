import React, { useState } from 'react';
import { Button, Checkbox, CustomModal, Padding, PasswordInput, Row, Text } from '@zextras/carbonio-design-system';
import { useHsm, HSM_PW_KEY } from '../store/HsmContext';

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
    <CustomModal open={open} onClose={onClose} size="small">
      <Padding all="large">
        <Text size="large" weight="bold">🔑 Unlock HSM</Text>
        <Padding top="medium" />
        <PasswordInput
          label="HSM Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          autoFocus
          hasError={!!displayError}
          onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') handleUnlock(); }}
        />
        {displayError && (
          <>
            <Padding top="small" />
            <Text size="small" color="error">{displayError}</Text>
          </>
        )}
        <Padding top="medium" />
        <Checkbox
          label="Save for this browser session"
          value={saveForSession}
          onClick={() => setSaveForSession(v => !v)}
        />
        <Padding top="large" />
        <Row mainAlignment="flex-end" gap="8px">
          <Button label="Cancel" color="secondary" onClick={onClose} disabled={loading} />
          <Button
            label="Unlock"
            color="primary"
            onClick={handleUnlock}
            disabled={!password || loading}
            loading={loading}
          />
        </Row>
      </Padding>
    </CustomModal>
  );
}
