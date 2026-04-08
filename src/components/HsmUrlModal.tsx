import React, { useState } from 'react';
import { Button, Input, Text } from '@zextras/carbonio-design-system';
import { useHsm } from '../store/HsmContext';
import { ModalDialog } from './ModalDialog';

interface Props {
  open: boolean;
  onClose: () => void;
}

export function HsmUrlModal({ open, onClose }: Props) {
  const { url, setUrl } = useHsm();
  const [draft, setDraft] = useState(url);

  function handleSave() {
    const trimmed = draft.trim().replace(/\/+$/, '');
    if (trimmed) {
      setUrl(trimmed);
    }
    onClose();
  }

  return (
    <ModalDialog open={open} onClose={onClose} width={400}>
      <div style={{ padding: 24 }}>
        <Text size="large" weight="bold">HSM URL</Text>
        <div style={{ marginTop: 16 }}>
          <Input
            label="Encedo HEM address"
            value={draft}
            onChange={e => setDraft(e.target.value)}
            autoFocus
            onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSave(); }}
          />
        </div>
        <div style={{ marginTop: 8 }}>
          <Text size="small" color="secondary">
            Saved to browser localStorage. URL is not sent to the Carbonio server.
          </Text>
        </div>
        <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button label="Cancel" color="secondary" onClick={onClose} />
          <Button label="Save" color="primary" onClick={handleSave} disabled={!draft.trim()} />
        </div>
      </div>
    </ModalDialog>
  );
}
