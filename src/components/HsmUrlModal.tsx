import React, { useState } from 'react';
import { Button, CustomModal, Input, Padding, Row, Text } from '@zextras/carbonio-design-system';
import { useHsm } from '../store/HsmContext';

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
    <CustomModal open={open} onClose={onClose} size="small">
      <Padding all="large">
        <Text size="large" weight="bold">HSM URL</Text>
        <Padding top="medium" />
        <Input
          label="Encedo HEM address"
          value={draft}
          onChange={e => setDraft(e.target.value)}
          autoFocus
          onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSave(); }}
        />
        <Padding top="small" />
        <Text size="small" color="secondary">
          Saved to browser localStorage. URL is not sent to the Carbonio server.
        </Text>
        <Padding top="large" />
        <Row mainAlignment="flex-end" gap="8px">
          <Button label="Cancel" color="secondary" onClick={onClose} />
          <Button label="Save" color="primary" onClick={handleSave} disabled={!draft.trim()} />
        </Row>
      </Padding>
    </CustomModal>
  );
}
