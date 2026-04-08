import { createPortal } from 'react-dom';

interface Props {
  open: boolean;
  onClose?: () => void;
  children: React.ReactNode;
  width?: number;
}

/**
 * Portal-based modal — renders into document.body so it always covers
 * the full viewport regardless of the React tree / stacking context.
 * (CustomModal from carbonio-design-system is scoped to its panel container.)
 */
export function ModalDialog({ open, onClose, children, width = 480 }: Props) {
  if (!open) return null;
  return createPortal(
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 1300,
        background: 'rgba(0,0,0,.45)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose?.(); }}
    >
      <div style={{
        background: '#fff',
        borderRadius: 10,
        width,
        maxWidth: '95vw',
        maxHeight: '90vh',
        overflowY: 'auto',
        boxShadow: '0 20px 60px rgba(0,0,0,.25)',
      }}>
        {children}
      </div>
    </div>,
    document.body,
  );
}
