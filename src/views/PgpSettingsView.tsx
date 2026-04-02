import React, { useCallback, useEffect, useState } from 'react';
import { Button, Icon, Input, Spinner, Text } from '@zextras/carbonio-design-system';
import { HsmProvider, decodeDescr, useHsm, DESCR_PREFIX } from '../store/HsmContext';
import { HsmUrlModal } from '../components/HsmUrlModal';
import { HsmPasswordModal } from '../components/HsmPasswordModal';
import { WkdImportModal } from '../components/WkdImportModal';
import { KeygenModal } from '../components/KeygenModal';

// ── Types ─────────────────────────────────────────────────────────────────────

interface KeyPair {
  email: string;
  iat: number;
  kidSign: string;
  kidEcdh: string;
}

interface PeerKeyPair {
  email: string;
  kidSign: string;
  kidEcdh: string;
}

// ── Styles ────────────────────────────────────────────────────────────────────
// Matches Carbonio Settings panel style (flat, white, divider-based)

const S = {
  page: {
    width: '100%',
    boxSizing: 'border-box',
    padding: '24px 32px',
    overflowY: 'auto',
  } as React.CSSProperties,

  section: {
    background: '#fff',
    border: '1px solid #e2e8f0',
    borderRadius: 8,
    marginBottom: 24,
    overflow: 'hidden',
  } as React.CSSProperties,

  sectionHeader: {
    padding: '16px 20px',
    borderBottom: '1px solid #e2e8f0',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,

  sectionTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    fontWeight: 600,
    fontSize: 14,
    color: '#2d3748',
  } as React.CSSProperties,

  sectionBody: { padding: '16px 20px' } as React.CSSProperties,
  sectionBodyNoPad: { padding: 0 } as React.CSSProperties,

  tableWrap: { overflowX: 'auto', paddingTop: 4 } as React.CSSProperties,

  table: { width: '100%', borderCollapse: 'collapse' } as React.CSSProperties,

  th: {
    textAlign: 'left',
    fontSize: 11,
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '.05em',
    color: '#718096',
    padding: '12px 16px 8px',
    borderBottom: '1px solid #e2e8f0',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,

  td: {
    padding: '11px 16px',
    borderBottom: '1px solid #f0f4f8',
    verticalAlign: 'middle',
    fontSize: 13,
    color: '#2d3748',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,

  tdActions: {
    padding: '8px 16px',
    borderBottom: '1px solid #f0f4f8',
    verticalAlign: 'middle',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,

  mono: { fontFamily: 'monospace', fontSize: 12, color: '#4a5568' } as React.CSSProperties,
  muted: { color: '#a0aec0', fontSize: 12 } as React.CSSProperties,

  badge: (kind: 'connected' | 'disconnected' | 'locked' | 'unlocked') => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: 5,
    padding: '3px 10px',
    borderRadius: 20,
    fontSize: 12,
    fontWeight: 500,
    background: (kind === 'connected' || kind === 'unlocked') ? '#c6f6d5' : kind === 'locked' ? '#fefcbf' : '#fed7d7',
    color:      (kind === 'connected' || kind === 'unlocked') ? '#276749' : kind === 'locked' ? '#744210' : '#9b2c2c',
  } as React.CSSProperties),

  dot: (ok: boolean, color?: string): React.CSSProperties => ({
    width: 7, height: 7, borderRadius: '50%',
    background: color ?? (ok ? '#276749' : '#9b2c2c'),
  }),

  pill: (status: 'published' | 'local'): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 12,
    fontSize: 11,
    fontWeight: 500,
    background: status === 'published' ? '#c6f6d5' : '#e2e8f0',
    color:      status === 'published' ? '#276749' : '#718096',
  }),

  emptyState: {
    textAlign: 'center',
    padding: '28px 0',
    color: '#a0aec0',
    fontSize: 13,
  } as React.CSSProperties,

  hsmRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    flexWrap: 'wrap',
  } as React.CSSProperties,

  urlBox: (hasUrl: boolean): React.CSSProperties => ({
    flex: 1,
    minWidth: 220,
    fontFamily: 'monospace',
    fontSize: 13,
    background: '#f7fafc',
    border: '1px solid #e2e8f0',
    borderRadius: 6,
    padding: '7px 12px',
    cursor: 'pointer',
    color: hasUrl ? '#2d3748' : '#a0aec0',
    transition: 'border-color .15s',
  }),
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(iat: number): string {
  return new Date(iat * 1000).toISOString().slice(0, 10);
}

function shortKid(kid: string): string {
  const hex = kid.replace(/[^a-fA-F0-9]/g, '').toUpperCase().slice(0, 16);
  return hex.replace(/(.{4})(?=.)/g, '$1 ');
}

// ── Inner view ────────────────────────────────────────────────────────────────

function PgpSettingsInner() {
  const { url, hem, listToken, connected, unlocked, disconnect, authorize } = useHsm();

  const [urlModalOpen, setUrlModalOpen] = useState(false);
  const [pwModalOpen,  setPwModalOpen]  = useState(false);

  const [selfKeys,    setSelfKeys]    = useState<KeyPair[]>([]);
  const [peerKeys,    setPeerKeys]    = useState<PeerKeyPair[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [keysError,   setKeysError]   = useState<string | null>(null);

  const [peerEmailInput,  setPeerEmailInput]  = useState('');
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importEmail,     setImportEmail]     = useState('');
  const [keygenModalOpen, setKeygenModalOpen] = useState(false);
  const [removeTarget,    setRemoveTarget]    = useState<PeerKeyPair | null>(null);
  const [removing,        setRemoving]        = useState(false);
  const [removeError,     setRemoveError]     = useState<string | null>(null);

  // ── Load keys ──────────────────────────────────────────────────────────────

  const loadKeys = useCallback(async () => {
    if (!hem || !listToken) return;
    setLoadingKeys(true);
    setKeysError(null);
    try {
      const raw = await hem.searchKeys(listToken, DESCR_PREFIX);
      const selfMap = new Map<string, Partial<KeyPair>>();
      const peerMap = new Map<string, Partial<PeerKeyPair>>();

      for (const key of raw) {
        const d = decodeDescr(key);
        if (!d) continue;
        if (d.role === 'self' && d.iat !== undefined) {
          const k = `${d.email}:${d.iat}`;
          const e = selfMap.get(k) ?? { email: d.email, iat: d.iat };
          if (d.keyType === 'sign') e.kidSign = key.kid;
          if (d.keyType === 'ecdh') e.kidEcdh = key.kid;
          selfMap.set(k, e);
        } else if (d.role === 'peer') {
          const e = peerMap.get(d.email) ?? { email: d.email };
          if (d.keyType === 'sign') e.kidSign = key.kid;
          if (d.keyType === 'ecdh') e.kidEcdh = key.kid;
          peerMap.set(d.email, e);
        }
      }

      setSelfKeys(
        [...selfMap.values()].filter((k): k is KeyPair => !!(k.kidSign && k.kidEcdh))
      );
      setPeerKeys(
        [...peerMap.values()].filter((k): k is PeerKeyPair => !!(k.kidSign || k.kidEcdh)) as PeerKeyPair[]
      );
    } catch (e) {
      setKeysError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingKeys(false);
    }
  }, [hem, listToken]);

  useEffect(() => {
    if (unlocked) loadKeys();
    else { setSelfKeys([]); setPeerKeys([]); }
  }, [unlocked, loadKeys]);

  // ── Handlers ───────────────────────────────────────────────────────────────

  function handleUnlockClick() {
    if (!url) setUrlModalOpen(true);
    else      setPwModalOpen(true);
  }

  async function handleRemoveConfirm() {
    if (!removeTarget || !hem) return;
    setRemoving(true);
    setRemoveError(null);
    try {
      const delToken = await authorize('keymgmt:del');
      if (removeTarget.kidSign) await hem.deleteKey(delToken, removeTarget.kidSign);
      if (removeTarget.kidEcdh) await hem.deleteKey(delToken, removeTarget.kidEcdh);
      setRemoveTarget(null);
      loadKeys();
    } catch (e: unknown) {
      setRemoveError(e instanceof Error ? e.message : String(e));
    } finally {
      setRemoving(false);
    }
  }

  function handleImportClick() {
    const email = peerEmailInput.trim();
    if (!email.includes('@')) return;
    setImportEmail(email);
    setImportModalOpen(true);
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <>
      <style>{`.pgp-tr:hover td { background: #f7fafc; }`}</style>
      <div style={S.page}>

        {/* Page title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
          <Icon icon="LockOutline" size="large" color="primary" />
          <Text size="large" weight="bold">PGP Encryption</Text>
        </div>

        {/* ── HSM Connection ─────────────────────────────────────────── */}
        <div style={S.section}>
          <div style={S.sectionHeader}>
            <div style={S.sectionTitle}>
              <Icon icon="GlobeOutline" size="small" />
              HSM Connection
            </div>
            <span style={S.badge(connected ? 'connected' : 'disconnected')}>
              <span style={S.dot(connected)} />
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div style={S.sectionBody}>
            <div style={S.hsmRow}>
              <div
                style={S.urlBox(!!url)}
                onClick={() => setUrlModalOpen(true)}
                title="Click to change HSM URL"
              >
                {url || 'Click to set HSM URL…'}
              </div>

              {unlocked ? (
                <>
                  <span style={S.badge('unlocked')}>
                    <span style={S.dot(true)} />
                    Unlocked
                  </span>
                  <Button label="Lock"         color="secondary" onClick={disconnect}               size="small" />
                  <Button label="Refresh keys" color="secondary" onClick={loadKeys}                 size="small" />
                </>
              ) : (
                <>
                  <span style={S.badge('locked')}>
                    <span style={S.dot(false, '#744210')} />
                    Locked
                  </span>
                  <Button label="Unlock" color="primary" onClick={handleUnlockClick} size="small" />
                </>
              )}

              <Button label="Change URL" color="secondary" onClick={() => setUrlModalOpen(true)} size="small" />
            </div>
          </div>
        </div>

        {/* ── My Keys ────────────────────────────────────────────────── */}
        <div style={S.section}>
          <div style={S.sectionHeader}>
            <div style={S.sectionTitle}>
              <Icon icon="KeyOutline" size="small" />
              My Keys
            </div>
            <Button
              label="+ Generate New Key"
              color="primary"
              size="small"
              onClick={() => setKeygenModalOpen(true)}
              disabled={!unlocked}
            />
          </div>
          <div style={S.sectionBodyNoPad}>
            {loadingKeys ? (
              <div style={{ padding: 24, display: 'flex', justifyContent: 'center' }}>
                <Spinner color="gray" />
              </div>
            ) : keysError ? (
              <div style={{ ...S.emptyState, color: '#c53030', padding: '20px 24px' }}>{keysError}</div>
            ) : selfKeys.length === 0 ? (
              <div style={{ ...S.emptyState, padding: '24px' }}>
                {unlocked
                  ? 'No PGP keys found on HSM. Generate a key pair to get started.'
                  : 'Unlock HSM to see your keys.'}
              </div>
            ) : (
              <div style={S.tableWrap}>
                <table style={S.table}>
                  <thead>
                    <tr>
                      <th style={S.th}>Email</th>
                      <th style={S.th}>Key ID (sign)</th>
                      <th style={S.th}>Key ID (ecdh)</th>
                      <th style={S.th}>Created</th>
                      <th style={S.th}>WKD</th>
                      <th style={S.th}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {selfKeys.map(kp => (
                      <tr className="pgp-tr" key={`${kp.email}:${kp.iat}`}>
                        <td style={S.td}>{kp.email}</td>
                        <td style={{ ...S.td, ...S.mono }}>{shortKid(kp.kidSign)}</td>
                        <td style={{ ...S.td, ...S.mono }}>{shortKid(kp.kidEcdh)}</td>
                        <td style={{ ...S.td, ...S.muted }}>{formatDate(kp.iat)}</td>
                        <td style={S.td}>
                          <span style={S.pill('local')}>Local only</span>
                        </td>
                        <td style={S.tdActions}>
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                            <Button label="↑ Publish" color="secondary" size="small" onClick={() => {}} disabled />
                            <Button label="✕ Revoke"  color="error"     size="small" onClick={() => {}} disabled />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* ── Peer Keys ──────────────────────────────────────────────── */}
        <div style={S.section}>
          <div style={S.sectionHeader}>
            <div style={S.sectionTitle}>
              <Icon icon="PeopleOutline" size="small" />
              Peer Keys
            </div>
          </div>
          <div style={S.sectionBody}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 16 }}>
              <div style={{ flex: 1 }}>
                <Input
                  label="alice@example.com"
                  value={peerEmailInput}
                  onChange={e => setPeerEmailInput(e.target.value)}
                  onKeyDown={(e: React.KeyboardEvent) => { if (e.key === 'Enter') handleImportClick(); }}
                />
              </div>
              <Button
                label="⬇ Import from WKD"
                color="primary"
                onClick={handleImportClick}
                disabled={!unlocked || !peerEmailInput.trim().includes('@')}
              />
            </div>

            {peerKeys.length > 0 ? (
              <div style={S.tableWrap}>
                <table style={S.table}>
                  <thead>
                    <tr>
                      <th style={S.th}>Email</th>
                      <th style={S.th}>Key ID (sign)</th>
                      <th style={S.th}>Key ID (ecdh)</th>
                      <th style={S.th}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {peerKeys.map(kp => (
                      <tr className="pgp-tr" key={kp.email}>
                        <td style={S.td}>{kp.email}</td>
                        <td style={{ ...S.td, ...S.mono }}>{kp.kidSign ? shortKid(kp.kidSign) : '—'}</td>
                        <td style={{ ...S.td, ...S.mono }}>{kp.kidEcdh ? shortKid(kp.kidEcdh) : '—'}</td>
                        <td style={S.tdActions}>
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                            <Button
                              label="✕ Remove"
                              color="error"
                              size="small"
                              onClick={() => { setRemoveError(null); setRemoveTarget(kp); }}
                            />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={S.emptyState}>
                {unlocked
                  ? 'No peer keys imported yet. Enter an email and click Import.'
                  : 'Unlock HSM to see imported peer keys.'}
              </div>
            )}
          </div>
        </div>

        {/* Modals */}
        <HsmUrlModal
          open={urlModalOpen}
          onClose={() => setUrlModalOpen(false)}
        />
        <HsmPasswordModal
          open={pwModalOpen}
          onClose={() => setPwModalOpen(false)}
          onUnlocked={loadKeys}
        />
        <WkdImportModal
          open={importModalOpen}
          email={importEmail}
          onClose={() => setImportModalOpen(false)}
          onImported={() => { setImportModalOpen(false); setPeerEmailInput(''); loadKeys(); }}
        />
        <KeygenModal
          open={keygenModalOpen}
          onClose={() => setKeygenModalOpen(false)}
          onGenerated={loadKeys}
        />

        {/* Remove peer key confirmation */}
        {removeTarget && (
          <div style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)',
            zIndex: 200, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <div style={{
              background: '#fff', borderRadius: 10, width: 420, maxWidth: '95vw',
              boxShadow: '0 20px 60px rgba(0,0,0,.2)', overflow: 'hidden',
            }}>
              <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid #e2e8f0' }}>
                <Text size="large" weight="bold">Remove Peer Key</Text>
              </div>
              <div style={{ padding: 20, fontSize: 13, color: '#4a5568', lineHeight: 1.6 }}>
                <p>Remove the key for <strong>{removeTarget.email}</strong> from the HSM?</p>
                <p style={{ marginTop: 8, color: '#c53030' }}>
                  ⚠ This cannot be undone. You will no longer be able to encrypt messages to this recipient using HSM.
                </p>
                {removeError && (
                  <p style={{ marginTop: 8, color: '#c53030' }}>{removeError}</p>
                )}
              </div>
              <div style={{ padding: '14px 20px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <Button label="Cancel"     color="secondary" onClick={() => setRemoveTarget(null)} disabled={removing} />
                <Button label="Remove Key" color="error"     onClick={handleRemoveConfirm}         disabled={removing} />
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

// ── Exported component ────────────────────────────────────────────────────────

export function PgpSettingsView() {
  return (
    <HsmProvider>
      <PgpSettingsInner />
    </HsmProvider>
  );
}
