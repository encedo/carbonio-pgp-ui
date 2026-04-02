import React, { useCallback, useEffect, useState } from 'react';
import { Button, Icon, Input, Spinner, Text } from '@zextras/carbonio-design-system';
import { HsmProvider, decodeDescr, useHsm, DESCR_PREFIX } from '../store/HsmContext';
import { HsmUrlModal } from '../components/HsmUrlModal';
import { HsmPasswordModal } from '../components/HsmPasswordModal';
import { WkdImportModal } from '../components/WkdImportModal';

// ── Grouped key pair ─────────────────────────────────────────────────────────

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

// ── Styles ───────────────────────────────────────────────────────────────────

const S = {
  card: {
    background: '#fff',
    border: '1px solid #e2e8f0',
    borderRadius: 10,
    marginBottom: 20,
    overflow: 'hidden',
  } as React.CSSProperties,
  cardHeader: {
    padding: '14px 20px',
    borderBottom: '1px solid #e2e8f0',
    background: '#f7fafc',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,
  cardBody: { padding: 20 } as React.CSSProperties,
  cardBodyNoPad: { padding: 0 } as React.CSSProperties,
  tableWrap: { overflowX: 'auto' } as React.CSSProperties,
  table: { width: '100%', borderCollapse: 'collapse' } as React.CSSProperties,
  th: {
    textAlign: 'left',
    fontSize: 11,
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '.05em',
    color: '#718096',
    padding: '0 12px 10px',
    borderBottom: '1px solid #e2e8f0',
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  td: {
    padding: '11px 12px',
    borderBottom: '1px solid #f0f4f8',
    verticalAlign: 'middle',
    fontSize: 13,
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  tdLast: {
    padding: '11px 12px',
    verticalAlign: 'middle',
    fontSize: 13,
    whiteSpace: 'nowrap',
  } as React.CSSProperties,
  mono: { fontFamily: 'monospace', fontSize: 12, color: '#4a5568' } as React.CSSProperties,
  muted: { color: '#a0aec0', fontSize: 12 } as React.CSSProperties,
  badge: (kind: 'connected' | 'disconnected' | 'locked' | 'unlocked') => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: 5,
    padding: '4px 10px',
    borderRadius: 20,
    fontSize: 12,
    fontWeight: 500,
    background: (kind === 'connected' || kind === 'unlocked') ? '#c6f6d5' : kind === 'locked' ? '#fefcbf' : '#fed7d7',
    color:      (kind === 'connected' || kind === 'unlocked') ? '#276749' : kind === 'locked' ? '#744210' : '#9b2c2c',
  } as React.CSSProperties),
  dot: (ok: boolean, color?: string) => ({
    width: 7, height: 7,
    borderRadius: '50%',
    background: color ?? (ok ? '#276749' : '#9b2c2c'),
  } as React.CSSProperties),
  pill: (status: 'published' | 'local') => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 12,
    fontSize: 11,
    fontWeight: 500,
    background: status === 'published' ? '#c6f6d5' : '#e2e8f0',
    color:      status === 'published' ? '#276749' : '#718096',
  } as React.CSSProperties),
  emptyState: {
    textAlign: 'center',
    padding: '28px 0',
    color: '#a0aec0',
    fontSize: 13,
  } as React.CSSProperties,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(iat: number): string {
  return new Date(iat * 1000).toISOString().slice(0, 10);
}

function shortKid(kid: string): string {
  const hex = kid.replace(/[^a-fA-F0-9]/g, '').toUpperCase().slice(0, 16);
  return hex.replace(/(.{4})(?=.)/g, '$1 ');
}

// ── Inner view ───────────────────────────────────────────────────────────────

function PgpSettingsInner() {
  const { url, hem, listToken, connected, unlocked, disconnect } = useHsm();

  const [urlModalOpen, setUrlModalOpen] = useState(false);
  const [pwModalOpen,  setPwModalOpen]  = useState(false);

  const [selfKeys,     setSelfKeys]     = useState<KeyPair[]>([]);
  const [peerKeys,     setPeerKeys]     = useState<PeerKeyPair[]>([]);
  const [loadingKeys,  setLoadingKeys]  = useState(false);
  const [keysError,    setKeysError]    = useState<string | null>(null);

  const [peerEmailInput,  setPeerEmailInput]  = useState('');
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importEmail,     setImportEmail]     = useState('');

  // ── Load keys ───────────────────────────────────────────────────────────

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
          const existing = selfMap.get(k) ?? { email: d.email, iat: d.iat };
          if (d.keyType === 'sign') existing.kidSign = key.kid;
          if (d.keyType === 'ecdh') existing.kidEcdh = key.kid;
          selfMap.set(k, existing);
        } else if (d.role === 'peer') {
          const existing = peerMap.get(d.email) ?? { email: d.email };
          if (d.keyType === 'sign') existing.kidSign = key.kid;
          if (d.keyType === 'ecdh') existing.kidEcdh = key.kid;
          peerMap.set(d.email, existing);
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

  // ── Handlers ────────────────────────────────────────────────────────────

  function handleUnlockClick() {
    if (!url) setUrlModalOpen(true);
    else      setPwModalOpen(true);
  }

  function handleImportClick() {
    const email = peerEmailInput.trim();
    if (!email || !email.includes('@')) return;
    setImportEmail(email);
    setImportModalOpen(true);
  }

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <>
      <style>{`.pgp-row:hover td { background: #f7fafc !important; }`}</style>
      <div style={{ padding: '32px 40px', maxWidth: 1100, overflowY: 'auto' }}>

        {/* Page title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
          <Icon icon="LockOutline" size="large" color="primary" />
          <Text size="large" weight="bold">PGP Encryption</Text>
        </div>

        {/* ── HSM Connection ─────────────────────────────────────────── */}
        <div style={S.card}>
          <div style={S.cardHeader}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon icon="GlobeOutline" size="small" />
              <Text weight="bold">HSM Connection</Text>
            </div>
            <span style={S.badge(connected ? 'connected' : 'disconnected')}>
              <span style={S.dot(connected)} />
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div style={S.cardBody}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <div
                onClick={() => setUrlModalOpen(true)}
                style={{
                  flex: 1,
                  minWidth: 200,
                  fontFamily: 'monospace',
                  fontSize: 13,
                  background: '#f7fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: 6,
                  padding: '8px 12px',
                  cursor: 'pointer',
                  color: url ? '#4a5568' : '#a0aec0',
                }}
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
        <div style={S.card}>
          <div style={S.cardHeader}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon icon="KeyOutline" size="small" />
              <Text weight="bold">My Keys</Text>
            </div>
            <Button label="+ Generate New Key" color="primary" size="small" onClick={() => {}} disabled />
          </div>
          <div style={S.cardBodyNoPad}>
            {loadingKeys ? (
              <div style={{ padding: 24, display: 'flex', justifyContent: 'center' }}>
                <Spinner color="gray" />
              </div>
            ) : keysError ? (
              <div style={{ ...S.emptyState, color: '#c53030' }}>{keysError}</div>
            ) : selfKeys.length === 0 ? (
              <div style={S.emptyState}>
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
                      <tr className="pgp-row" key={`${kp.email}:${kp.iat}`}>
                        <td style={S.td}>{kp.email}</td>
                        <td style={{ ...S.td, ...S.mono }}>{shortKid(kp.kidSign)}</td>
                        <td style={{ ...S.td, ...S.mono }}>{shortKid(kp.kidEcdh)}</td>
                        <td style={{ ...S.td, ...S.muted }}>{formatDate(kp.iat)}</td>
                        <td style={S.td}>
                          <span style={S.pill('local')}>Local only</span>
                        </td>
                        <td style={S.tdLast}>
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
        <div style={S.card}>
          <div style={S.cardHeader}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon icon="PeopleOutline" size="small" />
              <Text weight="bold">Peer Keys</Text>
            </div>
          </div>
          <div style={S.cardBody}>
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

            {peerKeys.length === 0 ? (
              <div style={S.emptyState}>
                {unlocked
                  ? 'No peer keys imported yet. Enter an email and click Import.'
                  : 'Unlock HSM to see imported peer keys.'}
              </div>
            ) : (
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
                      <tr className="pgp-row" key={kp.email}>
                        <td style={S.td}>{kp.email}</td>
                        <td style={{ ...S.td, ...S.mono }}>{kp.kidSign ? shortKid(kp.kidSign) : '—'}</td>
                        <td style={{ ...S.td, ...S.mono }}>{kp.kidEcdh ? shortKid(kp.kidEcdh) : '—'}</td>
                        <td style={S.tdLast}>
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                            <Button label="↻ Refresh" color="secondary" size="small" onClick={() => {}} disabled />
                            <Button label="✕ Remove"  color="error"     size="small" onClick={() => {}} disabled />
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
