import React, { useCallback, useEffect, useState } from 'react';
import { Button, Icon, Input, Spinner, Text } from '@zextras/carbonio-design-system';
import { decodeDescr, useHsm, DESCR_PREFIX, DESCR, encodeDescr } from '../store/HsmContext';
import { patchWebCrypto } from '../lib/webcrypto-patch';
import { wkdLookupParse } from '../lib/wkd-fetch';
import { HsmUrlModal } from '../components/HsmUrlModal';
import { HsmPasswordModal } from '../components/HsmPasswordModal';
import { WkdImportModal } from '../components/WkdImportModal';
import { KeygenModal } from '../components/KeygenModal';

// ── Types ─────────────────────────────────────────────────────────────────────

interface KeyPair {
  email: string;
  iat: number;
  exp?: number;
  kidSign: string;
  kidEcdh: string;
  fingerprint?: string;
}

interface PeerKeyPair {
  email: string;
  kidSign: string;
  kidEcdh: string;
  fingerprint?: string;
  wkdStatus?: 'ok' | 'obsolete' | 'no-wkd';
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

  pill: (status: 'published' | 'local' | 'checking' | 'mismatch'): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 12,
    fontSize: 11,
    fontWeight: 500,
    background: status === 'published' ? '#c6f6d5' : status === 'checking' ? '#fef9c3' : status === 'mismatch' ? '#fed7d7' : '#e2e8f0',
    color:      status === 'published' ? '#276749' : status === 'checking' ? '#92400e' : status === 'mismatch' ? '#9b2c2c' : '#718096',
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

/** Read Carbonio auth token from browser cookies (ZM_AUTH_TOKEN). */
function getCarbonioAuthToken(): string | undefined {
  const match = document.cookie.match(/(?:^|;\s*)ZM_AUTH_TOKEN=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : undefined;
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

function shortKid(kid: string): string {
  const hex = kid.replace(/[^a-fA-F0-9]/g, '').toUpperCase().slice(0, 16);
  return hex.replace(/(.{4})(?=.)/g, '$1 ');
}

// ── Inner view ────────────────────────────────────────────────────────────────

function PgpSettingsInner() {
  const { url, hem, listToken, genToken, connected, unlocked, disconnect, authorize } = useHsm();

  const [urlModalOpen, setUrlModalOpen] = useState(false);
  const [pwModalOpen,  setPwModalOpen]  = useState(false);
  const [unlockCallback, setUnlockCallback] = useState<(() => void) | null>(null);

  // Register global hook so mails-ui can trigger unlock modal
  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).__encedoPgpRequestUnlock = (onUnlocked: () => void) => {
      setUnlockCallback(() => onUnlocked);
      if (!url) setUrlModalOpen(true);
      else setPwModalOpen(true);
    };
    return () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (window as any).__encedoPgpRequestUnlock;
    };
  }, [url]);

  const [selfKeys,    setSelfKeys]    = useState<KeyPair[]>([]);
  const [peerKeys,    setPeerKeys]    = useState<PeerKeyPair[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [keysError,   setKeysError]   = useState<string | null>(null);

  const [wkdStatuses,    setWkdStatuses]    = useState<Map<string, 'checking' | 'published' | 'local' | 'mismatch'>>(new Map());
  const [publishingEmail, setPublishingEmail] = useState<string | null>(null);
  const [publishError,    setPublishError]    = useState<string | null>(null);

  const [peerEmailInput,  setPeerEmailInput]  = useState('');
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importEmail,     setImportEmail]     = useState('');
  const [keygenModalOpen, setKeygenModalOpen] = useState(false);
  const [removeTarget,    setRemoveTarget]    = useState<PeerKeyPair | null>(null);
  const [removing,        setRemoving]        = useState(false);
  const [removeError,     setRemoveError]     = useState<string | null>(null);
  const [revokeTarget,    setRevokeTarget]    = useState<KeyPair | null>(null);
  const [revoking,        setRevoking]        = useState(false);
  const [revokeError,     setRevokeError]     = useState<string | null>(null);
  const [rotateTarget,    setRotateTarget]    = useState<KeyPair | null>(null);
  const [rotating,        setRotating]        = useState(false);
  const [rotateError,     setRotateError]     = useState<string | null>(null);

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
          const e = selfMap.get(k) ?? { email: d.email, iat: d.iat, exp: d.exp };
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

      const keys = [...selfMap.values()].filter((k): k is KeyPair => !!(k.kidSign && k.kidEcdh));
      setSelfKeys(keys);
      const peers = [...peerMap.values()].filter((k): k is PeerKeyPair => !!(k.kidSign || k.kidEcdh)) as PeerKeyPair[];
      setPeerKeys(peers);

      // Fetch WKD info for peer keys: fingerprint + compare with HSM key to detect obsolete
      for (const peer of peers) {
        (async () => {
          try {
            const info = await wkdLookupParse(peer.email);
            const useToken = await authorize(`keymgmt:use:${peer.kidSign}`);
            const hsmResult = await hem!.getPubKey(useToken, peer.kidSign);
            const hsmB64 = typeof hsmResult === 'string' ? hsmResult : (hsmResult as unknown as { pubkey: string }).pubkey;
            const hsmBytes = Uint8Array.from(atob(hsmB64), c => c.charCodeAt(0));
            const match = hsmBytes.length === info.signRaw32.length &&
              hsmBytes.every((b, i) => b === info.signRaw32[i]);
            setPeerKeys(prev => prev.map(p => p.email === peer.email
              ? { ...p, fingerprint: info.fingerprint, wkdStatus: match ? 'ok' : 'obsolete' }
              : p
            ));
          } catch {
            setPeerKeys(prev => prev.map(p => p.email === peer.email
              ? { ...p, wkdStatus: 'no-wkd' }
              : p
            ));
          }
        })();
      }

      // Check WKD status for each self key — compare WKD key bytes with HSM key bytes
      const initStatuses = new Map<string, 'checking' | 'published' | 'local' | 'mismatch'>();
      for (const k of keys) initStatuses.set(k.email, 'checking');
      setWkdStatuses(initStatuses);

      for (const k of keys) {
        (async () => {
          try {
            const info = await wkdLookupParse(k.email);
            // Store fingerprint on the key entry
            setSelfKeys(prev => prev.map(p =>
              p.email === k.email && p.iat === k.iat ? { ...p, fingerprint: info.fingerprint } : p
            ));
            // Compare WKD public key with HSM public key to detect stale/wrong entries
            const useToken = await authorize(`keymgmt:use:${k.kidSign}`);
            const hsmResult = await hem!.getPubKey(useToken, k.kidSign);
            // getPubKey returns { pubkey: string (base64), ... } despite type declaration
            const hsmB64 = typeof hsmResult === 'string' ? hsmResult : (hsmResult as unknown as { pubkey: string }).pubkey;
            const hsmBytes = Uint8Array.from(atob(hsmB64), c => c.charCodeAt(0));
            const match = hsmBytes.length === info.signRaw32.length &&
              hsmBytes.every((b, i) => b === info.signRaw32[i]);
            setWkdStatuses(prev => {
              const next = new Map(prev);
              next.set(k.email, match ? 'published' : 'mismatch');
              return next;
            });
          } catch {
            setWkdStatuses(prev => {
              const next = new Map(prev);
              next.set(k.email, 'local');
              return next;
            });
          }
        })();
      }
    } catch (e) {
      setKeysError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingKeys(false);
    }
  }, [hem, listToken]);

  useEffect(() => {
    if (unlocked) loadKeys();
    else { setSelfKeys([]); setPeerKeys([]); setWkdStatuses(new Map()); }
  }, [unlocked, loadKeys]);

  // ── Handlers ───────────────────────────────────────────────────────────────

  function handleUnlockClick() {
    if (!url) setUrlModalOpen(true);
    else      setPwModalOpen(true);
  }

  async function handlePublish(kp: KeyPair) {
    if (!hem) return;
    setPublishingEmail(kp.email);
    setPublishError(null);
    try {
      const wkdBase = `https://${window.location.hostname}/wkd`;
      const authToken    = getCarbonioAuthToken();
      const useToken     = await authorize(`keymgmt:use:${kp.kidSign}`);
      const useEcdhToken = await authorize(`keymgmt:use:${kp.kidEcdh}`);
      patchWebCrypto();
      const { buildCertificate, publishKey } = await import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js');
      const { cert } = await buildCertificate(hem, useToken, kp.kidSign, kp.kidEcdh, kp.email, {
        ecdhToken: useEcdhToken, timestamp: kp.iat, expiryTimestamp: kp.exp,
      });
      await publishKey(wkdBase, kp.email, cert, authToken);
      setWkdStatuses(prev => { const next = new Map(prev); next.set(kp.email, 'published'); return next; });
    } catch (e: unknown) {
      setPublishError(e instanceof Error ? e.message : String(e));
    } finally {
      setPublishingEmail(null);
    }
  }

  async function handleRotateConfirm() {
    if (!rotateTarget || !hem || !genToken) return;
    setRotating(true);
    setRotateError(null);
    try {
      const wkdBase = `https://${window.location.hostname}/wkd`;
      // 1. Revoke from WKD (ignore 404)
      const authToken = getCarbonioAuthToken();
      try {
        patchWebCrypto();
        const { revokeKey } = await import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js');
        await revokeKey(wkdBase, rotateTarget.email, authToken);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!msg.includes('404')) throw e;
      }
      // 2. Delete old keys
      const delToken = await authorize('keymgmt:del');
      await hem.deleteKey(delToken, rotateTarget.kidSign);
      await hem.deleteKey(delToken, rotateTarget.kidEcdh);
      // 3. Generate new keys (preserve TTL if known)
      const iat = Math.floor(Date.now() / 1000);
      const exp = rotateTarget.exp ? iat + (rotateTarget.exp - rotateTarget.iat) : undefined;
      const { kid: kidSign } = await hem.createKeyPair(
        genToken, `pgp-sign-${rotateTarget.email}`, 'ED25519',
        encodeDescr(DESCR.selfSign(rotateTarget.email, iat, exp)),
      );
      const { kid: kidEcdh } = await hem.createKeyPair(
        genToken, `pgp-ecdh-${rotateTarget.email}`, 'CURVE25519',
        encodeDescr(DESCR.selfEcdh(rotateTarget.email, iat, exp)),
      );
      // 4. Build cert and publish
      const useToken     = await authorize(`keymgmt:use:${kidSign}`);
      const useEcdhToken = await authorize(`keymgmt:use:${kidEcdh}`);
      patchWebCrypto();
      const { buildCertificate, publishKey } = await import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js');
      const { cert } = await buildCertificate(hem, useToken, kidSign, kidEcdh, rotateTarget.email, {
        ecdhToken: useEcdhToken, timestamp: iat, expiryTimestamp: exp,
      });
      await publishKey(wkdBase, rotateTarget.email, cert, authToken);
      setRotateTarget(null);
      loadKeys();
    } catch (e: unknown) {
      setRotateError(e instanceof Error ? e.message : String(e));
    } finally {
      setRotating(false);
    }
  }

  async function handleRevokeConfirm() {
    if (!revokeTarget || !hem) return;
    setRevoking(true);
    setRevokeError(null);
    try {
      const wkdBase = `https://${window.location.hostname}/wkd`;
      // WKD revoke first — ignore 404 (key may not have been published)
      const authToken = getCarbonioAuthToken();
      try {
        patchWebCrypto();
        const { revokeKey } = await import('../../../encedo-pgp-js/dist/encedo-pgp.browser.js');
        await revokeKey(wkdBase, revokeTarget.email, authToken);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!msg.includes('404')) throw e;
      }
      // Delete both keys from HSM
      const delToken = await authorize('keymgmt:del');
      await hem.deleteKey(delToken, revokeTarget.kidSign);
      await hem.deleteKey(delToken, revokeTarget.kidEcdh);
      setRevokeTarget(null);
      loadKeys();
    } catch (e: unknown) {
      setRevokeError(e instanceof Error ? e.message : String(e));
    } finally {
      setRevoking(false);
    }
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
              <>
                <div style={S.tableWrap}>
                  <table style={S.table}>
                    <thead>
                      <tr>
                        <th style={S.th}>Email</th>
                        <th style={S.th}>Key ID (sign)</th>
                        <th style={S.th}>Key ID (ecdh)</th>
                        <th style={S.th}>Created</th>
                        <th style={S.th}>Expires</th>
                        <th style={S.th}>WKD</th>
                        <th style={S.th}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {selfKeys.map(kp => {
                        const wkdStatus = wkdStatuses.get(kp.email) ?? 'local';
                        const isPublishing = publishingEmail === kp.email;
                        const nb = kp.fingerprint ? { borderBottom: 'none' } : {};
                        const tdB = { ...S.td, ...nb };
                        return (
                          <React.Fragment key={`${kp.email}:${kp.iat}`}>
                            <tr className="pgp-tr">
                              <td style={tdB}>{kp.email}</td>
                              <td style={{ ...tdB, ...S.mono }}>{shortKid(kp.kidSign)}</td>
                              <td style={{ ...tdB, ...S.mono }}>{shortKid(kp.kidEcdh)}</td>
                              <td style={{ ...tdB, ...S.muted }}>{formatDate(kp.iat)}</td>
                              <td style={{ ...tdB, ...S.muted }}>{kp.exp ? formatDate(kp.exp) : '—'}</td>
                              <td style={tdB}>
                                <span style={S.pill(wkdStatus)}>
                                  {wkdStatus === 'checking' ? 'Checking…'
                                    : wkdStatus === 'published' ? 'Published'
                                    : wkdStatus === 'mismatch' ? '⚠ Mismatch'
                                    : 'Local'}
                                </span>
                              </td>
                              <td style={{ ...S.tdActions, ...nb }}>
                                <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                                  {wkdStatus === 'checking' ? (
                                    <Button label="↑ Publish" color="secondary" size="small" disabled onClick={() => {}} />
                                  ) : wkdStatus === 'local' ? (
                                    <Button
                                      label={isPublishing ? 'Publishing…' : '↑ Publish'}
                                      color="secondary" size="small"
                                      disabled={isPublishing}
                                      onClick={() => handlePublish(kp)}
                                    />
                                  ) : wkdStatus === 'mismatch' ? (
                                    <Button
                                      label={isPublishing ? 'Publishing…' : '↑ Re-publish'}
                                      color="warning" size="small"
                                      disabled={isPublishing}
                                      onClick={() => handlePublish(kp)}
                                    />
                                  ) : (
                                    <Button
                                      label="↻ Rotate"
                                      color="secondary" size="small"
                                      disabled={isPublishing || !genToken}
                                      onClick={() => { setRotateError(null); setRotateTarget(kp); }}
                                    />
                                  )}
                                  <Button label="✕ Revoke" color="error" size="small" onClick={() => { setRevokeError(null); setRevokeTarget(kp); }} />
                                </div>
                              </td>
                            </tr>
                            {kp.fingerprint && (
                              <tr>
                                <td colSpan={7} style={{ ...S.td, paddingTop: 0, paddingBottom: 8, fontFamily: 'monospace', fontSize: 11, color: '#a0aec0' }}>
                                  {kp.fingerprint}
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {publishError && (
                  <div style={{ padding: '10px 16px', background: '#fff5f5', borderTop: '1px solid #fed7d7', display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 13, color: '#c53030' }}>
                    <span>Publish failed: {publishError}</span>
                    <Button label="Dismiss" color="secondary" size="small" onClick={() => setPublishError(null)} />
                  </div>
                )}
              </>
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
                      <th style={S.th}>Fingerprint (WKD)</th>
                      <th style={S.th}>Key ID (sign)</th>
                      <th style={S.th}>Key ID (ecdh)</th>
                      <th style={S.th}>Status</th>
                      <th style={S.th}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {peerKeys.map(kp => (
                      <tr className="pgp-tr" key={kp.email}>
                        <td style={S.td}>{kp.email}</td>
                        <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{kp.fingerprint ?? '…'}</td>
                        <td style={{ ...S.td, ...S.mono }}>{kp.kidSign ? shortKid(kp.kidSign) : '—'}</td>
                        <td style={{ ...S.td, ...S.mono }}>{kp.kidEcdh ? shortKid(kp.kidEcdh) : '—'}</td>
                        <td style={S.td}>
                          {kp.wkdStatus === 'obsolete' && <span style={S.pill('mismatch')}>⚠ Obsolete</span>}
                          {kp.wkdStatus === 'ok'       && <span style={S.pill('published')}>✓ Current</span>}
                          {kp.wkdStatus === 'no-wkd'   && <span style={S.pill('local')}>No WKD</span>}
                          {!kp.wkdStatus               && <span style={S.pill('checking')}>Checking…</span>}
                        </td>
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
          onClose={() => { setPwModalOpen(false); setUnlockCallback(null); }}
          onUnlocked={() => { loadKeys(); unlockCallback?.(); setUnlockCallback(null); }}
        />
        <WkdImportModal
          open={importModalOpen}
          email={importEmail}
          onClose={() => setImportModalOpen(false)}
          onImported={() => { setImportModalOpen(false); setPeerEmailInput(''); loadKeys(); }}
          existingKey={peerKeys.find(p => p.email === importEmail)}
        />
        <KeygenModal
          open={keygenModalOpen}
          onClose={() => setKeygenModalOpen(false)}
          onGenerated={loadKeys}
          onPublished={(email) => setWkdStatuses(prev => { const next = new Map(prev); next.set(email, 'published'); return next; })}
          disabledEmails={selfKeys.map(k => k.email)}
        />

        {/* Rotate key confirmation */}
        {rotateTarget && (
          <div style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)',
            zIndex: 200, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <div style={{
              background: '#fff', borderRadius: 10, width: 440, maxWidth: '95vw',
              boxShadow: '0 20px 60px rgba(0,0,0,.2)', overflow: 'hidden',
            }}>
              <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid #e2e8f0' }}>
                <Text size="large" weight="bold">Rotate Key</Text>
              </div>
              <div style={{ padding: 20, fontSize: 13, color: '#4a5568', lineHeight: 1.6 }}>
                <p>Rotate the key for <strong>{rotateTarget.email}</strong>?</p>
                <p style={{ marginTop: 8 }}>
                  This will revoke the current WKD entry, delete both keys from the HSM,
                  generate a new key pair, and publish the new key to WKD.
                </p>
                <p style={{ marginTop: 8, color: '#c53030' }}>
                  ⚠ Emails encrypted to the old key will no longer be decryptable after rotation.
                </p>
                {rotateError && (
                  <p style={{ marginTop: 8, color: '#c53030' }}>{rotateError}</p>
                )}
              </div>
              <div style={{ padding: '14px 20px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <Button label="Cancel"     color="secondary" onClick={() => setRotateTarget(null)} disabled={rotating} />
                <Button label="Rotate Key" color="primary"   onClick={handleRotateConfirm}         disabled={rotating} />
              </div>
            </div>
          </div>
        )}

        {/* Revoke own key confirmation */}
        {revokeTarget && (
          <div style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)',
            zIndex: 200, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <div style={{
              background: '#fff', borderRadius: 10, width: 420, maxWidth: '95vw',
              boxShadow: '0 20px 60px rgba(0,0,0,.2)', overflow: 'hidden',
            }}>
              <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid #e2e8f0' }}>
                <Text size="large" weight="bold">Revoke Key</Text>
              </div>
              <div style={{ padding: 20, fontSize: 13, color: '#4a5568', lineHeight: 1.6 }}>
                <p>Revoke the key for <strong>{revokeTarget.email}</strong>?</p>
                <p style={{ marginTop: 8 }}>
                  This will remove the public key from WKD (if published) and delete both keys from the HSM.
                </p>
                <p style={{ marginTop: 8, color: '#c53030' }}>
                  ⚠ This cannot be undone. Emails encrypted to this key will no longer be decryptable.
                </p>
                {revokeError && (
                  <p style={{ marginTop: 8, color: '#c53030' }}>{revokeError}</p>
                )}
              </div>
              <div style={{ padding: '14px 20px', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <Button label="Cancel"     color="secondary" onClick={() => setRevokeTarget(null)} disabled={revoking} />
                <Button label="Revoke Key" color="error"     onClick={handleRevokeConfirm}         disabled={revoking} />
              </div>
            </div>
          </div>
        )}

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
  return <PgpSettingsInner />;
}
