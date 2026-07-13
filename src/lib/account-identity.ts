/**
 * Minimal shape of the Carbonio account identity list we read. The
 * carbonio-shell-ui types are incomplete, so we type only what we touch instead
 * of depending on ReturnType<typeof useUserAccount>.
 */
interface IdentityAttrs {
  zimbraPrefFromAddress?: string | string[];
  zimbraPrefFromDisplay?: string | string[];
}
interface AccountLike {
  identities?: { identity?: Array<{ _attrs?: IdentityAttrs }> };
}

/**
 * The display name Carbonio has configured for a given From-address, taken from
 * the identity whose `zimbraPrefFromAddress` matches `email`
 * (`zimbraPrefFromDisplay`). Used as the User ID display name when building an
 * OpenPGP certificate, e.g. "Krzysztof Rutecki <krzysztof@encedo.com>".
 *
 * Returns undefined when the address has no identity or no display name set — the
 * cert then falls back to the bare "<email>" UID. We deliberately do not borrow the
 * primary account name for an alias that lacks its own identity, to avoid labelling
 * an address with someone else's / the wrong name.
 */
export function getDisplayNameForEmail(email: string, account: AccountLike | undefined): string | undefined {
  const target = email.trim().toLowerCase();
  for (const identity of account?.identities?.identity ?? []) {
    const from = identity._attrs?.zimbraPrefFromAddress;
    const fromStr = Array.isArray(from) ? from[0] : from;
    if (!fromStr || String(fromStr).toLowerCase() !== target) continue;
    const disp = identity._attrs?.zimbraPrefFromDisplay;
    const dispStr = Array.isArray(disp) ? disp[0] : disp;
    const name = dispStr ? String(dispStr).trim() : '';
    return name || undefined;
  }
  return undefined;
}
