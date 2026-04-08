#!/usr/bin/env bash
# install-pgp-ui.sh — Install carbonio-pgp-ui on a Carbonio server
# Copy this script to the server together with carbonio-pgp-ui.zip, then run:
#   sudo bash /tmp/install-pgp-ui.sh
#
# Assumes carbonio-pgp-ui.zip is in the same directory as this script.

set -euo pipefail

IRIS=/opt/zextras/web/iris
ZIP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIP="$ZIP_DIR/carbonio-pgp-ui.zip"

if [[ ! -f "$ZIP" ]]; then
    echo "ERROR: $ZIP not found"
    exit 1
fi

# ── Unzip ────────────────────────────────────────────────────────────────────
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
unzip -q "$ZIP" -d "$TMP"

# ── Read commit hash from component.json ─────────────────────────────────────
COMMIT=$(python3 -c "import json; print(json.load(open('$TMP/dist/component.json'))['commit'])")
echo "==> Installing carbonio-pgp-ui commit ${COMMIT:0:8}..."

# ── Copy files ───────────────────────────────────────────────────────────────
mkdir -p "$IRIS/carbonio-pgp-ui/$COMMIT"
cp -r "$TMP/dist/." "$IRIS/carbonio-pgp-ui/$COMMIT/"
chown -R zextras:zextras "$IRIS/carbonio-pgp-ui/$COMMIT/"
echo "    Files copied to $IRIS/carbonio-pgp-ui/$COMMIT/"

# ── Register in components.json ──────────────────────────────────────────────
python3 << PYEOF
import json

components_path = '$IRIS/components.json'
component_path  = '$IRIS/carbonio-pgp-ui/$COMMIT/component.json'

with open(components_path) as f:
    root = json.load(f)

with open(component_path) as f:
    new = json.load(f)

root['components'] = [x for x in root['components'] if x.get('name') != 'carbonio-pgp-ui']
root['components'].append(new)

with open(components_path, 'w') as f:
    json.dump(root, f, indent=2)

print(f"    Registered: {new['name']} {new['commit'][:8]}")
PYEOF

chown zextras:zextras "$IRIS/components.json"

echo ""
echo "==> Done. Hard-reload the browser (Ctrl+Shift+R) to activate."
echo ""
echo "Rollback if needed:"
echo "  sudo python3 -c \""
echo "  import json; p='$IRIS/components.json'; r=json.load(open(p));"
echo "  r['components']=[x for x in r['components'] if x.get('name')!='carbonio-pgp-ui'];"
echo "  json.dump(r,open(p,'w'))"
echo "  \""
