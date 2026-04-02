#!/usr/bin/env bash
# build-zip.sh — Build carbonio-pgp-ui and package into a ZIP for deployment
# Usage: bash build-zip.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building..."
npm run build

echo "==> Packaging..."
rm -f carbonio-pgp-ui.zip
zip -r carbonio-pgp-ui.zip dist/ install-pgp-ui.sh

COMMIT=$(git rev-parse HEAD)
SIZE=$(du -sh carbonio-pgp-ui.zip | cut -f1)
echo ""
echo "Done: carbonio-pgp-ui.zip ($SIZE)"
echo "Commit: $COMMIT"
echo ""
echo "Deploy:"
echo "  rsync -av carbonio-pgp-ui.zip user@host:/tmp/"
echo "  ssh host 'sudo bash /tmp/install-pgp-ui.sh'"
