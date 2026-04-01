#!/usr/bin/env bash
# install-deps.sh — Bootstrap carbonio-pgp-ui development environment
# Usage: bash install-deps.sh [carbonio-host]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Installing npm dependencies..."
npm install

echo "==> Linking sibling repos (hem-sdk-js, encedo-pgp-js)..."
# hem-sdk-js must be at ../hem-sdk-js/ (same convention as encedo-pgp-js)
HEM_SDK="$SCRIPT_DIR/../hem-sdk-js/hem-sdk.js"
if [[ ! -f "$HEM_SDK" ]]; then
    echo "WARNING: hem-sdk-js not found at $HEM_SDK"
    echo "         Clone it: git clone https://github.com/encedo/hem-sdk-js ../hem-sdk-js"
fi

PGP_BROWSER="$SCRIPT_DIR/../encedo-pgp-js/dist/encedo-pgp.browser.js"
if [[ ! -f "$PGP_BROWSER" ]]; then
    echo "WARNING: encedo-pgp-js browser bundle not found at $PGP_BROWSER"
    echo "         Build it: cd ../encedo-pgp-js && npm install && npm run build"
fi

echo ""
echo "Done. Next steps:"
echo "  npm start -- -h <carbonio-host>   # dev mode (watch + proxy)"
echo "  npm run build                      # production build"
echo "  npm run deploy -- -h <host>        # deploy to Carbonio"
