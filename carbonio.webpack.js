// carbonio.webpack.js — custom webpack overrides
//
// hem-sdk.browser.js contains `import('node:https/http/url')` in the
// Node.js-only code path (#reqNode), guarded by:
//   const isNode = typeof process !== 'undefined' && process.versions?.node;
// In a browser this code is dead and never executed. We need to tell webpack
// to ignore these unresolvable node: scheme imports.
//
// Strategy: NormalModuleReplacementPlugin strips the 'node:' prefix, then
// resolve.fallback maps those modules to false (empty stubs).

const webpack = require('webpack');
const path = require('path');

// Absolute path to openpgp's prebuilt browser ESM bundle. openpgp's package
// "exports" does not expose ./dist/* subpaths, so resolve the package main
// (dist/node/openpgp.min.cjs) and walk to the sibling browser build.
const OPENPGP_BROWSER_BUILD = path.resolve(
  path.dirname(require.resolve('openpgp')),
  '../openpgp.min.mjs',
);

module.exports = function (config /*, pkg, options, mode */) {
  // Strip 'node:' prefix so webpack can apply resolve.fallback rules
  config.plugins = config.plugins ?? [];
  config.plugins.push(
    new webpack.NormalModuleReplacementPlugin(/^node:/, (resource) => {
      resource.request = resource.request.replace(/^node:/, '');
    })
  );

  // Stub out the Node.js built-ins as empty modules in the browser build
  config.resolve = config.resolve ?? {};
  config.resolve.fallback = {
    ...(config.resolve.fallback ?? {}),
    https: false,
    http:  false,
    url:   false,
    net:   false,
    tls:   false,
  };

  // Force openpgp's PREBUILT BROWSER bundle. openpgp@6's package exports resolve
  // the "import" condition to dist/node/openpgp.mjs (built for Node); bundled for
  // the browser, its EdDSA verification throws "Unknown curve" (decrypt/readKey
  // still work, so it's easy to miss). dist/openpgp.min.mjs is the same build the
  // standalone tester loads and verifies signatures correctly. The `$` makes this
  // an exact match for bare `openpgp` imports (both app.tsx and the encedo-pgp
  // bundle), so there is still a single shared, working instance.
  config.resolve.alias = {
    ...(config.resolve.alias ?? {}),
    openpgp$: OPENPGP_BROWSER_BUILD,
  };

  return config;
};
