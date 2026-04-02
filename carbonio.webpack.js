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

  return config;
};
