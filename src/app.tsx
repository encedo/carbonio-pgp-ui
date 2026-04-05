import { addRoute, registerFunctions } from '@zextras/carbonio-shell-ui';
import { HsmProvider } from './store/HsmContext';
import { PgpSettingsView } from './views/PgpSettingsView';

const APP_ID = 'carbonio-pgp-ui';

// Defined at module level so the reference is stable — HsmProvider never unmounts.
function PgpView() {
  return <HsmProvider><PgpSettingsView /></HsmProvider>;
}

export default function App() {
  // Register main nav route
  addRoute({
    id: APP_ID,
    app: APP_ID,
    route: 'pgp',
    position: 200,
    visible: true,
    label: 'PGP',
    primaryBar: 'LockOutline',
    appView: PgpView,
    badge: { show: false },
  });

  // Register stub functions for mails-ui integration (Phase 2 & 3)
  registerFunctions({
    'pgp:encrypt': {
      id: `${APP_ID}:pgp:encrypt`,
      fn: () => { throw new Error('PGP encrypt: HSM not yet connected'); },
    },
    'pgp:sign-encrypt': {
      id: `${APP_ID}:pgp:sign-encrypt`,
      fn: () => { throw new Error('PGP sign+encrypt: HSM not yet connected'); },
    },
    'pgp:decrypt': {
      id: `${APP_ID}:pgp:decrypt`,
      fn: () => { throw new Error('PGP decrypt: HSM not yet connected'); },
    },
  });

  return null;
}
