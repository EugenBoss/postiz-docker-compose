type Integration = { providerIdentifier?: string } | null | undefined;

// Runtime source of truth is the reviewed CommonJS module copied beside this bridge.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const implementation = require('./meta-revoke-control.js') as {
  assertStandardDeleteAllowed(integration: Integration): void;
};

export const assertStandardDeleteAllowed = implementation.assertStandardDeleteAllowed;
