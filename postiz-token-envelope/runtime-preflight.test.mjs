import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyRuntime } from './runtime-preflight.mjs';

const image = `registry.example/postiz@sha256:${'a'.repeat(64)}`;
const now = Date.parse('2026-11-11T12:00:00.000Z');
const runtime = {
  image,
  environment: {
    POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY: 'k2026_11',
    POSTIZ_INTEGRATION_TOKEN_KEYS_FILE: '/run/secrets/postiz_integration_token_keys',
    POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE: 'reject',
    POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: '/run/secrets/postiz_meta_revocation_signing_key',
    POSTIZ_META_REVOKE_APPLY: 'NO',
  },
  secrets: ['postiz_integration_token_keys', 'postiz_meta_revocation_signing_key'],
  oauth_callbacks: { in_flight: 0, quiesced: true, observed_at: '2026-11-11T11:59:00.000Z' },
};

test('acceptă numai runtime-ul imutabil, file-only și fără flow OAuth', () => {
  const report = verifyRuntime({ origin: 'https://postiz.example.test', expectedImage: image, runtime, now });
  assert.equal(report.status, 'pass');
  assert.deepEqual(report.redirects, [
    'https://postiz.example.test/integrations/social/facebook',
    'https://postiz.example.test/integrations/social/instagram',
  ]);
});

test('refuză tag mobil, env nesanitizat și callbackuri nequiescente', () => {
  assert.throws(() => verifyRuntime({ origin: 'https://postiz.example.test', expectedImage: 'postiz:latest', runtime, now }), /expected_image_not_pinned/);
  assert.throws(() => verifyRuntime({ origin: 'https://postiz.example.test', expectedImage: image,
    runtime: { ...runtime, environment: { ...runtime.environment, POSTIZ_API_TOKEN: 'EAAsecret' } }, now }), /runtime_environment_unknown_key/);
  assert.throws(() => verifyRuntime({ origin: 'https://postiz.example.test', expectedImage: image,
    runtime: { ...runtime, oauth_callbacks: { ...runtime.oauth_callbacks, in_flight: 1 } }, now }), /runtime_oauth_not_quiesced/);
});

test('refuză originea nepublică și observația runtime învechită', () => {
  assert.throws(() => verifyRuntime({ origin: 'http://localhost:4007', expectedImage: image, runtime, now }), /origin_invalid/);
  assert.throws(() => verifyRuntime({ origin: 'https://postiz.example.test', expectedImage: image,
    runtime: { ...runtime, oauth_callbacks: { ...runtime.oauth_callbacks, observed_at: '2026-11-11T11:50:00.000Z' } }, now }), /runtime_quiescence_stale/);
});
