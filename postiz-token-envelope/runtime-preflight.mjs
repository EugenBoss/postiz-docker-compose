#!/usr/bin/env node
/**
 * Refuză activarea OAuth Meta dacă runtime-ul Postiz nu poate demonstra
 * contractul de origine, imagine imutabilă, secrete file-only și quiescență.
 * Inputul runtime este intenționat sanitizat: valori secrete nu sunt acceptate.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const REQUIRED_ENV = Object.freeze({
  POSTIZ_INTEGRATION_TOKEN_KEYS_FILE: '/run/secrets/postiz_integration_token_keys',
  POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE: 'reject',
  POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: '/run/secrets/postiz_meta_revocation_signing_key',
  POSTIZ_META_REVOKE_APPLY: 'NO',
});
const REQUIRED_SECRETS = Object.freeze([
  'postiz_integration_token_keys',
  'postiz_meta_revocation_signing_key',
]);
const MAX_QUIESCENCE_AGE_MS = 5 * 60 * 1000;

function fail(code) { throw new Error(code); }
function isObject(value) { return value && typeof value === 'object' && !Array.isArray(value); }

export function canonicalOrigin(value) {
  let url;
  try { url = new URL(String(value)); } catch { fail('origin_invalid'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') fail('origin_invalid');
  return url.origin;
}

function isPinnedImage(value) {
  return typeof value === 'string' && /^[^\s@]+@sha256:[a-f0-9]{64}$/.test(value);
}

function isSafeRuntimeEnvelope(value) {
  if (!isObject(value)) return false;
  const allowed = new Set(['image', 'environment', 'secrets', 'oauth_callbacks']);
  return Object.keys(value).every((key) => allowed.has(key));
}

export function verifyRuntime({ origin, expectedImage, runtime, now = Date.now() }) {
  const originValue = canonicalOrigin(origin);
  if (!isPinnedImage(expectedImage)) fail('expected_image_not_pinned');
  if (!isSafeRuntimeEnvelope(runtime)) fail('runtime_shape_invalid');
  if (runtime.image !== expectedImage) fail('runtime_image_mismatch');
  if (!isObject(runtime.environment)) fail('runtime_environment_invalid');
  const expectedEnvironmentNames = new Set([
    ...Object.keys(REQUIRED_ENV),
    'POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY',
  ]);
  if (Object.keys(runtime.environment).some((key) => !expectedEnvironmentNames.has(key))) {
    fail('runtime_environment_unknown_key');
  }
  for (const [key, expected] of Object.entries(REQUIRED_ENV)) {
    if (runtime.environment[key] !== expected) fail(`runtime_environment_${key}_invalid`);
  }
  if (typeof runtime.environment.POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY !== 'string'
      || !/^[A-Za-z0-9._-]{1,64}$/.test(runtime.environment.POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY)) {
    fail('runtime_environment_POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY_invalid');
  }
  for (const [key, value] of Object.entries(runtime.environment)) {
    if (typeof value !== 'string' || /EAA|-----BEGIN|sk-[A-Za-z0-9]/.test(value)) fail('runtime_secret_value_detected');
  }
  if (!Array.isArray(runtime.secrets) || new Set(runtime.secrets).size !== runtime.secrets.length
      || REQUIRED_SECRETS.some((item) => !runtime.secrets.includes(item))) fail('runtime_secrets_invalid');
  if (!isObject(runtime.oauth_callbacks) || runtime.oauth_callbacks.in_flight !== 0
      || runtime.oauth_callbacks.quiesced !== true) fail('runtime_oauth_not_quiesced');
  const observed = Date.parse(runtime.oauth_callbacks.observed_at ?? '');
  if (!Number.isFinite(observed) || observed > now || now - observed > MAX_QUIESCENCE_AGE_MS) fail('runtime_quiescence_stale');
  return {
    status: 'pass',
    origin: originValue,
    redirects: [`${originValue}/integrations/social/facebook`, `${originValue}/integrations/social/instagram`],
    image: expectedImage,
    requiredSecrets: REQUIRED_SECRETS,
  };
}

function option(argv, name) {
  const index = argv.indexOf(name);
  return index < 0 ? null : argv[index + 1] ?? null;
}

function main(argv) {
  const origin = option(argv, '--origin') ?? process.env.POSTIZ_PUBLIC_ORIGIN;
  const expectedImage = option(argv, '--expected-image');
  const runtimeFile = option(argv, '--runtime-file');
  if (!origin || !expectedImage || !runtimeFile) fail('usage: --origin <https-origin> --expected-image <image@sha256> --runtime-file <sanitized-json>');
  const runtime = JSON.parse(readFileSync(resolve(runtimeFile), 'utf8'));
  return verifyRuntime({ origin, expectedImage, runtime });
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  try {
    process.stdout.write(`${JSON.stringify(main(process.argv.slice(2)))}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ status: 'fail', code: error.message })}\n`);
    process.exitCode = 2;
  }
}
