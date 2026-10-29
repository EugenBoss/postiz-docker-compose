#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const files = ['-f', 'docker-compose.yaml', '-f', 'docker-compose.meta-token-envelope.yaml'];

function containerState() {
  const result = spawnSync('docker', ['inspect', 'postiz', '--format', '{{.Image}}|{{.State.Status}}'], {
    cwd: ROOT, encoding: 'utf8',
  });
  return result.status === 0 ? result.stdout.trim() : null;
}

function composeConfig(environment) {
  const env = { ...process.env, POSTIZ_JWT_SECRET: 'fixture-jwt-only' };
  delete env.POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY;
  delete env.POSTIZ_INTEGRATION_TOKEN_KEYS_HOST_FILE;
  Object.assign(env, environment);
  return spawnSync('docker', ['compose', ...files, 'config'], {
    cwd: ROOT,
    encoding: 'utf8',
    env,
  });
}

const temp = mkdtempSync(path.join(tmpdir(), 'postiz-envelope-compose-'));
const keyringPath = path.join(temp, 'keyring.json');
const before = containerState();

try {
  const fixtureKey = Buffer.alloc(32, 7).toString('base64');
  writeFileSync(keyringPath, JSON.stringify({ fixture_key: fixtureKey }), { mode: 0o400 });
  chmodSync(keyringPath, 0o400);

  const valid = composeConfig({
    POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY: 'fixture_key',
    POSTIZ_INTEGRATION_TOKEN_KEYS_HOST_FILE: keyringPath,
  });
  assert.equal(valid.status, 0, valid.stderr);
  assert.match(valid.stdout, /image:\s+postiz-pm-meta-token-envelope:v1\.47\.0-local/u);
  assert.match(valid.stdout, /dockerfile:\s+Dockerfile\.meta-token-envelope/u);
  assert.match(valid.stdout, /POSTIZ_INTEGRATION_TOKEN_KEYS_FILE:\s+\/run\/secrets\/postiz_integration_token_keys/u);
  assert.match(valid.stdout, /source:\s+postiz_integration_token_keys/u);
  assert.doesNotMatch(valid.stdout, new RegExp(fixtureKey, 'u'));

  const noKeyFile = composeConfig({ POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY: 'fixture_key' });
  assert.notEqual(noKeyFile.status, 0);
  assert.match(noKeyFile.stderr, /POSTIZ_INTEGRATION_TOKEN_KEYS_HOST_FILE must be set/u);

  const noActiveKey = composeConfig({ POSTIZ_INTEGRATION_TOKEN_KEYS_HOST_FILE: keyringPath });
  assert.notEqual(noActiveKey.status, 0);
  assert.match(noActiveKey.stderr, /POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY must be set/u);

  assert.equal(containerState(), before, 'compose config must not recreate or mutate the active Postiz container');
  process.stdout.write('PASS compose overlay: config valid, missing inputs fail closed, active runtime unchanged\n');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
