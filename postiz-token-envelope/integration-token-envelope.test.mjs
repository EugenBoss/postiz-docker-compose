import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const { createIntegrationTokenEnvelope, PREFIX } = require('./integration-token-envelope.js');
const { planIntegrationTokenRow, applyMigrationPlanCas } = require('./migration-plan.js');

const key = (byte) => Buffer.alloc(32, byte).toString('base64');
const env = (active = 'k2', keys = { k1: key(1), k2: key(2) }, legacy = 'reject') => {
  const directory = mkdtempSync(join(tmpdir(), 'postiz-token-keyring-'));
  const file = join(directory, 'keys.json');
  writeFileSync(file, JSON.stringify(keys), { mode: 0o600 });
  return {
    POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY: active,
    POSTIZ_INTEGRATION_TOKEN_KEYS_FILE: file,
    POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE: legacy,
  };
};

test('AES-256-GCM păstrează numai ciphertext versionat și face roundtrip fără plaintext în log/eroare', () => {
  const envelope = createIntegrationTokenEnvelope({ env: env(), randomBytesImpl: () => Buffer.alloc(12, 7) });
  const plaintext = 'fixture-sensitive-value';
  const ciphertext = envelope.encrypt('integration-1', 'token', plaintext);
  assert.ok(ciphertext.startsWith(`${PREFIX}k2:`));
  assert.equal(ciphertext.includes(plaintext), false);
  assert.equal(envelope.decrypt('integration-1', 'token', ciphertext), plaintext);
  assert.throws(() => envelope.decrypt('integration-1', 'refreshToken', ciphertext), (error) => {
    assert.equal(error.message, 'integration_token_decryption_failed');
    assert.equal(error.message.includes(plaintext), false);
    return true;
  });
});

test('cheia greșită și plaintextul legacy sunt refuzate fail-closed', () => {
  const writer = createIntegrationTokenEnvelope({ env: env('k1'), randomBytesImpl: () => Buffer.alloc(12, 3) });
  const ciphertext = writer.encrypt('integration-1', 'token', 'fixture');
  const wrong = createIntegrationTokenEnvelope({ env: env('k1', { k1: key(9) }) });
  assert.throws(() => wrong.decrypt('integration-1', 'token', ciphertext), /integration_token_decryption_failed/);
  assert.throws(() => writer.decrypt('integration-1', 'token', 'legacy-plain'), /integration_token_plaintext_detected/);
});

test('AAD leagă ciphertextul de Integration.id și refuză swap între două conturi', () => {
  const envelope = createIntegrationTokenEnvelope({ env: env(), randomBytesImpl: () => Buffer.alloc(12, 8) });
  const ciphertext = envelope.encrypt('integration-A', 'token', 'account-A-token');
  assert.equal(envelope.decrypt('integration-A', 'token', ciphertext), 'account-A-token');
  assert.throws(() => envelope.decrypt('integration-B', 'token', ciphertext), /integration_token_decryption_failed/);
});

test('keyring-ul rotește ciphertextul vechi la cheia activă fără a pierde valoarea', () => {
  const oldEnvelope = createIntegrationTokenEnvelope({ env: env('k1'), randomBytesImpl: () => Buffer.alloc(12, 1) });
  const oldCiphertext = oldEnvelope.encrypt('integration-1', 'refreshToken', 'refresh-fixture');
  const newEnvelope = createIntegrationTokenEnvelope({ env: env('k2'), randomBytesImpl: () => Buffer.alloc(12, 2) });
  const rotated = newEnvelope.encrypt('integration-1', 'refreshToken', oldCiphertext);
  assert.ok(rotated.startsWith(`${PREFIX}k2:`));
  assert.notEqual(rotated, oldCiphertext);
  assert.equal(newEnvelope.decrypt('integration-1', 'refreshToken', rotated), 'refresh-fixture');
});

test('middleware-ul criptează numai câmpurile rădăcină Integration și decriptează read-back-ul', async () => {
  const envelope = createIntegrationTokenEnvelope({
    env: env(),
    randomBytesImpl: () => Buffer.alloc(12, 5),
    randomIdImpl: () => 'new-integration-id',
  });
  let stored;
  const result = await envelope.middleware({
    model: 'Integration',
    action: 'upsert',
    args: {
      where: { id: 'integration-1' },
      create: { token: 'new-access', refreshToken: 'new-refresh' },
      update: { token: 'access', refreshToken: 'refresh', nested: { token: 'github-plain' } },
    },
  }, async (params) => {
    stored = structuredClone(params.args.update);
    return { id: 'integration-1', ...stored };
  });
  assert.ok(stored.token.startsWith(PREFIX));
  assert.ok(stored.refreshToken.startsWith(PREFIX));
  assert.equal(stored.nested.token, 'github-plain');
  assert.deepEqual(result, {
    id: 'integration-1', token: 'access', refreshToken: 'refresh', nested: { token: 'github-plain' },
  });
});

test('middleware-ul nu atinge tokenul plaintext al altui model GitHub', async () => {
  const envelope = createIntegrationTokenEnvelope({ env: env() });
  const github = { id: 'github-1', token: 'github-plaintext-fixture', refreshToken: 'github-refresh-fixture' };
  let forwarded;
  const result = await envelope.middleware({ model: 'GithubIntegration', action: 'findUnique', args: { where: { id: 'github-1' } } }, async (params) => {
    forwarded = params;
    return github;
  });
  assert.deepEqual(forwarded, { model: 'GithubIntegration', action: 'findUnique', args: { where: { id: 'github-1' } } });
  assert.equal(result, github);
});

test('middleware-ul nu transformă select/where, injectează temporar id și îl elimină după read-back', async () => {
  const envelope = createIntegrationTokenEnvelope({ env: env(), randomBytesImpl: () => Buffer.alloc(12, 6) });
  const ciphertext = envelope.encrypt('integration-1', 'token', 'selected-token');
  let forwarded;
  const result = await envelope.middleware({ model: 'Integration', action: 'findUnique', args: { where: { id: 'integration-1' }, select: { token: true } } }, async (params) => {
    forwarded = params.args;
    return { id: 'integration-1', token: ciphertext };
  });
  assert.deepEqual(forwarded, { where: { id: 'integration-1' }, select: { token: true, id: true } });
  assert.deepEqual(result, { token: 'selected-token' });
});

test('create primește un ID explicit înainte de criptare pentru AAD stabil', async () => {
  const envelope = createIntegrationTokenEnvelope({
    env: env(),
    randomBytesImpl: () => Buffer.alloc(12, 9),
    randomIdImpl: () => 'generated-integration-id',
  });
  let stored;
  const result = await envelope.middleware({ model: 'Integration', action: 'create', args: { data: { token: 'access' } } }, async (params) => {
    stored = params.args.data;
    return stored;
  });
  assert.equal(stored.id, 'generated-integration-id');
  assert.ok(stored.token.startsWith(PREFIX));
  assert.deepEqual(result, { id: 'generated-integration-id', token: 'access' });
});

test('updateManyAndReturn cu token este refuzat fail-closed înainte să poată scrie plaintext', async () => {
  const envelope = createIntegrationTokenEnvelope({ env: env() });
  let called = false;
  await assert.rejects(() => envelope.middleware({
    model: 'Integration', action: 'updateManyAndReturn', args: { data: { token: 'plaintext' } },
  }, async () => {
    called = true;
    return [];
  }), /integration_token_bulk_return_write_unsupported/);
  assert.equal(called, false);
});

test('transformarea nu aplatizează obiecte non-plain din Prisma', () => {
  class DecimalFixture { constructor(value) { this.value = value; } }
  const envelope = createIntegrationTokenEnvelope({ env: env() });
  const decimal = new DecimalFixture('12.34');
  const transformed = envelope.transformRead({ id: 'integration-1', amount: decimal }, 'findUnique');
  assert.equal(transformed.amount, decimal);
  assert.equal(transformed.amount instanceof DecimalFixture, true);
});

test('producția cere keyring file și refuză explicit keyring inline', () => {
  assert.throws(() => createIntegrationTokenEnvelope({ env: {} }), /integration_token_active_key_invalid/);
  assert.throws(() => createIntegrationTokenEnvelope({ env: {
    POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY: 'k2',
    POSTIZ_INTEGRATION_TOKEN_KEYS: JSON.stringify({ k2: key(2) }),
  } }), /integration_token_inline_keyring_forbidden/);
  assert.throws(() => createIntegrationTokenEnvelope({ env: env('k2', { k2: Buffer.alloc(16).toString('base64') }) }), /integration_token_keyring_invalid/);
  assert.throws(() => createIntegrationTokenEnvelope({ env: env('missing') }), /integration_token_active_key_missing/);
});

test('keyring-ul valid vine exclusiv dintr-un secret file montat numai la runtime', () => {
  const envelope = createIntegrationTokenEnvelope({ env: env('k2', { k2: key(2) }) });
  const ciphertext = envelope.encrypt('integration-1', 'token', 'fixture');
  assert.equal(envelope.decrypt('integration-1', 'token', ciphertext), 'fixture');
});

test('migratorul planifică plaintextul și rewrap-ul per ID, dar nu rescrie cheia activă', () => {
  const oldEnvelope = createIntegrationTokenEnvelope({ env: env('k1'), randomBytesImpl: () => Buffer.alloc(12, 1) });
  const newEnvelope = createIntegrationTokenEnvelope({ env: env('k2'), randomBytesImpl: () => Buffer.alloc(12, 2) });
  const oldCiphertext = oldEnvelope.encrypt('integration-1', 'refreshToken', 'old-refresh');
  const row = { id: 'integration-1', token: 'legacy-token', refreshToken: oldCiphertext };
  const plan = planIntegrationTokenRow(row, newEnvelope);
  assert.deepEqual({ plaintextFields: plan.plaintextFields, encryptedFields: plan.encryptedFields, rewrapFields: plan.rewrapFields, changes: plan.changes }, {
    plaintextFields: 1, encryptedFields: 1, rewrapFields: 1, changes: 2,
  });
  const stable = planIntegrationTokenRow({ id: row.id, ...plan.data }, newEnvelope);
  assert.equal(stable.changes, 0);
});

test('migratorul CAS refuză concurența și nu suprascrie valoarea apărută între citire și write', async () => {
  const row = { id: 'integration-1', token: 'old-token', refreshToken: 'old-refresh' };
  const plan = { changes: 2, data: { token: 'new-token', refreshToken: 'new-refresh' } };
  let databaseRow = { ...row, token: 'concurrent-token' };
  const prisma = {
    integration: {
      async updateMany({ where, data }) {
        const matches = databaseRow.id === where.id && databaseRow.token === where.token && databaseRow.refreshToken === where.refreshToken;
        if (matches) databaseRow = { ...databaseRow, ...data };
        return { count: matches ? 1 : 0 };
      },
    },
  };
  await assert.rejects(() => applyMigrationPlanCas(prisma, row, plan), /integration_token_migration_conflict/);
  assert.equal(databaseRow.token, 'concurrent-token');
  assert.equal(databaseRow.refreshToken, 'old-refresh');
});
