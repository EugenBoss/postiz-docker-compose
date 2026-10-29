import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const { createMetaRevocationPrismaStore } = require('./meta-revoke-prisma-store.js');
const { createMetaRevocationControl } = require('./meta-revoke-control.js');
const { createMetaReceiptSigner } = require('./meta-receipt-signing.js');

test('session advisory lock păstrează markerul autocommit când operația eșuează', async () => {
  const calls = [];
  let persistedSettings = '[]';
  const prisma = { integration: {
    async updateMany({ data }) {
      calls.push('autocommit-update');
      if (Object.hasOwn(data, 'additionalSettings')) persistedSettings = data.additionalSettings;
      return { count: 1 };
    },
  } };
  const lockClient = {
    async connect() { calls.push('lock-connect'); },
    async query(sql) { calls.push(sql.includes('unlock') ? 'unlock' : 'lock'); },
    async end() { calls.push('lock-end'); },
  };
  const store = createMetaRevocationPrismaStore({
    prisma,
    envelope: { decrypt: (_id, _field, value) => value, encrypt: (_id, _field, value) => value },
    pgClientFactory: () => lockClient,
  });
  const row = { id: 'integration-1', _rawToken: 'cipher-a', _rawRefreshToken: 'cipher-r', _rawAdditionalSettings: '[]' };
  await assert.rejects(() => store.withGrantLock(['root:root-1'], async () => {
    assert.equal(await store.markProviderAttemptCas(row, { idempotencyKey: 'a'.repeat(64) }), 1);
    throw new Error('simulated-crash');
  }), /simulated-crash/);
  assert.match(persistedSettings, /_postizMetaRevokePending/u);
  assert.deepEqual(calls, ['lock-connect', 'lock', 'autocommit-update', 'unlock', 'lock-end']);
  assert.equal(Object.hasOwn(prisma, '$transaction'), false);
});

test('PG disposable: markerul supraviețuiește erorii provider și retry-ul face zero al doilea egress', {
  skip: !process.env.POSTIZ_META_TEST_DATABASE_URL,
}, async () => {
  const { PrismaClient } = require('/app/node_modules/@prisma/client');
  const { Client: PgClient } = require('/app/node_modules/pg');
  const { createIntegrationTokenEnvelope } = require('./integration-token-envelope.js');
  const databaseUrl = process.env.POSTIZ_META_TEST_DATABASE_URL;
  const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  const envelope = createIntegrationTokenEnvelope();
  const signerDirectory = mkdtempSync(join(tmpdir(), 'postiz-pg-signing-'));
  const signerFile = join(signerDirectory, 'private.pem');
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(signerFile, JSON.stringify({
    activeKeyId: 'pg-test-v1',
    keys: { 'pg-test-v1': privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
  }), { mode: 0o400 });
  const receiptSigner = createMetaReceiptSigner({ env: {
    POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: signerFile,
  } });
  const store = createMetaRevocationPrismaStore({
    prisma,
    envelope,
    pgClientFactory: () => new PgClient({ connectionString: databaseUrl }),
  });
  const request = {
    integrationId: 'pg-meta-1',
    expectedPlatform: 'facebook',
    expectedExternalAccountId: 'pg-page-1',
    expectedCredentialVersion: 1,
    idempotencyKey: createHash('sha256').update('pg-operation').digest('hex'),
    actorPrincipal: 'pg-test',
    reason: 'crash persistence proof',
  };
  let providerCalls = 0;
  const provider = {
    async revokeGrant() { providerCalls += 1; throw new Error('simulated-provider-timeout'); },
    async readBackGrant() { throw new Error('must-not-run'); },
  };
  try {
    await prisma.organization.create({ data: { id: 'pg-org-1', name: 'PG fixture' } });
    await prisma.integration.create({ data: {
      id: 'pg-meta-1',
      internalId: 'pg-page-1',
      rootInternalId: 'pg-user-1',
      organizationId: 'pg-org-1',
      name: 'PG Meta',
      providerIdentifier: 'facebook',
      type: 'facebook',
      token: envelope.encrypt('pg-meta-1', 'token', 'pg-page-token'),
      refreshToken: envelope.encrypt('pg-meta-1', 'refreshToken', 'pg-user-token'),
    } });
    const first = createMetaRevocationControl({ store, provider, receiptSigner });
    await assert.rejects(() => first.revoke(request), /meta_revoke_provider_failed/);
    const raw = await prisma.integration.findUnique({ where: { id: 'pg-meta-1' } });
    assert.equal(raw.disabled, true);
    assert.match(raw.additionalSettings, /_postizMetaRevokePending/u);
    const second = createMetaRevocationControl({ store, provider, receiptSigner });
    await assert.rejects(() => second.revoke(request), /meta_revoke_recovery_required/);
    assert.equal(providerCalls, 1);
  } finally {
    await prisma.$disconnect();
  }
});
