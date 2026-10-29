import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const {
  assertStandardDeleteAllowed,
  createMetaGraphProvider,
  createMetaRevocationControl,
  requireQuiescenceAssertionPath,
  validateQuiescenceAssertion,
  validateRequest,
} = require('./meta-revoke-control.js');
const { createMetaReceiptSigner } = require('./meta-receipt-signing.js');

const signerDirectory = mkdtempSync(join(tmpdir(), 'postiz-meta-signing-'));
const signerFile = join(signerDirectory, 'private.pem');
const { privateKey } = generateKeyPairSync('ed25519');
writeFileSync(signerFile, JSON.stringify({
  activeKeyId: 'fixture-ed25519-v1',
  keys: { 'fixture-ed25519-v1': privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
}), { mode: 0o400 });
const receiptSigner = createMetaReceiptSigner({ env: {
  POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: signerFile,
} });

const grant = 'user-grant-fixture';
const grantLockCall = `lock:grant:${createHash('sha256').update(grant).digest('hex')}|root:meta-user-9`;
const idempotencyKey = createHash('sha256').update('fixture-idempotency').digest('hex');
const request = {
  integrationId: 'facebook-1',
  expectedPlatform: 'facebook',
  expectedExternalAccountId: 'page-123',
  expectedCredentialVersion: 17,
  idempotencyKey,
  actorPrincipal: 'admin-fixture',
  reason: 'disconnect requested',
};

const target = () => ({
  id: 'facebook-1',
  organizationId: 'org-1',
  providerIdentifier: 'facebook',
  internalId: 'page-123',
  rootInternalId: 'meta-user-9',
  credentialVersion: 17,
  token: 'page-token-fixture',
  refreshToken: grant,
  disabled: false,
  deletedAt: null,
  revokeReceipt: null,
});

const sibling = () => ({
  ...target(),
  id: 'instagram-2',
  providerIdentifier: 'instagram',
  internalId: 'instagram-456',
  token: 'instagram-token-fixture',
  disabled: true,
});

function harness({ rows = [target()], store: storeOverrides = {}, provider: providerOverrides = {}, dates } = {}) {
  const calls = [];
  const store = {
    async withGrantLock(lockKeys, operation) { calls.push(`lock:${lockKeys.join('|')}`); return operation(); },
    async loadAllMetaIntegrations() { calls.push('load'); return rows; },
    async killSwitchTargetCas() { calls.push('kill'); return 1; },
    async markProviderAttemptCas() { calls.push('mark-provider-attempt'); return 1; },
    async invalidateTargetCas() { calls.push('invalidate'); return 1; },
    ...storeOverrides,
  };
  const provider = {
    async revokeGrant() { calls.push('provider-ack'); return { acknowledged: true }; },
    async readBackGrant() { calls.push('provider-readback'); return { revoked: true }; },
    ...providerOverrides,
  };
  const sequence = dates || [
    new Date('2026-10-29T12:00:00.000Z'),
    new Date('2026-10-29T12:00:01.000Z'),
    new Date('2026-10-29T12:00:02.000Z'),
  ];
  let dateIndex = 0;
  const control = createMetaRevocationControl({ store, provider, receiptSigner, now: () => sequence[Math.min(dateIndex++, sequence.length - 1)] });
  return { control, calls };
}

function expectedReceipt() {
  const receiptDigest = createHash('sha256').update(idempotencyKey).update('\0').update('facebook-1').digest('hex').slice(0, 48);
  return receiptSigner.signReceipt({
    integrationId: 'facebook-1',
    provider: 'meta',
    platform: 'facebook',
    externalAccountId: 'page-123',
    credentialVersion: 17,
    providerAccess: 'revoked',
    siblingCount: 0,
    localCredential: 'invalidated',
    killSwitchEngaged: true,
    receiptId: `meta_rvk:${receiptDigest}`,
    providerRevokedAt: '2026-10-29T12:00:01.000Z',
    credentialInvalidatedAt: '2026-10-29T12:00:02.000Z',
    idempotencyKey,
  });
}

test('requestul Admin exact este acceptat, iar secret-like keys sunt refuzate înainte de lucru', () => {
  assert.deepEqual(validateRequest(request), request);
  assert.throws(() => validateRequest({ ...request, refreshToken: grant }), /meta_revoke_request_secret_forbidden/);
  assert.throws(() => validateRequest({ ...request, unexpected: 'value' }), /meta_revoke_request_invalid/);
});

test('operator quiescence assertion este doar o gardă locală și cere zero flow-uri + fereastră validă', () => {
  const now = () => new Date('2026-10-29T12:00:00Z');
  assert.deepEqual(validateQuiescenceAssertion({
    receiptId: 'quiescence-1', oauthCallbacksQuiesced: true, inFlightFlows: 0,
    observedAt: '2026-10-29T11:59:00Z', expiresAt: '2026-10-29T12:05:00Z',
  }, now), {
    receiptId: 'quiescence-1', oauthCallbacksQuiesced: true, inFlightFlows: 0,
    observedAt: '2026-10-29T11:59:00.000Z', expiresAt: '2026-10-29T12:05:00.000Z',
  });
  assert.throws(() => validateQuiescenceAssertion({
    receiptId: 'quiescence-1', oauthCallbacksQuiesced: true, inFlightFlows: 1,
    observedAt: '2026-10-29T11:59:00Z', expiresAt: '2026-10-29T12:05:00Z',
  }, now), /meta_revoke_quiescence_assertion_invalid/);
});

test('CLI apply refuză fail-closed când lipsește operator quiescence assertion', () => {
  assert.throws(() => requireQuiescenceAssertionPath(['node', 'cli', '--apply']), /meta_revoke_quiescence_assertion_required/);
  assert.equal(requireQuiescenceAssertionPath(['node', 'cli', '--apply', '--operator-quiescence-assertion', '/run/public.json']), '/run/public.json');
});

test('identity mismatch este refuzat înainte de kill switch/provider', async () => {
  const { control, calls } = harness();
  await assert.rejects(() => control.revoke({ ...request, expectedExternalAccountId: 'page-wrong' }), /meta_revoke_identity_mismatch/);
  assert.deepEqual(calls, ['load']);
});

test('credentialVersion este binding pozitiv caller-owned, echo/persistat, iar CAS leagă snapshotul local', async () => {
  const { control } = harness();
  const receipt = await control.revoke({ ...request, expectedCredentialVersion: 18 });
  assert.equal(receipt.credentialVersion, 18);
});

test('grantul user lipsă este refuzat fail-closed', async () => {
  const { control, calls } = harness({ rows: [{ ...target(), refreshToken: null }] });
  await assert.rejects(() => control.revoke(request), /meta_revoke_user_grant_missing/);
  assert.deepEqual(calls, ['load']);
});

test('root identity lipsă este refuzată înainte de provider', async () => {
  const { control, calls } = harness({ rows: [{ ...target(), rootInternalId: null }] });
  await assert.rejects(() => control.revoke(request), /meta_revoke_root_identity_missing/);
  assert.deepEqual(calls, ['load']);
});

test('kill switch-ul este primul efect și conflictul oprește providerul', async () => {
  const { control, calls } = harness({ store: { async killSwitchTargetCas() { calls.push('kill-conflict'); return 0; } } });
  await assert.rejects(() => control.revoke(request), /meta_revoke_kill_switch_failed/);
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill-conflict']);
});

test('orice soră activă produce numai revocare locală target, fără egress provider', async () => {
  const { control, calls } = harness({ rows: [target(), sibling()] });
  const receipt = await control.revoke(request);
  assert.equal(receipt.providerAccess, 'retained_for_siblings');
  assert.equal(receipt.siblingCount, 1);
  assert.equal(receipt.providerRevokedAt, null);
  assert.equal(receipt.localCredential, 'invalidated');
  assert.equal(receiptSigner.verifyReceipt(receipt), true);
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'invalidate']);
});

test('două surori concurente sunt serializate pe grant: una local-only, ultima exact un provider DELETE', async () => {
  const rows = [target(), { ...sibling(), rootInternalId: 'meta-user-other-root' }];
  let lockTail = Promise.resolve();
  let providerDeletes = 0;
  const store = {
    async withGrantLock(lockKeys, operation) {
      assert.equal(lockKeys.some((key) => key.startsWith('grant:')), true);
      const previous = lockTail;
      let release;
      lockTail = new Promise((resolve) => { release = resolve; });
      await previous;
      try { return await operation(); } finally { release(); }
    },
    async loadAllMetaIntegrations() { return rows; },
    async killSwitchTargetCas(row) { row.disabled = true; return 1; },
    async markProviderAttemptCas(row, pending) { row.revokePending = pending; return 1; },
    async invalidateTargetCas(row, { receipt, revokedAt }) {
      row.deletedAt = revokedAt;
      row.refreshToken = null;
      row.revokePending = null;
      row.revokeReceipt = receipt;
      return 1;
    },
  };
  const provider = {
    async revokeGrant() { providerDeletes += 1; return { acknowledged: true }; },
    async readBackGrant() { return { revoked: true }; },
  };
  const control = createMetaRevocationControl({ store, provider, receiptSigner, now: () => new Date('2026-10-29T12:00:00Z') });
  const instagramRequest = {
    ...request,
    integrationId: 'instagram-2',
    expectedPlatform: 'instagram',
    expectedExternalAccountId: 'instagram-456',
    expectedCredentialVersion: 21,
    idempotencyKey: createHash('sha256').update('instagram-operation').digest('hex'),
  };
  const receipts = await Promise.all([control.revoke(request), control.revoke(instagramRequest)]);
  assert.deepEqual(receipts.map((receipt) => receipt.providerAccess).sort(), ['retained_for_siblings', 'revoked']);
  assert.equal(providerDeletes, 1);
  assert.equal(rows.filter((row) => !row.deletedAt).length, 0);
});

test('o soră soft-deleted nu blochează ultimul canal activ', async () => {
  const { control, calls } = harness({ rows: [target(), { ...sibling(), deletedAt: new Date('2026-01-01') }] });
  await control.revoke(request);
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'mark-provider-attempt', 'provider-ack', 'provider-readback', 'invalidate']);
});

test('provider exception este sanitizată și oprește read-back/CAS', async () => {
  const { control, calls } = harness({ provider: { async revokeGrant() { calls.push('provider-error'); throw new Error(`leak:${grant}`); } } });
  await assert.rejects(() => control.revoke(request), (error) => {
    assert.equal(error.message, 'meta_revoke_provider_failed');
    assert.equal(error.message.includes(grant), false);
    return true;
  });
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'mark-provider-attempt', 'provider-error']);
});

test('ACK lipsă oprește read-back și invalidarea', async () => {
  const { control, calls } = harness({ provider: { async revokeGrant() { calls.push('provider-no-ack'); return { acknowledged: false }; } } });
  await assert.rejects(() => control.revoke(request), /meta_revoke_provider_ack_missing/);
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'mark-provider-attempt', 'provider-no-ack']);
});

test('read-back ambiguu oprește invalidarea', async () => {
  const { control, calls } = harness({ provider: { async readBackGrant() { calls.push('readback-no'); return { revoked: false }; } } });
  await assert.rejects(() => control.revoke(request), /meta_revoke_provider_readback_unconfirmed/);
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'mark-provider-attempt', 'provider-ack', 'readback-no']);
});

test('conflictul CAS după provider este fail-closed', async () => {
  const { control, calls } = harness({ store: { async invalidateTargetCas() { calls.push('invalidate-conflict'); return 0; } } });
  await assert.rejects(() => control.revoke(request), /meta_revoke_local_cas_failed/);
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'mark-provider-attempt', 'provider-ack', 'provider-readback', 'invalidate-conflict']);
});

test('ultimul canal produce receiptul exact cerut de Admin și fără secrete', async () => {
  const { control, calls } = harness();
  const receipt = await control.revoke(request);
  assert.deepEqual(receipt, expectedReceipt());
  assert.deepEqual(calls, ['load', grantLockCall, 'load', 'kill', 'mark-provider-attempt', 'provider-ack', 'provider-readback', 'invalidate']);
  assert.equal(JSON.stringify(receipt).includes(grant), false);
  assert.equal(JSON.stringify(receipt).includes('page-token'), false);
  assert.equal(receiptSigner.verifyReceipt(receipt), true);
});

test('crash-window persistent oprește auto-retry și nu declară revoked', async () => {
  const { control, calls } = harness({ rows: [{
    ...target(),
    disabled: true,
    revokePending: { idempotencyKey, integrationId: 'facebook-1' },
  }] });
  await assert.rejects(() => control.revoke(request), /meta_revoke_recovery_required/);
  assert.deepEqual(calls, ['load']);
});

test('replay după succes întoarce byte-equivalent receipt fără kill switch sau egress', async () => {
  const receipt = expectedReceipt();
  const { control, calls } = harness({ rows: [{ ...target(), deletedAt: new Date(receipt.credentialInvalidatedAt), disabled: true, refreshToken: null, revokeReceipt: receipt }] });
  assert.deepEqual(await control.revoke(request), receipt);
  assert.deepEqual(calls, ['load']);
});

test('replay cu idempotency key divergent este conflict persistent', async () => {
  const receipt = expectedReceipt();
  const { control, calls } = harness({ rows: [{ ...target(), deletedAt: new Date(receipt.credentialInvalidatedAt), disabled: true, refreshToken: null, revokeReceipt: receipt }] });
  const divergent = createHash('sha256').update('different').digest('hex');
  await assert.rejects(() => control.revoke({ ...request, idempotencyKey: divergent }), /postiz_meta_revocation_conflict/);
  assert.deepEqual(calls, ['load']);
});

test('replay cu receipt semnat de altă cheie este refuzat fail-closed', async () => {
  const otherDirectory = mkdtempSync(join(tmpdir(), 'postiz-meta-signing-other-'));
  const otherFile = join(otherDirectory, 'private.pem');
  const otherPair = generateKeyPairSync('ed25519');
  writeFileSync(otherFile, JSON.stringify({
    activeKeyId: 'fixture-ed25519-v1',
    keys: { 'fixture-ed25519-v1': otherPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
  }), { mode: 0o400 });
  const otherSigner = createMetaReceiptSigner({ env: {
    POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: otherFile,
  } });
  const receipt = otherSigner.signReceipt({ ...expectedReceipt(), receiptKeyId: undefined, receiptSignature: undefined });
  const { control } = harness({ rows: [{ ...target(), deletedAt: new Date(), revokeReceipt: receipt }] });
  await assert.rejects(() => control.revoke(request), /meta_revoke_receipt_signature_invalid/);
});

test('readMetaRevocation întoarce receiptul persistent identic, nu status public auto-declarat', async () => {
  const receipt = expectedReceipt();
  const { control } = harness({ rows: [{ ...target(), deletedAt: new Date(receipt.credentialInvalidatedAt), disabled: true, refreshToken: null, revokeReceipt: receipt }] });
  assert.deepEqual(await control.readRevocation(request), receipt);
});

test('DELETE standard rămâne blocat pentru orice Meta și permis non-Meta', () => {
  assert.throws(() => assertStandardDeleteAllowed({ providerIdentifier: 'facebook' }), /meta_provider_revoke_receipt_required/);
  assert.throws(() => assertStandardDeleteAllowed({ providerIdentifier: 'instagram' }), /meta_provider_revoke_receipt_required/);
  assert.doesNotThrow(() => assertStandardDeleteAllowed({ providerIdentifier: 'linkedin' }));
});

test('adapterul Graph folosește /rootInternalId/permissions + Bearer, ACK și read-back, fără egress real', async () => {
  const seen = [];
  const responses = [
    { ok: true, async json() { return { success: true }; } },
    { ok: false, async json() { return { error: { code: 190 } }; } },
  ];
  const provider = createMetaGraphProvider({ fetchImpl: async (url, options) => {
    seen.push({ url, options });
    return responses.shift();
  } });
  assert.deepEqual(await provider.revokeGrant({ rootInternalId: 'meta-user-9', grantToken: grant }), { acknowledged: true });
  assert.deepEqual(await provider.readBackGrant({ rootInternalId: 'meta-user-9', grantToken: grant }), { revoked: true });
  assert.equal(seen[0].url.endsWith('/meta-user-9/permissions'), true);
  assert.equal(seen[0].url.includes(grant), false);
  assert.equal(seen[0].options.headers.authorization, `Bearer ${grant}`);
  assert.equal(seen[0].options.method, 'DELETE');
  assert.equal(seen[1].options.method, 'GET');
});
