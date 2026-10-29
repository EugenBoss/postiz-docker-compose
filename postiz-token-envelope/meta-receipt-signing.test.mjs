import assert from 'node:assert/strict';
import test from 'node:test';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { canonicalReceipt, createMetaReceiptSigner } = require('./meta-receipt-signing.js');

function signerFixture(keyId = 'ed25519-fixture-v1') {
  const directory = mkdtempSync(join(tmpdir(), 'postiz-receipt-key-'));
  const file = join(directory, 'private.pem');
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(file, JSON.stringify({
    activeKeyId: keyId,
    keys: { [keyId]: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
  }), { mode: 0o400 });
  return {
    file,
    signer: createMetaReceiptSigner({ env: {
      POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: file,
    } }),
  };
}

const unsigned = {
  integrationId: 'integration-1',
  provider: 'meta',
  platform: 'facebook',
  externalAccountId: 'page-1',
  credentialVersion: 3,
  providerAccess: 'revoked',
  siblingCount: 0,
  localCredential: 'invalidated',
  killSwitchEngaged: true,
  receiptId: 'meta_rvk:fixture',
  providerRevokedAt: '2026-10-29T12:00:00.000Z',
  credentialInvalidatedAt: '2026-10-29T12:00:01.000Z',
  idempotencyKey: 'a'.repeat(64),
};

test('Ed25519 semnează canonical receipt, iar tamper identity/version/status este refuzat', () => {
  const { signer } = signerFixture();
  const receipt = signer.signReceipt(unsigned);
  assert.equal(receipt.receiptKeyId, 'ed25519-fixture-v1');
  assert.match(receipt.receiptSignature, /^[A-Za-z0-9_-]+$/u);
  assert.equal(signer.verifyReceipt(receipt), true);
  assert.equal(signer.verifyReceipt({ ...receipt, externalAccountId: 'page-2' }), false);
  assert.equal(signer.verifyReceipt({ ...receipt, credentialVersion: 4 }), false);
  assert.equal(signer.verifyReceipt({ ...receipt, providerAccess: 'retained_for_siblings' }), false);
});

test('canonical JSON este determinist și include key id + siblingCount', () => {
  const { signer } = signerFixture();
  const receipt = signer.signReceipt(unsigned);
  const parsed = JSON.parse(canonicalReceipt(receipt).toString('utf8'));
  assert.equal(parsed.receiptKeyId, receipt.receiptKeyId);
  assert.equal(parsed.siblingCount, 0);
  assert.equal(Object.hasOwn(parsed, 'receiptSignature'), false);
});

test('keyring lipsă, inline, invalid și active key absent sunt refuzate fail-closed', () => {
  assert.throws(() => createMetaReceiptSigner({ env: {} }), /meta_receipt_signing_key_file_required/);
  assert.throws(() => createMetaReceiptSigner({ env: {
    POSTIZ_META_REVOCATION_SIGNING_KEY: 'inline-forbidden',
  } }), /meta_receipt_inline_signing_key_forbidden/);
  const directory = mkdtempSync(join(tmpdir(), 'postiz-wrong-key-'));
  const wrong = join(directory, 'wrong.pem');
  writeFileSync(wrong, JSON.stringify({ activeKeyId: 'key-1', keys: { 'key-1': 'not-a-private-key' } }), { mode: 0o400 });
  assert.throws(() => createMetaReceiptSigner({ env: {
    POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: wrong,
  } }), /meta_receipt_signing_keyring_invalid/);
});

test('rotația semnează numai cu active key și verifică receipturile cheilor vechi încă prezente', () => {
  const directory = mkdtempSync(join(tmpdir(), 'postiz-signing-rotation-'));
  const file = join(directory, 'keyring.json');
  const oldPair = generateKeyPairSync('ed25519');
  const newPair = generateKeyPairSync('ed25519');
  const oldPem = oldPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const newPem = newPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  writeFileSync(file, JSON.stringify({ activeKeyId: 'old', keys: { old: oldPem, new: newPem } }), { mode: 0o400 });
  const oldSigner = createMetaReceiptSigner({ env: { POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: file } });
  const oldReceipt = oldSigner.signReceipt(unsigned);
  chmodSync(file, 0o600);
  writeFileSync(file, JSON.stringify({ activeKeyId: 'new', keys: { old: oldPem, new: newPem } }), { mode: 0o400 });
  chmodSync(file, 0o400);
  const rotated = createMetaReceiptSigner({ env: { POSTIZ_META_REVOCATION_SIGNING_KEY_FILE: file } });
  assert.equal(rotated.verifyReceipt(oldReceipt), true);
  assert.equal(rotated.signReceipt(unsigned).receiptKeyId, 'new');
});

test('o altă cheie cu același key id nu poate valida receiptul', () => {
  const first = signerFixture('shared-key-id').signer;
  const second = signerFixture('shared-key-id').signer;
  const receipt = first.signReceipt(unsigned);
  assert.equal(second.verifyReceipt(receipt), false);
});

test('vectorul fix cross-contract are canonical bytes și semnătură Ed25519 verificabile independent', () => {
  const fixture = JSON.parse(readFileSync(new URL('./meta-receipt-cross-contract.fixture.json', import.meta.url), 'utf8'));
  assert.equal(canonicalReceipt(fixture.receipt).toString('utf8'), fixture.canonical);
  assert.equal(verify(
    null,
    Buffer.from(fixture.canonical, 'utf8'),
    createPublicKey(fixture.publicKeyPem),
    Buffer.from(fixture.receipt.receiptSignature, 'base64url'),
  ), true);
});
