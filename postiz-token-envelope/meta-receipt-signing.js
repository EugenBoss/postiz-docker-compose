'use strict';

const { createPrivateKey, createPublicKey, sign, verify } = require('node:crypto');
const { readFileSync } = require('node:fs');

const KEY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SIGNED_FIELDS = [
  'integrationId', 'provider', 'platform', 'externalAccountId', 'credentialVersion',
  'providerAccess', 'siblingCount', 'localCredential', 'killSwitchEngaged', 'receiptId',
  'providerRevokedAt', 'credentialInvalidatedAt', 'idempotencyKey', 'receiptKeyId',
];

function safeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function canonicalReceipt(receipt) {
  const canonical = {};
  for (const field of SIGNED_FIELDS) {
    if (!Object.hasOwn(receipt, field)) throw safeError('meta_receipt_field_missing');
    canonical[field] = receipt[field];
  }
  return Buffer.from(JSON.stringify(canonical), 'utf8');
}

function createMetaReceiptSigner({ env = process.env } = {}) {
  if (String(env.POSTIZ_META_REVOCATION_SIGNING_KEY || '').trim()) {
    throw safeError('meta_receipt_inline_signing_key_forbidden');
  }
  const file = String(env.POSTIZ_META_REVOCATION_SIGNING_KEY_FILE || '').trim();
  if (!file) throw safeError('meta_receipt_signing_key_file_required');
  let raw;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw safeError('meta_receipt_signing_keyring_invalid');
  }
  if (!raw || Array.isArray(raw) || typeof raw !== 'object' || !KEY_ID_RE.test(raw.activeKeyId)
      || !raw.keys || Array.isArray(raw.keys) || typeof raw.keys !== 'object') {
    throw safeError('meta_receipt_signing_keyring_invalid');
  }
  const keys = new Map();
  for (const [keyId, pem] of Object.entries(raw.keys)) {
    if (!KEY_ID_RE.test(keyId) || typeof pem !== 'string') throw safeError('meta_receipt_signing_keyring_invalid');
    let privateKey;
    try {
      privateKey = createPrivateKey(pem);
    } catch {
      throw safeError('meta_receipt_signing_keyring_invalid');
    }
    if (privateKey.asymmetricKeyType !== 'ed25519') throw safeError('meta_receipt_signing_keyring_invalid');
    keys.set(keyId, { privateKey, publicKey: createPublicKey(privateKey) });
  }
  if (!keys.has(raw.activeKeyId)) throw safeError('meta_receipt_active_signing_key_missing');

  return Object.freeze({
    keyId: raw.activeKeyId,
    signReceipt(unsignedReceipt) {
      const withKey = { ...unsignedReceipt, receiptKeyId: raw.activeKeyId };
      const receiptSignature = sign(null, canonicalReceipt(withKey), keys.get(raw.activeKeyId).privateKey).toString('base64url');
      return Object.freeze({ ...withKey, receiptSignature });
    },
    verifyReceipt(receipt) {
      const key = keys.get(receipt?.receiptKeyId);
      if (!key || typeof receipt?.receiptSignature !== 'string') return false;
      try {
        return verify(null, canonicalReceipt(receipt), key.publicKey, Buffer.from(receipt.receiptSignature, 'base64url'));
      } catch {
        return false;
      }
    },
    exportPublicKeyPem(keyId = raw.activeKeyId) {
      const key = keys.get(keyId);
      if (!key) throw safeError('meta_receipt_verification_key_missing');
      return key.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    },
  });
}

module.exports = { canonicalReceipt, createMetaReceiptSigner, SIGNED_FIELDS };
