'use strict';

const { randomUUID } = require('node:crypto');

function parseControlState(additionalSettings) {
  if (typeof additionalSettings !== 'string' || additionalSettings.length === 0) return {};
  try {
    const parsed = JSON.parse(additionalSettings);
    return parsed && !Array.isArray(parsed) && typeof parsed === 'object'
      ? {
          revokeReceipt: parsed._postizMetaRevokeReceipt || null,
          revokePending: parsed._postizMetaRevokePending || null,
        }
      : {};
  } catch {
    return {};
  }
}

function createMetaRevocationPrismaStore({ prisma, envelope, pgClientFactory, randomIdImpl = randomUUID }) {
  if (!prisma || !envelope || typeof pgClientFactory !== 'function') throw new Error('meta_revoke_store_dependencies_invalid');

  function mapRow(row) {
    const controlState = parseControlState(row.additionalSettings);
    return {
      ...row,
      token: envelope.decrypt(row.id, 'token', row.token),
      refreshToken: envelope.decrypt(row.id, 'refreshToken', row.refreshToken),
      revokeReceipt: controlState.revokeReceipt || null,
      revokePending: controlState.revokePending || null,
      _rawToken: row.token,
      _rawRefreshToken: row.refreshToken,
      _rawAdditionalSettings: row.additionalSettings,
    };
  }

  return Object.freeze({
    async withGrantLock(lockKeys, operationUnderLock) {
      if (!Array.isArray(lockKeys) || lockKeys.length === 0) throw new Error('meta_revoke_lock_keys_invalid');
      const orderedKeys = [...new Set(lockKeys)].sort();
      const lockClient = pgClientFactory();
      await lockClient.connect();
      const locked = [];
      try {
        for (const key of orderedKeys) {
          await lockClient.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [key]);
          locked.push(key);
        }
        return await operationUnderLock();
      } finally {
        for (const key of locked.reverse()) {
          try {
            await lockClient.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [key]);
          } catch {
            // Closing the dedicated session releases the lock even if explicit unlock fails.
          }
        }
        await lockClient.end().catch(() => {});
      }
    },
    async loadAllMetaIntegrations() {
      const rows = await prisma.integration.findMany({
        where: { providerIdentifier: { in: ['facebook', 'instagram'] } },
        select: {
          id: true,
          organizationId: true,
          providerIdentifier: true,
          internalId: true,
          rootInternalId: true,
          token: true,
          refreshToken: true,
          disabled: true,
          deletedAt: true,
          additionalSettings: true,
        },
      });
      return rows.map(mapRow);
    },
    async killSwitchTargetCas(row) {
      const result = await prisma.integration.updateMany({
        where: { id: row.id, token: row._rawToken, refreshToken: row._rawRefreshToken, deletedAt: null },
        data: { disabled: true },
      });
      return result.count;
    },
    async markProviderAttemptCas(row, pending) {
      const pendingState = JSON.stringify({
        _postizMetaRevokePending: pending,
        _previousAdditionalSettings: row._rawAdditionalSettings,
      });
      const result = await prisma.integration.updateMany({
        where: {
          id: row.id,
          token: row._rawToken,
          refreshToken: row._rawRefreshToken,
          additionalSettings: row._rawAdditionalSettings,
          disabled: true,
          deletedAt: null,
        },
        data: { additionalSettings: pendingState },
      });
      if (result.count === 1) {
        row._rawAdditionalSettings = pendingState;
        row.revokePending = pending;
      }
      return result.count;
    },
    async invalidateTargetCas(row, { receipt, revokedAt }) {
      const invalidToken = envelope.encrypt(row.id, 'token', `revoked:${randomIdImpl()}`);
      const receiptState = JSON.stringify({
        _postizMetaRevokeReceipt: receipt,
        _previousAdditionalSettings: row._rawAdditionalSettings,
      });
      const result = await prisma.integration.updateMany({
        where: {
          id: row.id,
          token: row._rawToken,
          refreshToken: row._rawRefreshToken,
          additionalSettings: row._rawAdditionalSettings,
          disabled: true,
          deletedAt: null,
        },
        data: {
          token: invalidToken,
          refreshToken: null,
          additionalSettings: receiptState,
          disabled: true,
          refreshNeeded: false,
          deletedAt: revokedAt,
        },
      });
      return result.count;
    },
  });
}

module.exports = { createMetaRevocationPrismaStore, parseControlState };
