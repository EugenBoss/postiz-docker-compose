'use strict';

const { PREFIX } = require('./integration-token-envelope.js');

function planIntegrationTokenRow(row, envelope) {
  if (typeof row?.id !== 'string' || row.id.length === 0) throw new Error('integration_token_migration_id_invalid');
  const fields = [row.token, row.refreshToken].filter((value) => typeof value === 'string' && value.length > 0);
  const token = envelope.encrypt(row.id, 'token', row.token);
  const refreshToken = envelope.encrypt(row.id, 'refreshToken', row.refreshToken);
  const changes = Number(token !== row.token) + Number(refreshToken !== row.refreshToken);
  return Object.freeze({
    plaintextFields: fields.filter((value) => !value.startsWith(PREFIX)).length,
    encryptedFields: fields.filter((value) => value.startsWith(PREFIX)).length,
    rewrapFields: fields.filter((value) => value.startsWith(PREFIX) && !value.startsWith(`${PREFIX}${envelope.activeKeyId}:`)).length,
    changes,
    data: changes ? { token, refreshToken } : null,
  });
}

async function applyMigrationPlanCas(prisma, row, plan) {
  if (!plan.changes) return false;
  const result = await prisma.integration.updateMany({
    where: { id: row.id, token: row.token, refreshToken: row.refreshToken },
    data: plan.data,
  });
  if (result?.count !== 1) throw new Error('integration_token_migration_conflict');
  return true;
}

module.exports = { planIntegrationTokenRow, applyMigrationPlanCas };
