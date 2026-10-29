import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { PrismaClient } = require('/app/node_modules/@prisma/client');
const { createIntegrationTokenEnvelope } = require('./integration-token-envelope.js');
const { planIntegrationTokenRow, applyMigrationPlanCas } = require('./migration-plan.js');

const apply = process.argv.includes('--apply');
if (apply && process.env.POSTIZ_INTEGRATION_TOKEN_MIGRATION_APPLY !== 'YES') {
  throw new Error('integration_token_migration_apply_not_authorized');
}

const envelope = createIntegrationTokenEnvelope({
  env: { ...process.env, POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE: 'allow-read' },
});
const prisma = new PrismaClient();
try {
  const rows = await prisma.integration.findMany({ select: { id: true, token: true, refreshToken: true } });
  let plaintextFields = 0;
  let encryptedFields = 0;
  let rewrapFields = 0;
  let pendingRows = 0;
  let updatedRows = 0;
  for (const row of rows) {
    const plan = planIntegrationTokenRow(row, envelope);
    plaintextFields += plan.plaintextFields;
    encryptedFields += plan.encryptedFields;
    rewrapFields += plan.rewrapFields;
    if (!plan.changes) continue;
    pendingRows += 1;
    if (!apply) continue;
    await applyMigrationPlanCas(prisma, row, plan);
    updatedRows += 1;
  }
  process.stdout.write(`${JSON.stringify({ mode: apply ? 'apply' : 'dry-run', rows: rows.length, plaintextFields, encryptedFields, rewrapFields, pendingRows, updatedRows })}\n`);
} finally {
  await prisma.$disconnect();
}
