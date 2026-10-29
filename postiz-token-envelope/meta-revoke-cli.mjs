import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const { PrismaClient } = require('/app/node_modules/@prisma/client');
const { Client: PgClient } = require('/app/node_modules/pg');
const { createIntegrationTokenEnvelope } = require('./integration-token-envelope.js');
const { createMetaReceiptSigner } = require('./meta-receipt-signing.js');
const { createMetaRevocationPrismaStore } = require('./meta-revoke-prisma-store.js');
const { createMetaGraphProvider, createMetaRevocationControl, requireQuiescenceAssertionPath, validateQuiescenceAssertion, validateRequest } = require('./meta-revoke-control.js');

function publicErrorCode(error) {
  const candidate = typeof error?.code === 'string' ? error.code : (typeof error?.message === 'string' ? error.message : '');
  return /^(?:meta_|postiz_meta_|shared_meta_)[a-z0-9_]+$/u.test(candidate) ? candidate : 'meta_revoke_failed';
}

function reportError(error) {
  process.stderr.write(`${JSON.stringify({ status: 'failed', code: publicErrorCode(error) })}\n`);
  process.exitCode = 1;
}

function readPublicRequest(path) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error('meta_revoke_request_invalid');
  }
  return validateRequest(value);
}

function readPublicJson(path, code) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(code);
  }
}

async function main() {
  const requestIndex = process.argv.indexOf('--request');
  if (requestIndex < 0 || !process.argv[requestIndex + 1]) throw new Error('meta_revoke_request_file_required');
  const operation = process.argv.includes('--read-receipt') ? 'readRevocation' : (process.argv.includes('--apply') ? 'revoke' : 'plan');
  if (operation === 'revoke' && process.env.POSTIZ_META_REVOKE_APPLY !== 'YES') {
    throw new Error('meta_revoke_apply_not_authorized');
  }
  if (operation === 'revoke') {
    const quiescencePath = requireQuiescenceAssertionPath(process.argv);
    validateQuiescenceAssertion(readPublicJson(quiescencePath, 'meta_revoke_quiescence_assertion_invalid'));
  }

  const request = readPublicRequest(process.argv[requestIndex + 1]);
  const envelope = createIntegrationTokenEnvelope();
  const receiptSigner = createMetaReceiptSigner();
  const prisma = new PrismaClient();
  const store = createMetaRevocationPrismaStore({
    prisma,
    envelope,
    pgClientFactory: () => new PgClient({ connectionString: process.env.DATABASE_URL }),
  });
  const control = createMetaRevocationControl({ store, provider: createMetaGraphProvider(), receiptSigner });
  try {
    const result = await control[operation](request);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await prisma.$disconnect();
  }
}

process.once('uncaughtException', reportError);
process.once('unhandledRejection', reportError);
main().catch(reportError);
