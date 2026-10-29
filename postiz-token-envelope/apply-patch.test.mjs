import assert from 'node:assert/strict';
import test from 'node:test';
import { cp, mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const compiledFixture = `"use strict";\nconst client_1 = require("@prisma/client");\nclass PrismaService extends client_1.PrismaClient {\n    constructor() {\n        super({\n            log: [],\n        });\n    }\n    async onModuleInit() {}\n}\n`;
const sourceFixture = `import { PrismaClient } from '@prisma/client';\nexport class PrismaService extends PrismaClient {\n  constructor() {\n    super({\n      log: [],\n    });\n  }\n  async onModuleInit() {}\n}\n`;

test('patcher-ul modifică exact backend+orchestrator, păstrează sursa și este idempotent', async () => {
  const root = await mkdtemp(join(tmpdir(), 'postiz-token-patch-'));
  for (const target of ['apps/backend/dist/libraries/nestjs-libraries/src/database/prisma', 'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma']) {
    const directory = join(root, target);
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'prisma.service.js'), compiledFixture);
  }
  const sourceDirectory = join(root, 'libraries/nestjs-libraries/src/database/prisma');
  await mkdir(sourceDirectory, { recursive: true });
  await writeFile(join(sourceDirectory, 'prisma.service.ts'), sourceFixture);
  const script = new URL('./apply-patch.mjs', import.meta.url).pathname;
  for (let i = 0; i < 2; i += 1) {
    const run = spawnSync(process.execPath, [script, root], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
  }
  const compiled = await readFile(join(root, 'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/prisma.service.js'), 'utf8');
  assert.equal((compiled.match(/createIntegrationTokenEnvelope/g) || []).length, 1);
  assert.match(compiled, /this\.\$use\(tokenEnvelope\.middleware\)/u);
  assert.equal((await readFile(join(sourceDirectory, 'integration-token-envelope.ts'), 'utf8')).includes('createIntegrationTokenEnvelope'), true);
});
