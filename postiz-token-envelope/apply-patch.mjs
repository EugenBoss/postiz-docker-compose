import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const root = process.argv[2] || '/app';
const payload = new URL('.', import.meta.url).pathname;
const distTargets = [
  'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma',
  'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma',
];

const requireAnchor = 'const client_1 = require("@prisma/client");';
const requirePatch = `${requireAnchor}\nconst integration_token_envelope_1 = require("./integration-token-envelope");`;
const constructorAnchor = "        });\n    }\n    async onModuleInit()";
const constructorPatch = "        });\n        const tokenEnvelope = (0, integration_token_envelope_1.createIntegrationTokenEnvelope)();\n        this.$use(tokenEnvelope.middleware);\n    }\n    async onModuleInit()";

for (const relative of distTargets) {
  const directory = join(root, relative);
  const servicePath = join(directory, 'prisma.service.js');
  const envelopePath = join(directory, 'integration-token-envelope.js');
  let source = await readFile(servicePath, 'utf8');
  if (!source.includes('integration_token_envelope_1')) {
    if (!source.includes(requireAnchor) || !source.includes(constructorAnchor)) throw new Error(`postiz_patch_anchor_missing:${relative}`);
    source = source.replace(requireAnchor, requirePatch).replace(constructorAnchor, constructorPatch);
    await writeFile(servicePath, source, 'utf8');
  }
  await copyFile(join(payload, 'integration-token-envelope.js'), envelopePath);
}

const sourceDirectory = join(root, 'libraries/nestjs-libraries/src/database/prisma');
const sourceServicePath = join(sourceDirectory, 'prisma.service.ts');
let sourceTs = await readFile(sourceServicePath, 'utf8');
const importAnchor = "import { PrismaClient } from '@prisma/client';";
const importPatch = `${importAnchor}\nimport { createIntegrationTokenEnvelope } from './integration-token-envelope';`;
const sourceConstructorAnchor = "    });\n  }\n  async onModuleInit()";
const sourceConstructorPatch = "    });\n    const tokenEnvelope = createIntegrationTokenEnvelope();\n    this.$use(tokenEnvelope.middleware);\n  }\n  async onModuleInit()";
if (!sourceTs.includes('createIntegrationTokenEnvelope')) {
  if (!sourceTs.includes(importAnchor) || !sourceTs.includes(sourceConstructorAnchor)) throw new Error('postiz_source_patch_anchor_missing');
  sourceTs = sourceTs.replace(importAnchor, importPatch).replace(sourceConstructorAnchor, sourceConstructorPatch);
  await writeFile(sourceServicePath, sourceTs, 'utf8');
}
await copyFile(join(payload, 'integration-token-envelope.ts'), join(sourceDirectory, 'integration-token-envelope.ts'));
await copyFile(join(payload, 'integration-token-envelope.js'), join(sourceDirectory, 'integration-token-envelope.js'));

process.stdout.write(`postiz token envelope patch applied to ${distTargets.length}/2 runtimes\n`);
