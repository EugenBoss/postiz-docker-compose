import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const root = process.argv[2] || '/app';
const payload = new URL('.', import.meta.url).pathname;
const distTargets = [
  'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma',
  'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma',
];
const distIntegrationTargets = [
  'apps/backend/dist/libraries/nestjs-libraries/src/integrations',
  'apps/orchestrator/dist/libraries/nestjs-libraries/src/integrations',
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

for (const relative of distIntegrationTargets) {
  await copyFile(join(payload, 'meta-revoke-control.js'), join(root, relative, 'meta-revoke-control.js'));
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

const sourceIntegrationsDirectory = join(root, 'libraries/nestjs-libraries/src/integrations');
await copyFile(join(payload, 'meta-revoke-control.ts'), join(sourceIntegrationsDirectory, 'meta-revoke-control.ts'));
await copyFile(join(payload, 'meta-revoke-control.js'), join(sourceIntegrationsDirectory, 'meta-revoke-control.js'));

const compiledControllerPath = join(root, 'apps/backend/dist/apps/backend/src/api/routes/integrations.controller.js');
const compiledImportAnchor = 'const refresh_integration_service_1 = require("../../../../../libraries/nestjs-libraries/src/integrations/refresh.integration.service");';
const compiledImportPatch = `${compiledImportAnchor}\nconst meta_revoke_control_1 = require("../../../../../libraries/nestjs-libraries/src/integrations/meta-revoke-control");`;
const compiledDeleteAnchor = '    async deleteChannel(org, id) {\n        const isTherePosts = await this._integrationService.getPostsForChannel(org.id, id);';
const compiledDeletePatch = '    async deleteChannel(org, id) {\n        const integration = await this._integrationService.getIntegrationById(org.id, id);\n        (0, meta_revoke_control_1.assertStandardDeleteAllowed)(integration);\n        const isTherePosts = await this._integrationService.getPostsForChannel(org.id, id);';
let compiledController = await readFile(compiledControllerPath, 'utf8');
if (!compiledController.includes('meta_revoke_control_1')) {
  if (!compiledController.includes(compiledImportAnchor) || !compiledController.includes(compiledDeleteAnchor)) {
    throw new Error('postiz_meta_delete_guard_compiled_anchor_missing');
  }
  compiledController = compiledController.replace(compiledImportAnchor, compiledImportPatch).replace(compiledDeleteAnchor, compiledDeletePatch);
  await writeFile(compiledControllerPath, compiledController, 'utf8');
}

const sourceControllerPath = join(root, 'apps/backend/src/api/routes/integrations.controller.ts');
const sourceImportAnchor = "import { RefreshIntegrationService } from '@gitroom/nestjs-libraries/integrations/refresh.integration.service';";
const sourceImportPatch = `${sourceImportAnchor}\nimport { assertStandardDeleteAllowed } from '@gitroom/nestjs-libraries/integrations/meta-revoke-control';`;
const sourceDeleteAnchor = "  async deleteChannel(\n    @GetOrgFromRequest() org: Organization,\n    @Body('id') id: string\n  ) {\n    const isTherePosts = await this._integrationService.getPostsForChannel(\n      org.id,\n      id\n    );";
const sourceDeletePatch = "  async deleteChannel(\n    @GetOrgFromRequest() org: Organization,\n    @Body('id') id: string\n  ) {\n    const integration = await this._integrationService.getIntegrationById(\n      org.id,\n      id\n    );\n    assertStandardDeleteAllowed(integration);\n    const isTherePosts = await this._integrationService.getPostsForChannel(\n      org.id,\n      id\n    );";
let sourceController = await readFile(sourceControllerPath, 'utf8');
if (!sourceController.includes('assertStandardDeleteAllowed')) {
  if (!sourceController.includes(sourceImportAnchor) || !sourceController.includes(sourceDeleteAnchor)) {
    throw new Error('postiz_meta_delete_guard_source_anchor_missing');
  }
  sourceController = sourceController.replace(sourceImportAnchor, sourceImportPatch).replace(sourceDeleteAnchor, sourceDeletePatch);
  await writeFile(sourceControllerPath, sourceController, 'utf8');
}

const compiledIntegrationServiceTargets = [
  'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/integrations/integration.service.js',
  'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma/integrations/integration.service.js',
];
for (const relative of compiledIntegrationServiceTargets) {
  const path = join(root, relative);
  let service = await readFile(path, 'utf8');
  const importAnchor = 'const integration_repository_1 = require("./integration.repository");';
  const importPatch = `${importAnchor}\nconst meta_revoke_control_1 = require("../../../integrations/meta-revoke-control");`;
  const deleteAnchor = '    async deleteChannel(org, id) {\n        return this._integrationRepository.deleteChannel(org, id);\n    }';
  const deletePatch = '    async deleteChannel(org, id) {\n        const integration = await this._integrationRepository.getIntegrationById(org, id);\n        (0, meta_revoke_control_1.assertStandardDeleteAllowed)(integration);\n        return this._integrationRepository.deleteChannel(org, id);\n    }';
  if (!service.includes('meta_revoke_control_1')) {
    if (!service.includes(importAnchor) || !service.includes(deleteAnchor)) {
      throw new Error(`postiz_meta_delete_guard_service_compiled_anchor_missing:${relative}`);
    }
    service = service.replace(importAnchor, importPatch).replace(deleteAnchor, deletePatch);
    await writeFile(path, service, 'utf8');
  }
}

const sourceIntegrationServicePath = join(root, 'libraries/nestjs-libraries/src/database/prisma/integrations/integration.service.ts');
let sourceIntegrationService = await readFile(sourceIntegrationServicePath, 'utf8');
const sourceServiceImportAnchor = "import { IntegrationRepository } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.repository';";
const sourceServiceImportPatch = `${sourceServiceImportAnchor}\nimport { assertStandardDeleteAllowed } from '@gitroom/nestjs-libraries/integrations/meta-revoke-control';`;
const sourceServiceDeleteAnchor = '  async deleteChannel(org: string, id: string) {\n    return this._integrationRepository.deleteChannel(org, id);\n  }';
const sourceServiceDeletePatch = '  async deleteChannel(org: string, id: string) {\n    const integration = await this._integrationRepository.getIntegrationById(org, id);\n    assertStandardDeleteAllowed(integration);\n    return this._integrationRepository.deleteChannel(org, id);\n  }';
if (!sourceIntegrationService.includes('assertStandardDeleteAllowed')) {
  if (!sourceIntegrationService.includes(sourceServiceImportAnchor) || !sourceIntegrationService.includes(sourceServiceDeleteAnchor)) {
    throw new Error('postiz_meta_delete_guard_service_source_anchor_missing');
  }
  sourceIntegrationService = sourceIntegrationService
    .replace(sourceServiceImportAnchor, sourceServiceImportPatch)
    .replace(sourceServiceDeleteAnchor, sourceServiceDeletePatch);
  await writeFile(sourceIntegrationServicePath, sourceIntegrationService, 'utf8');
}

const additionalDeleteSurfaces = [
  {
    path: 'apps/backend/dist/apps/backend/src/public-api/routes/v1/public.integrations.controller.js',
    importAnchor: 'const integration_service_1 = require("../../../../../../libraries/nestjs-libraries/src/database/prisma/integrations/integration.service");',
    importPatch: 'const integration_service_1 = require("../../../../../../libraries/nestjs-libraries/src/database/prisma/integrations/integration.service");\nconst meta_revoke_control_1 = require("../../../../../../libraries/nestjs-libraries/src/integrations/meta-revoke-control");',
    deleteAnchor: "    async deleteChannel(org, id) {\n        Sentry.metrics.count('public_api-request', 1);\n        const isTherePosts = await this._integrationService.getPostsForChannel(org.id, id);",
    deletePatch: "    async deleteChannel(org, id) {\n        Sentry.metrics.count('public_api-request', 1);\n        const integration = await this._integrationService.getIntegrationById(org.id, id);\n        (0, meta_revoke_control_1.assertStandardDeleteAllowed)(integration);\n        const isTherePosts = await this._integrationService.getPostsForChannel(org.id, id);",
    errorCode: 'postiz_meta_delete_guard_public_compiled_anchor_missing',
  },
  {
    path: 'apps/backend/dist/apps/backend/src/api/routes/enterprise.controller.js',
    importAnchor: 'const integration_service_1 = require("../../../../../libraries/nestjs-libraries/src/database/prisma/integrations/integration.service");',
    importPatch: 'const integration_service_1 = require("../../../../../libraries/nestjs-libraries/src/database/prisma/integrations/integration.service");\nconst meta_revoke_control_1 = require("../../../../../libraries/nestjs-libraries/src/integrations/meta-revoke-control");',
    deleteAnchor: "            if (!org) {\n                return { success: false };\n            }\n            const isTherePosts = await this._integrationService.getPostsForChannel(org.id, load.id);",
    deletePatch: "            if (!org) {\n                return { success: false };\n            }\n            const integration = await this._integrationService.getIntegrationById(org.id, load.id);\n            (0, meta_revoke_control_1.assertStandardDeleteAllowed)(integration);\n            const isTherePosts = await this._integrationService.getPostsForChannel(org.id, load.id);",
    errorCode: 'postiz_meta_delete_guard_enterprise_compiled_anchor_missing',
  },
];
for (const target of additionalDeleteSurfaces) {
  const path = join(root, target.path);
  let controller = await readFile(path, 'utf8');
  if (!controller.includes('meta_revoke_control_1')) {
    if (!controller.includes(target.importAnchor) || !controller.includes(target.deleteAnchor)) throw new Error(target.errorCode);
    controller = controller.replace(target.importAnchor, target.importPatch).replace(target.deleteAnchor, target.deletePatch);
    await writeFile(path, controller, 'utf8');
  }
}

const sourceAdditionalDeleteSurfaces = [
  {
    path: 'apps/backend/src/public-api/routes/v1/public.integrations.controller.ts',
    importAnchor: "import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';",
    importPatch: "import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';\nimport { assertStandardDeleteAllowed } from '@gitroom/nestjs-libraries/integrations/meta-revoke-control';",
    deleteAnchor: "    Sentry.metrics.count('public_api-request', 1);\n    const isTherePosts = await this._integrationService.getPostsForChannel(\n      org.id,\n      id\n    );",
    deletePatch: "    Sentry.metrics.count('public_api-request', 1);\n    const integration = await this._integrationService.getIntegrationById(org.id, id);\n    assertStandardDeleteAllowed(integration);\n    const isTherePosts = await this._integrationService.getPostsForChannel(\n      org.id,\n      id\n    );",
    errorCode: 'postiz_meta_delete_guard_public_source_anchor_missing',
  },
  {
    path: 'apps/backend/src/api/routes/enterprise.controller.ts',
    importAnchor: "import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';",
    importPatch: "import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';\nimport { assertStandardDeleteAllowed } from '@gitroom/nestjs-libraries/integrations/meta-revoke-control';",
    deleteAnchor: "      if (!org) {\n        return { success: false };\n      }\n\n      const isTherePosts = await this._integrationService.getPostsForChannel(\n        org.id,\n        load.id\n      );",
    deletePatch: "      if (!org) {\n        return { success: false };\n      }\n\n      const integration = await this._integrationService.getIntegrationById(org.id, load.id);\n      assertStandardDeleteAllowed(integration);\n      const isTherePosts = await this._integrationService.getPostsForChannel(\n        org.id,\n        load.id\n      );",
    errorCode: 'postiz_meta_delete_guard_enterprise_source_anchor_missing',
  },
];
for (const target of sourceAdditionalDeleteSurfaces) {
  const path = join(root, target.path);
  let controller = await readFile(path, 'utf8');
  if (!controller.includes('assertStandardDeleteAllowed')) {
    if (!controller.includes(target.importAnchor) || !controller.includes(target.deleteAnchor)) throw new Error(target.errorCode);
    controller = controller.replace(target.importAnchor, target.importPatch).replace(target.deleteAnchor, target.deletePatch);
    await writeFile(path, controller, 'utf8');
  }
}

function patchMetaConnectLock(source, { opening, closing, replacementOpening, replacementClosing, errorCode }) {
  if (source.includes('meta_grant_revoke_in_progress_or_completed')) return source;
  const start = source.indexOf(opening);
  if (start < 0) throw new Error(errorCode);
  const end = source.indexOf(closing, start + opening.length);
  if (end < 0) throw new Error(errorCode);
  return source.slice(0, start)
    + replacementOpening
    + source.slice(start + opening.length, end)
    + replacementClosing
    + source.slice(end + closing.length);
}

const compiledRepositoryTargets = [
  'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/integrations/integration.repository.js',
  'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma/integrations/integration.repository.js',
];
for (const relative of compiledRepositoryTargets) {
  const path = join(root, relative);
  let repository = await readFile(path, 'utf8');
  repository = patchMetaConnectLock(repository, {
    opening: '        const upsert = await this._integration.model.integration.upsert({',
    closing: '            },\n        });\n        if (oneTimeToken) {',
    replacementOpening: `        const upsert = await this._integration.model.$transaction(async (transaction) => {\n            if (provider === 'facebook' || provider === 'instagram') {\n                const grantRef = refreshToken ? (0, crypto_1.createHash)('sha256').update(refreshToken).digest('hex') : null;\n                const lockKeys = [\`root:\${internalId}\`];\n                if (grantRef) lockKeys.push(\`grant:\${grantRef}\`);\n                for (const lockKey of lockKeys.sort()) {\n                    await transaction.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', lockKey);\n                }\n                const revokeStates = await transaction.integration.findMany({\n                    where: { providerIdentifier: { in: ['facebook', 'instagram'] } },\n                    select: { rootInternalId: true, additionalSettings: true },\n                });\n                const blocked = revokeStates.some(({ rootInternalId, additionalSettings }) => {\n                    try {\n                        const pending = JSON.parse(additionalSettings || '[]')?._postizMetaRevokePending;\n                        return !!pending && (rootInternalId === internalId || (!!grantRef && pending.grantRef === grantRef));\n                    } catch {\n                        return false;\n                    }\n                });\n                if (blocked) throw new Error('meta_grant_revoke_in_progress_or_completed');\n            }\n            return transaction.integration.upsert({`,
    replacementClosing: '            },\n            });\n        });\n        if (oneTimeToken) {',
    errorCode: `postiz_meta_connect_lock_compiled_anchor_missing:${relative}`,
  });
  await writeFile(path, repository, 'utf8');
}

const sourceRepositoryPath = join(root, 'libraries/nestjs-libraries/src/database/prisma/integrations/integration.repository.ts');
let sourceRepository = await readFile(sourceRepositoryPath, 'utf8');
sourceRepository = patchMetaConnectLock(sourceRepository, {
  opening: '    const upsert = await this._integration.model.integration.upsert({',
  closing: '      },\n    });\n\n    if (oneTimeToken) {',
  replacementOpening: `    const upsert = await this._integration.model.$transaction(async (transaction) => {\n      if (provider === 'facebook' || provider === 'instagram') {\n        const grantRef = refreshToken ? createHash('sha256').update(refreshToken).digest('hex') : null;\n        const lockKeys = [\`root:\${internalId}\`];\n        if (grantRef) lockKeys.push(\`grant:\${grantRef}\`);\n        for (const lockKey of lockKeys.sort()) {\n          await transaction.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', lockKey);\n        }\n        const revokeStates = await transaction.integration.findMany({\n          where: { providerIdentifier: { in: ['facebook', 'instagram'] } },\n          select: { rootInternalId: true, additionalSettings: true },\n        });\n        const blocked = revokeStates.some(({ rootInternalId, additionalSettings }) => {\n          try {\n            const pending = JSON.parse(additionalSettings || '[]')?._postizMetaRevokePending;\n            return !!pending && (rootInternalId === internalId || (!!grantRef && pending.grantRef === grantRef));\n          } catch {\n            return false;\n          }\n        });\n        if (blocked) throw new Error('meta_grant_revoke_in_progress_or_completed');\n      }\n      return transaction.integration.upsert({`,
  replacementClosing: '      },\n      });\n    });\n\n    if (oneTimeToken) {',
  errorCode: 'postiz_meta_connect_lock_source_anchor_missing',
});
await writeFile(sourceRepositoryPath, sourceRepository, 'utf8');

process.stdout.write(`postiz token envelope, Meta delete guard, and connect lock applied to ${distTargets.length}/2 runtimes\n`);
