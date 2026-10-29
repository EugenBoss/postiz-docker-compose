import assert from 'node:assert/strict';
import test from 'node:test';
import { cp, mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const compiledFixture = `"use strict";\nconst client_1 = require("@prisma/client");\nclass PrismaService extends client_1.PrismaClient {\n    constructor() {\n        super({\n            log: [],\n        });\n    }\n    async onModuleInit() {}\n}\n`;
const sourceFixture = `import { PrismaClient } from '@prisma/client';\nexport class PrismaService extends PrismaClient {\n  constructor() {\n    super({\n      log: [],\n    });\n  }\n  async onModuleInit() {}\n}\n`;
const compiledControllerFixture = `"use strict";\nconst refresh_integration_service_1 = require("../../../../../libraries/nestjs-libraries/src/integrations/refresh.integration.service");\nclass IntegrationsController {\n    async deleteChannel(org, id) {\n        const isTherePosts = await this._integrationService.getPostsForChannel(org.id, id);\n        return this._integrationService.deleteChannel(org.id, id);\n    }\n}\n`;
const sourceControllerFixture = `import { RefreshIntegrationService } from '@gitroom/nestjs-libraries/integrations/refresh.integration.service';\nexport class IntegrationsController {\n  async deleteChannel(\n    @GetOrgFromRequest() org: Organization,\n    @Body('id') id: string\n  ) {\n    const isTherePosts = await this._integrationService.getPostsForChannel(\n      org.id,\n      id\n    );\n    return this._integrationService.deleteChannel(org.id, id);\n  }\n}\n`;
const compiledServiceFixture = `"use strict";\nconst integration_repository_1 = require("./integration.repository");\nclass IntegrationService {\n    async deleteChannel(org, id) {\n        return this._integrationRepository.deleteChannel(org, id);\n    }\n}\n`;
const sourceServiceFixture = `import { IntegrationRepository } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.repository';\nexport class IntegrationService {\n  async deleteChannel(org: string, id: string) {\n    return this._integrationRepository.deleteChannel(org, id);\n  }\n}\n`;
const compiledPublicControllerFixture = `"use strict";\nconst integration_service_1 = require("../../../../../../libraries/nestjs-libraries/src/database/prisma/integrations/integration.service");\nclass PublicIntegrationsController {\n    async deleteChannel(org, id) {\n        Sentry.metrics.count('public_api-request', 1);\n        const isTherePosts = await this._integrationService.getPostsForChannel(org.id, id);\n        return this._integrationService.deleteChannel(org.id, id);\n    }\n}\n`;
const sourcePublicControllerFixture = `import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';\nexport class PublicIntegrationsController {\n  async deleteChannel(org: Organization, id: string) {\n    Sentry.metrics.count('public_api-request', 1);\n    const isTherePosts = await this._integrationService.getPostsForChannel(\n      org.id,\n      id\n    );\n    return this._integrationService.deleteChannel(org.id, id);\n  }\n}\n`;
const compiledEnterpriseControllerFixture = `"use strict";\nconst integration_service_1 = require("../../../../../libraries/nestjs-libraries/src/database/prisma/integrations/integration.service");\nclass EnterpriseController {\n    async deleteChannel(params) {\n        const load = {};\n        const org = {};\n            if (!org) {\n                return { success: false };\n            }\n            const isTherePosts = await this._integrationService.getPostsForChannel(org.id, load.id);\n        await this._integrationService.deleteChannel(org.id, load.id);\n    }\n}\n`;
const sourceEnterpriseControllerFixture = `import { IntegrationService } from '@gitroom/nestjs-libraries/database/prisma/integrations/integration.service';\nexport class EnterpriseController {\n  async deleteChannel(params: string) {\n      const load = {} as any;\n      const org = {} as any;\n      if (!org) {\n        return { success: false };\n      }\n\n      const isTherePosts = await this._integrationService.getPostsForChannel(\n        org.id,\n        load.id\n      );\n      await this._integrationService.deleteChannel(org.id, load.id);\n  }\n}\n`;
const compiledRepositoryFixture = `class Repository {\n    async createOrUpdateIntegration(provider, internalId) {\n        const upsert = await this._integration.model.integration.upsert({\n            where: {},\n            create: {},\n            update: {\n            },\n        });\n        if (oneTimeToken) {\n        }\n        return upsert;\n    }\n}\n`;
const sourceRepositoryFixture = `class Repository {\n  async createOrUpdateIntegration(provider: string, internalId: string) {\n    const upsert = await this._integration.model.integration.upsert({\n      where: {},\n      create: {},\n      update: {\n      },\n    });\n\n    if (oneTimeToken) {\n    }\n    return upsert;\n  }\n}\n`;

test('patcher-ul modifică exact backend+orchestrator, păstrează sursa și este idempotent', async () => {
  const root = await mkdtemp(join(tmpdir(), 'postiz-token-patch-'));
  for (const target of ['apps/backend/dist/libraries/nestjs-libraries/src/database/prisma', 'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma']) {
    const directory = join(root, target);
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'prisma.service.js'), compiledFixture);
  }
  for (const target of ['apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/integrations', 'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma/integrations']) {
    const directory = join(root, target);
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'integration.repository.js'), compiledRepositoryFixture);
    await writeFile(join(directory, 'integration.service.js'), compiledServiceFixture);
  }
  for (const target of ['apps/backend/dist/libraries/nestjs-libraries/src/integrations', 'apps/orchestrator/dist/libraries/nestjs-libraries/src/integrations']) {
    await mkdir(join(root, target), { recursive: true });
  }
  const sourceDirectory = join(root, 'libraries/nestjs-libraries/src/database/prisma');
  await mkdir(sourceDirectory, { recursive: true });
  await writeFile(join(sourceDirectory, 'prisma.service.ts'), sourceFixture);
  const sourceIntegrationsDirectory = join(root, 'libraries/nestjs-libraries/src/integrations');
  await mkdir(sourceIntegrationsDirectory, { recursive: true });
  const compiledControllerDirectory = join(root, 'apps/backend/dist/apps/backend/src/api/routes');
  await mkdir(compiledControllerDirectory, { recursive: true });
  await writeFile(join(compiledControllerDirectory, 'integrations.controller.js'), compiledControllerFixture);
  const sourceControllerDirectory = join(root, 'apps/backend/src/api/routes');
  await mkdir(sourceControllerDirectory, { recursive: true });
  await writeFile(join(sourceControllerDirectory, 'integrations.controller.ts'), sourceControllerFixture);
  const sourceRepositoryDirectory = join(root, 'libraries/nestjs-libraries/src/database/prisma/integrations');
  await mkdir(sourceRepositoryDirectory, { recursive: true });
  await writeFile(join(sourceRepositoryDirectory, 'integration.repository.ts'), sourceRepositoryFixture);
  await writeFile(join(sourceRepositoryDirectory, 'integration.service.ts'), sourceServiceFixture);
  const compiledPublicDirectory = join(root, 'apps/backend/dist/apps/backend/src/public-api/routes/v1');
  await mkdir(compiledPublicDirectory, { recursive: true });
  await writeFile(join(compiledPublicDirectory, 'public.integrations.controller.js'), compiledPublicControllerFixture);
  const sourcePublicDirectory = join(root, 'apps/backend/src/public-api/routes/v1');
  await mkdir(sourcePublicDirectory, { recursive: true });
  await writeFile(join(sourcePublicDirectory, 'public.integrations.controller.ts'), sourcePublicControllerFixture);
  const compiledEnterpriseDirectory = join(root, 'apps/backend/dist/apps/backend/src/api/routes');
  await writeFile(join(compiledEnterpriseDirectory, 'enterprise.controller.js'), compiledEnterpriseControllerFixture);
  const sourceEnterpriseDirectory = join(root, 'apps/backend/src/api/routes');
  await writeFile(join(sourceEnterpriseDirectory, 'enterprise.controller.ts'), sourceEnterpriseControllerFixture);
  const script = new URL('./apply-patch.mjs', import.meta.url).pathname;
  for (let i = 0; i < 2; i += 1) {
    const run = spawnSync(process.execPath, [script, root], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
  }
  const compiled = await readFile(join(root, 'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/prisma.service.js'), 'utf8');
  assert.equal((compiled.match(/createIntegrationTokenEnvelope/g) || []).length, 1);
  assert.match(compiled, /this\.\$use\(tokenEnvelope\.middleware\)/u);
  assert.equal((await readFile(join(sourceDirectory, 'integration-token-envelope.ts'), 'utf8')).includes('createIntegrationTokenEnvelope'), true);
  const compiledController = await readFile(join(compiledControllerDirectory, 'integrations.controller.js'), 'utf8');
  const sourceController = await readFile(join(sourceControllerDirectory, 'integrations.controller.ts'), 'utf8');
  assert.equal((compiledController.match(/assertStandardDeleteAllowed/g) || []).length, 1);
  assert.equal((sourceController.match(/assertStandardDeleteAllowed/g) || []).length, 2);
  assert.equal(compiledController.indexOf('assertStandardDeleteAllowed') < compiledController.indexOf('getPostsForChannel'), true);
  assert.equal(sourceController.indexOf('assertStandardDeleteAllowed(integration)') < sourceController.indexOf('getPostsForChannel'), true);
  const compiledPublic = await readFile(join(compiledPublicDirectory, 'public.integrations.controller.js'), 'utf8');
  const sourcePublic = await readFile(join(sourcePublicDirectory, 'public.integrations.controller.ts'), 'utf8');
  const compiledEnterprise = await readFile(join(compiledEnterpriseDirectory, 'enterprise.controller.js'), 'utf8');
  const sourceEnterprise = await readFile(join(sourceEnterpriseDirectory, 'enterprise.controller.ts'), 'utf8');
  for (const controller of [compiledPublic, sourcePublic, compiledEnterprise, sourceEnterprise]) {
    assert.equal(controller.indexOf('assertStandardDeleteAllowed') < controller.indexOf('getPostsForChannel'), true);
  }
  for (const target of ['apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/integrations', 'apps/orchestrator/dist/libraries/nestjs-libraries/src/database/prisma/integrations']) {
    const service = await readFile(join(root, target, 'integration.service.js'), 'utf8');
    assert.equal(service.indexOf('assertStandardDeleteAllowed') < service.indexOf('_integrationRepository.deleteChannel'), true);
  }
  const sourceService = await readFile(join(sourceRepositoryDirectory, 'integration.service.ts'), 'utf8');
  assert.equal(sourceService.indexOf('assertStandardDeleteAllowed') < sourceService.indexOf('_integrationRepository.deleteChannel'), true);
  assert.equal((await readFile(join(sourceIntegrationsDirectory, 'meta-revoke-control.ts'), 'utf8')).includes('assertStandardDeleteAllowed'), true);
  const compiledRepository = await readFile(join(root, 'apps/backend/dist/libraries/nestjs-libraries/src/database/prisma/integrations/integration.repository.js'), 'utf8');
  const sourceRepository = await readFile(join(sourceRepositoryDirectory, 'integration.repository.ts'), 'utf8');
  assert.equal((compiledRepository.match(/pg_advisory_xact_lock/g) || []).length, 1);
  assert.equal((sourceRepository.match(/pg_advisory_xact_lock/g) || []).length, 1);
  assert.match(compiledRepository, /createHash\)\('sha256'\)/u);
  assert.match(sourceRepository, /createHash\('sha256'\)/u);
  assert.match(compiledRepository, /pending\.grantRef === grantRef/u);
  assert.match(sourceRepository, /pending\.grantRef === grantRef/u);
  assert.match(compiledRepository, /meta_grant_revoke_in_progress_or_completed/u);
  assert.match(sourceRepository, /meta_grant_revoke_in_progress_or_completed/u);
  assert.doesNotMatch(compiledRepository, /providerAccess/u);
  assert.doesNotMatch(sourceRepository, /providerAccess/u);
});
