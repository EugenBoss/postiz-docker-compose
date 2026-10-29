import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

type PrismaMiddlewareParams = { model?: string; args?: unknown } & Record<string, unknown>;
type Next = (params: PrismaMiddlewareParams) => Promise<unknown>;

// Runtime source of truth is the reviewed CommonJS module copied beside the compiled Prisma service.
// Keeping this typed bridge in the image makes the AGPL source corresponding to the running patch available.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const implementation = require('./integration-token-envelope.js') as {
  createIntegrationTokenEnvelope(options?: { env?: NodeJS.ProcessEnv }): {
    middleware(params: PrismaMiddlewareParams, next: Next): Promise<unknown>;
  };
};

export const createIntegrationTokenEnvelope = implementation.createIntegrationTokenEnvelope;
export { createCipheriv, createDecipheriv, randomBytes };
