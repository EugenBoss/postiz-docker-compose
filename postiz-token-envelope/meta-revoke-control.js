'use strict';

const { createHash } = require('node:crypto');

const META_PROVIDERS = new Set(['facebook', 'instagram']);
const PUBLIC_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$/u;
const IDEMPOTENCY_RE = /^[a-f0-9]{64}$/u;
const SECRET_KEY_RE = /^(?:access[_-]?token|refresh[_-]?token|token|secret|password|authorization|cookie|api[_-]?key)$/iu;
const REQUEST_KEYS = new Set([
  'integrationId',
  'expectedPlatform',
  'expectedExternalAccountId',
  'expectedCredentialVersion',
  'idempotencyKey',
  'actorPrincipal',
  'reason',
]);

function safeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function isMetaProvider(providerIdentifier) {
  return META_PROVIDERS.has(providerIdentifier);
}

function assertStandardDeleteAllowed(integration) {
  if (integration && isMetaProvider(integration.providerIdentifier)) {
    throw safeError('meta_provider_revoke_receipt_required');
  }
}

function publicId(value, code) {
  if (typeof value !== 'string' || !PUBLIC_ID_RE.test(value)) throw safeError(code);
  return value;
}

function validateRequest(input) {
  if (!input || Array.isArray(input) || typeof input !== 'object') throw safeError('meta_revoke_request_invalid');
  for (const key of Object.keys(input)) {
    if (SECRET_KEY_RE.test(key)) throw safeError('meta_revoke_request_secret_forbidden');
    if (!REQUEST_KEYS.has(key)) throw safeError('meta_revoke_request_invalid');
  }
  const integrationId = publicId(input.integrationId, 'meta_revoke_integration_id_invalid');
  const expectedExternalAccountId = publicId(input.expectedExternalAccountId, 'meta_revoke_external_account_id_invalid');
  if (!META_PROVIDERS.has(input.expectedPlatform)) throw safeError('meta_revoke_platform_invalid');
  if (!Number.isSafeInteger(input.expectedCredentialVersion) || input.expectedCredentialVersion <= 0) {
    throw safeError('meta_revoke_credential_version_invalid');
  }
  if (typeof input.idempotencyKey !== 'string' || !IDEMPOTENCY_RE.test(input.idempotencyKey)) {
    throw safeError('meta_revoke_idempotency_key_invalid');
  }
  if (typeof input.actorPrincipal !== 'string' || input.actorPrincipal.length < 1 || input.actorPrincipal.length > 256) {
    throw safeError('meta_revoke_actor_invalid');
  }
  if (typeof input.reason !== 'string' || input.reason.length < 1 || input.reason.length > 512) {
    throw safeError('meta_revoke_reason_invalid');
  }
  return Object.freeze({
    integrationId,
    expectedPlatform: input.expectedPlatform,
    expectedExternalAccountId,
    expectedCredentialVersion: input.expectedCredentialVersion,
    idempotencyKey: input.idempotencyKey,
    actorPrincipal: input.actorPrincipal,
    reason: input.reason,
  });
}

function validateQuiescenceAssertion(input, now = () => new Date()) {
  const allowed = new Set(['receiptId', 'oauthCallbacksQuiesced', 'inFlightFlows', 'observedAt', 'expiresAt']);
  if (!input || Array.isArray(input) || typeof input !== 'object' || Object.keys(input).some((key) => !allowed.has(key))) {
    throw safeError('meta_revoke_quiescence_assertion_invalid');
  }
  publicId(input.receiptId, 'meta_revoke_quiescence_assertion_invalid');
  const observedAt = Date.parse(input.observedAt);
  const expiresAt = Date.parse(input.expiresAt);
  if (input.oauthCallbacksQuiesced !== true || input.inFlightFlows !== 0
      || !Number.isFinite(observedAt) || !Number.isFinite(expiresAt)
      || observedAt > now().getTime() || expiresAt <= now().getTime() || expiresAt <= observedAt) {
    throw safeError('meta_revoke_quiescence_assertion_invalid');
  }
  return Object.freeze({
    receiptId: input.receiptId,
    oauthCallbacksQuiesced: true,
    inFlightFlows: 0,
    observedAt: new Date(observedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
  });
}

function requireQuiescenceAssertionPath(argv) {
  const index = Array.isArray(argv) ? argv.indexOf('--operator-quiescence-assertion') : -1;
  if (index < 0 || typeof argv[index + 1] !== 'string' || argv[index + 1].length === 0) {
    throw safeError('meta_revoke_quiescence_assertion_required');
  }
  return argv[index + 1];
}

function makeReceiptId(request) {
  const digest = createHash('sha256')
    .update(request.idempotencyKey)
    .update('\0')
    .update(request.integrationId)
    .digest('hex')
    .slice(0, 48);
  return `meta_rvk:${digest}`;
}

function receiptMatchesRequest(receipt, request) {
  return receipt?.integrationId === request.integrationId
    && receipt?.provider === 'meta'
    && receipt?.platform === request.expectedPlatform
    && receipt?.externalAccountId === request.expectedExternalAccountId
    && receipt?.credentialVersion === request.expectedCredentialVersion
    && receipt?.idempotencyKey === request.idempotencyKey;
}

function activeSiblings(rows, target) {
  return rows.filter((row) => {
    if (row.id === target.id || row.deletedAt || !isMetaProvider(row.providerIdentifier)) return false;
    const sharesRoot = typeof target.rootInternalId === 'string' && target.rootInternalId.length > 0
      && row.rootInternalId === target.rootInternalId;
    const sharesGrant = typeof target.refreshToken === 'string' && target.refreshToken.length > 0
      && row.refreshToken === target.refreshToken;
    return sharesRoot || sharesGrant;
  });
}

function grantLockKeys(target) {
  const keys = [`root:${target.rootInternalId}`];
  if (typeof target.refreshToken === 'string' && target.refreshToken.length > 0) {
    keys.push(`grant:${createHash('sha256').update(target.refreshToken).digest('hex')}`);
  }
  return [...new Set(keys)].sort();
}

function createMetaRevocationControl({ store, provider, receiptSigner, now = () => new Date() }) {
  if (!store || !provider || !receiptSigner || typeof store.withGrantLock !== 'function') {
    throw safeError('meta_revoke_dependencies_invalid');
  }

  async function load(request) {
    let rows;
    try {
      rows = await store.loadAllMetaIntegrations();
    } catch {
      throw safeError('meta_revoke_store_failed');
    }
    if (!Array.isArray(rows)) throw safeError('meta_revoke_store_result_invalid');
    const target = rows.find((row) => row.id === request.integrationId);
    if (!target) throw safeError('meta_revoke_target_not_found');
    if (target.revokeReceipt) {
      if (receiptSigner.verifyReceipt(target.revokeReceipt) !== true) throw safeError('meta_revoke_receipt_signature_invalid');
      if (!receiptMatchesRequest(target.revokeReceipt, request)) throw safeError('postiz_meta_revocation_conflict');
      return { rows, target, replayReceipt: target.revokeReceipt };
    }
    if (target.revokePending) {
      if (target.revokePending.idempotencyKey !== request.idempotencyKey) throw safeError('postiz_meta_revocation_conflict');
      throw safeError('meta_revoke_recovery_required');
    }
    if (target.deletedAt) throw safeError('meta_revoke_target_not_found');
    if (!isMetaProvider(target.providerIdentifier)) throw safeError('meta_revoke_provider_unsupported');
    if (target.providerIdentifier !== request.expectedPlatform) throw safeError('meta_revoke_identity_mismatch');
    if (target.internalId !== request.expectedExternalAccountId) throw safeError('meta_revoke_identity_mismatch');
    if (typeof target.refreshToken !== 'string' || target.refreshToken.length === 0) {
      throw safeError('meta_revoke_user_grant_missing');
    }
    if (typeof target.rootInternalId !== 'string' || target.rootInternalId.length === 0) {
      throw safeError('meta_revoke_root_identity_missing');
    }
    return { rows, target, replayReceipt: null };
  }

  async function plan(input) {
    const request = validateRequest(input);
    const state = await load(request);
    if (state.replayReceipt) return { replay: true, receipt: state.replayReceipt };
    const siblings = activeSiblings(state.rows, state.target).map((row) => row.id).sort();
    return Object.freeze({
      integrationId: state.target.id,
      platform: state.target.providerIdentifier,
      externalAccountId: state.target.internalId,
      credentialVersion: request.expectedCredentialVersion,
      killSwitchEngaged: state.target.disabled === true,
      providerRevocationAllowed: siblings.length === 0,
      activeSiblingIntegrationIds: siblings,
    });
  }

  async function readRevocation(input) {
    const request = validateRequest(input);
    const state = await load(request);
    if (state.replayReceipt) {
      return state.replayReceipt;
    }
    throw safeError('meta_revoke_receipt_not_found');
  }

  async function revoke(input) {
    const request = validateRequest(input);
    const initial = await load(request);
    if (initial.replayReceipt) return initial.replayReceipt;
    return store.withGrantLock(grantLockKeys(initial.target), async () => {
      const state = await load(request);
      if (state.replayReceipt) return state.replayReceipt;

      let killed;
      try {
        killed = await store.killSwitchTargetCas(state.target, { actorPrincipal: request.actorPrincipal, reason: request.reason });
      } catch {
        throw safeError('meta_revoke_kill_switch_failed');
      }
      if (killed !== 1) throw safeError('meta_revoke_kill_switch_failed');

      const siblings = activeSiblings(state.rows, state.target);
      let providerAccess = 'retained_for_siblings';
      let providerRevokedAt = null;
      if (siblings.length === 0) {
      let marked;
      try {
        marked = await store.markProviderAttemptCas(state.target, {
          idempotencyKey: request.idempotencyKey,
          integrationId: request.integrationId,
          platform: request.expectedPlatform,
          externalAccountId: request.expectedExternalAccountId,
          credentialVersion: request.expectedCredentialVersion,
          grantRef: createHash('sha256').update(state.target.refreshToken).digest('hex'),
          startedAt: now().toISOString(),
        });
      } catch {
        throw safeError('meta_revoke_provider_attempt_cas_failed');
      }
      if (marked !== 1) throw safeError('meta_revoke_provider_attempt_cas_failed');

      let acknowledgment;
      try {
        acknowledgment = await provider.revokeGrant({
          rootInternalId: state.target.rootInternalId,
          grantToken: state.target.refreshToken,
        });
      } catch {
        throw safeError('meta_revoke_provider_failed');
      }
      if (acknowledgment?.acknowledged !== true) throw safeError('meta_revoke_provider_ack_missing');

      let readBack;
      try {
        readBack = await provider.readBackGrant({
          rootInternalId: state.target.rootInternalId,
          grantToken: state.target.refreshToken,
        });
      } catch {
        throw safeError('meta_revoke_provider_readback_failed');
      }
      if (readBack?.revoked !== true) throw safeError('meta_revoke_provider_readback_unconfirmed');
      providerAccess = 'revoked';
      providerRevokedAt = now().toISOString();
      }

      const credentialInvalidatedAt = now().toISOString();
      const unsignedReceipt = {
      integrationId: request.integrationId,
      provider: 'meta',
      platform: request.expectedPlatform,
      externalAccountId: request.expectedExternalAccountId,
      credentialVersion: request.expectedCredentialVersion,
      providerAccess,
      siblingCount: siblings.length,
      localCredential: 'invalidated',
      killSwitchEngaged: true,
      receiptId: makeReceiptId(request),
      providerRevokedAt,
      credentialInvalidatedAt,
      idempotencyKey: request.idempotencyKey,
      };
      const receipt = receiptSigner.signReceipt(unsignedReceipt);

      let invalidated;
      try {
        invalidated = await store.invalidateTargetCas(state.target, { receipt, revokedAt: new Date(credentialInvalidatedAt) });
      } catch {
        throw safeError('meta_revoke_local_cas_failed');
      }
      if (invalidated !== 1) throw safeError('meta_revoke_local_cas_failed');
      return receipt;
    });
  }

  return Object.freeze({ plan, readRevocation, revoke });
}

function createMetaGraphProvider({ fetchImpl = globalThis.fetch, graphBaseUrl = 'https://graph.facebook.com/v25.0' } = {}) {
  if (typeof fetchImpl !== 'function') throw safeError('meta_provider_fetch_unavailable');

  async function request(method, rootInternalId, grantToken) {
    publicId(rootInternalId, 'meta_provider_root_identity_invalid');
    if (typeof grantToken !== 'string' || grantToken.length === 0) throw safeError('meta_provider_grant_missing');
    const endpoint = `${graphBaseUrl.replace(/\/$/u, '')}/${encodeURIComponent(rootInternalId)}/permissions`;
    try {
      const response = await fetchImpl(endpoint, {
        method,
        headers: { authorization: `Bearer ${grantToken}`, accept: 'application/json' },
      });
      let body = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      return { ok: response.ok, body };
    } catch {
      throw safeError('meta_provider_unreachable');
    }
  }

  return Object.freeze({
    async revokeGrant({ rootInternalId, grantToken }) {
      const response = await request('DELETE', rootInternalId, grantToken);
      return { acknowledged: response.ok && response.body?.success === true };
    },
    async readBackGrant({ rootInternalId, grantToken }) {
      const response = await request('GET', rootInternalId, grantToken);
      const invalidToken = !response.ok && response.body?.error?.code === 190;
      const noPermissions = response.ok && Array.isArray(response.body?.data) && response.body.data.length === 0;
      return { revoked: invalidToken || noPermissions };
    },
  });
}

module.exports = {
  assertStandardDeleteAllowed,
  createMetaGraphProvider,
  createMetaRevocationControl,
  isMetaProvider,
  requireQuiescenceAssertionPath,
  validateQuiescenceAssertion,
  validateRequest,
};
