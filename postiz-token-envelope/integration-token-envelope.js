'use strict';

const { createCipheriv, createDecipheriv, randomBytes, randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');

const PREFIX = 'postizenc:v1:';
const FIELD_NAMES = new Set(['token', 'refreshToken']);
const KEY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const READ_RECORD_ACTIONS = new Set([
  'create', 'delete', 'findFirst', 'findFirstOrThrow', 'findUnique', 'findUniqueOrThrow', 'update', 'upsert',
]);
const READ_LIST_ACTIONS = new Set(['createManyAndReturn', 'findMany', 'updateManyAndReturn']);

function safeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function parseKeyring(env = process.env) {
  const activeKeyId = String(env.POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY || '').trim();
  if (!KEY_ID_RE.test(activeKeyId)) throw safeError('integration_token_active_key_invalid');

  const inline = String(env.POSTIZ_INTEGRATION_TOKEN_KEYS || '').trim();
  const file = String(env.POSTIZ_INTEGRATION_TOKEN_KEYS_FILE || '').trim();
  if (inline) throw safeError('integration_token_inline_keyring_forbidden');
  if (!file) throw safeError('integration_token_keyring_file_required');
  let serialized;
  try {
    serialized = readFileSync(file, { encoding: 'utf8', flag: 'r' });
  } catch {
    throw safeError('integration_token_keyring_unreadable');
  }
  let raw;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw safeError('integration_token_keyring_invalid');
  }
  if (!raw || Array.isArray(raw) || typeof raw !== 'object') throw safeError('integration_token_keyring_invalid');

  const keys = new Map();
  for (const [keyId, encoded] of Object.entries(raw)) {
    if (!KEY_ID_RE.test(keyId) || typeof encoded !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) {
      throw safeError('integration_token_keyring_invalid');
    }
    const key = Buffer.from(encoded, 'base64');
    if (key.length !== 32 || key.toString('base64') !== encoded) throw safeError('integration_token_keyring_invalid');
    keys.set(keyId, key);
  }
  if (!keys.has(activeKeyId)) throw safeError('integration_token_active_key_missing');

  const legacyMode = String(env.POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE || 'reject').trim();
  if (!['reject', 'allow-read'].includes(legacyMode)) throw safeError('integration_token_legacy_mode_invalid');
  return Object.freeze({ activeKeyId, keys, legacyMode });
}

function requireIntegrationId(integrationId) {
  if (typeof integrationId !== 'string' || integrationId.length === 0) {
    throw safeError('integration_token_integration_id_invalid');
  }
  return integrationId;
}

function aad(integrationId, field) {
  return Buffer.from(`postiz:Integration:${requireIntegrationId(integrationId)}:${field}:v1`, 'utf8');
}

function isPlainRecord(value) {
  if (!value || typeof value !== 'object' || value instanceof Date || Buffer.isBuffer(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function parseEnvelope(value) {
  if (typeof value !== 'string' || !value.startsWith(PREFIX)) return null;
  const parts = value.split(':');
  if (parts.length !== 6 || parts[0] !== 'postizenc' || parts[1] !== 'v1' || !KEY_ID_RE.test(parts[2])) {
    throw safeError('integration_token_ciphertext_invalid');
  }
  const [iv, tag, ciphertext] = parts.slice(3).map((part) => Buffer.from(part, 'base64url'));
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length < 1) throw safeError('integration_token_ciphertext_invalid');
  return { keyId: parts[2], iv, tag, ciphertext };
}

function createIntegrationTokenEnvelope({ env = process.env, randomBytesImpl = randomBytes, randomIdImpl = randomUUID } = {}) {
  const keyring = parseKeyring(env);

  function decrypt(integrationId, field, value) {
    requireIntegrationId(integrationId);
    if (!FIELD_NAMES.has(field)) throw safeError('integration_token_field_invalid');
    if (value === null || value === undefined || value === '') return value;
    if (typeof value !== 'string') throw safeError('integration_token_value_invalid');
    const envelope = parseEnvelope(value);
    if (!envelope) {
      if (keyring.legacyMode === 'allow-read') return value;
      throw safeError('integration_token_plaintext_detected');
    }
    const key = keyring.keys.get(envelope.keyId);
    if (!key) throw safeError('integration_token_key_unavailable');
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, envelope.iv);
      decipher.setAAD(aad(integrationId, field));
      decipher.setAuthTag(envelope.tag);
      return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]).toString('utf8');
    } catch {
      throw safeError('integration_token_decryption_failed');
    }
  }

  function encrypt(integrationId, field, value) {
    requireIntegrationId(integrationId);
    if (!FIELD_NAMES.has(field)) throw safeError('integration_token_field_invalid');
    if (value === null || value === undefined || value === '') return value;
    if (typeof value !== 'string') throw safeError('integration_token_value_invalid');
    const existing = parseEnvelope(value);
    const plaintext = existing ? decrypt(integrationId, field, value) : value;
    if (existing?.keyId === keyring.activeKeyId) return value;

    const iv = randomBytesImpl(12);
    if (!Buffer.isBuffer(iv) || iv.length !== 12) throw safeError('integration_token_nonce_invalid');
    const cipher = createCipheriv('aes-256-gcm', keyring.keys.get(keyring.activeKeyId), iv);
    cipher.setAAD(aad(integrationId, field));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${PREFIX}${keyring.activeKeyId}:${iv.toString('base64url')}:${tag.toString('base64url')}:${ciphertext.toString('base64url')}`;
  }

  function transformWrite(record, integrationId) {
    if (!isPlainRecord(record)) return record;
    const id = requireIntegrationId(integrationId || record.id);
    const output = { ...record };
    for (const field of FIELD_NAMES) {
      if (!Object.hasOwn(record, field)) continue;
      const value = record[field];
      output[field] = value && isPlainRecord(value) && Object.hasOwn(value, 'set')
        ? { ...value, set: encrypt(id, field, value.set) }
        : encrypt(id, field, value);
    }
    return output;
  }

  function transformIntegrationRecord(record) {
    if (!isPlainRecord(record)) return record;
    const hasEncryptedField = [...FIELD_NAMES].some((field) => Object.hasOwn(record, field));
    if (!hasEncryptedField) return record;
    const id = requireIntegrationId(record.id);
    const output = { ...record };
    for (const field of FIELD_NAMES) {
      if (Object.hasOwn(record, field)) output[field] = decrypt(id, field, record[field]);
    }
    return output;
  }

  function transformRead(value, action) {
    if (READ_LIST_ACTIONS.has(action)) {
      if (!Array.isArray(value)) return value;
      return value.map(transformIntegrationRecord);
    }
    if (READ_RECORD_ACTIONS.has(action)) return transformIntegrationRecord(value);
    return value;
  }

  function addReadId(params) {
    const select = params?.args?.select;
    if (!isPlainRecord(select) || select.id === true) return { params, stripId: false };
    const selectsToken = [...FIELD_NAMES].some((field) => select[field] === true);
    if (!selectsToken) return { params, stripId: false };
    return {
      params: { ...params, args: { ...params.args, select: { ...select, id: true } } },
      stripId: true,
    };
  }

  function stripInjectedId(value, action, stripId) {
    if (!stripId) return value;
    const strip = (record) => {
      if (!isPlainRecord(record)) return record;
      const { id: ignored, ...rest } = record;
      return rest;
    };
    return READ_LIST_ACTIONS.has(action) && Array.isArray(value) ? value.map(strip) : strip(value);
  }

  function hasTokenWrite(data) {
    return isPlainRecord(data) && [...FIELD_NAMES].some((field) => Object.hasOwn(data, field));
  }

  async function resolveExistingId(where, next) {
    if (typeof where?.id === 'string' && where.id.length > 0) return where.id;
    const existing = await next({ model: 'Integration', action: 'findUnique', args: { where, select: { id: true } } });
    return existing?.id || null;
  }

  async function transformWriteParams(params, next) {
    const args = params.args;
    if (!args || !isPlainRecord(args)) return params;
    if (params.action === 'create') {
      const data = isPlainRecord(args.data) ? args.data : {};
      const id = typeof data.id === 'string' && data.id.length > 0 ? data.id : randomIdImpl();
      return { ...params, args: { ...args, data: transformWrite({ ...data, id }, id) } };
    }
    if (params.action === 'createMany' || params.action === 'createManyAndReturn') {
      const input = Array.isArray(args.data) ? args.data : [args.data];
      const data = input.map((record) => {
        const id = typeof record?.id === 'string' && record.id.length > 0 ? record.id : randomIdImpl();
        return transformWrite({ ...record, id }, id);
      });
      return { ...params, args: { ...args, data: Array.isArray(args.data) ? data : data[0] } };
    }
    if (params.action === 'update' && hasTokenWrite(args.data)) {
      const id = await resolveExistingId(args.where, next);
      if (!id) throw safeError('integration_token_write_target_missing');
      return { ...params, args: { ...args, data: transformWrite(args.data, id) } };
    }
    if (params.action === 'upsert') {
      const existingId = await resolveExistingId(args.where, next);
      const create = isPlainRecord(args.create) ? args.create : {};
      const createId = typeof create.id === 'string' && create.id.length > 0 ? create.id : randomIdImpl();
      return {
        ...params,
        args: {
          ...args,
          create: transformWrite({ ...create, id: createId }, createId),
          update: hasTokenWrite(args.update) ? transformWrite(args.update, existingId || createId) : args.update,
        },
      };
    }
    return params;
  }

  async function runTokenUpdateMany(params, next) {
    const rows = await next({ model: 'Integration', action: 'findMany', args: { where: params.args.where, select: { id: true } } });
    if (!Array.isArray(rows)) throw safeError('integration_token_bulk_target_invalid');
    let count = 0;
    for (const row of rows) {
      const result = await next({
        model: 'Integration',
        action: 'updateMany',
        args: { where: { id: row.id }, data: transformWrite(params.args.data, row.id) },
      });
      count += Number(result?.count || 0);
    }
    return { count };
  }

  async function middleware(params, next) {
    if (params?.model !== 'Integration') return next(params);
    if (params.action === 'updateManyAndReturn' && hasTokenWrite(params.args?.data)) {
      throw safeError('integration_token_bulk_return_write_unsupported');
    }
    if (params.action === 'updateMany' && hasTokenWrite(params.args?.data)) {
      return runTokenUpdateMany(params, next);
    }
    const transformed = await transformWriteParams(params, next);
    const { params: readSafeParams, stripId } = addReadId(transformed);
    const result = await next(readSafeParams);
    return stripInjectedId(transformRead(result, params.action), params.action, stripId);
  }

  return Object.freeze({ encrypt, decrypt, transformWrite, transformRead, middleware, activeKeyId: keyring.activeKeyId });
}

module.exports = { createIntegrationTokenEnvelope, parseKeyring, PREFIX };
