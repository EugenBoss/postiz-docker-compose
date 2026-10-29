# Compose override — token envelope Postiz

The file docker-compose.meta-token-envelope.yaml is an opt-in override. The
current docker-compose.yaml remains the rollback path and is not modified.

The override:

- builds only from Dockerfile.meta-token-envelope, which pins Postiz v1.47.0 by digest;
- mounts the versioned keyring as a Docker secret at /run/secrets/postiz_integration_token_keys;
- mounts an Ed25519 Meta receipt keyring as a second runtime-only Docker secret; the JSON keyring names
  `activeKeyId`. In this prepared schema every `keys` entry is PKCS#8 private material, including inactive
  entries retained so the same module can derive their public keys and verify persisted receipts. This is
  a deliberate current-format limitation, not a claim that verification intrinsically needs private keys;
- requires the host-only path POSTIZ_INTEGRATION_TOKEN_KEYS_HOST_FILE and the non-secret
  active key id POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY;
- starts in reject mode, so legacy plaintext fails closed;
- keeps `POSTIZ_META_REVOKE_APPLY=NO` by default; the destructive internal CLI needs an
  explicit one-shot `YES` override in addition to `--apply`;
- contains no key material and never passes a key as a build argument.

Before any deployment, the dry-run migrator and backup procedure in
POSTIZ_META_TOKEN_ENCRYPTION.md must pass. OAuth remains disabled until the
encrypted image, migration read-back, and controlled Meta redirects are verified.

The patched dashboard, Public API and enterprise channel-delete routes refuse Facebook Page and Instagram
Business rows before they delete posts or soft-delete the channel; the shared Integration service repeats
the guard. Meta channel removal is only available through the receipt-bound one-shot flow documented in
`POSTIZ_META_TOKEN_ENCRYPTION.md`; ordinary deletion remains available for non-Meta providers. Upstream
whole-account erasure/anonymization is a separately documented account-lifecycle exception, not a
provider-revocation receipt path.

Rollback is the original Compose file and original pinned/runtime image. Do not
remove an old key id until the dry-run reports zero ciphertext rows using it.

Validation is read-only and does not start or recreate containers:

    node postiz-token-envelope/compose-overlay.test.mjs
