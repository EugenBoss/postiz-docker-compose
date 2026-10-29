# Compose override — token envelope Postiz

The file docker-compose.meta-token-envelope.yaml is an opt-in override. The
current docker-compose.yaml remains the rollback path and is not modified.

The override:

- builds only from Dockerfile.meta-token-envelope, which pins Postiz v1.47.0 by digest;
- mounts the versioned keyring as a Docker secret at /run/secrets/postiz_integration_token_keys;
- requires the host-only path POSTIZ_INTEGRATION_TOKEN_KEYS_HOST_FILE and the non-secret
  active key id POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY;
- starts in reject mode, so legacy plaintext fails closed;
- contains no key material and never passes a key as a build argument.

Before any deployment, the dry-run migrator and backup procedure in
POSTIZ_META_TOKEN_ENCRYPTION.md must pass. OAuth remains disabled until the
encrypted image, migration read-back, and controlled Meta redirects are verified.

Rollback is the original Compose file and original pinned/runtime image. Do not
remove an old key id until the dry-run reports zero ciphertext rows using it.

Validation is read-only and does not start or recreate containers:

    node postiz-token-envelope/compose-overlay.test.mjs
