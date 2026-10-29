# Postiz Meta token envelope (v1.47.0)

This overlay pins the reviewed Postiz image and adds AES-256-GCM application-level encryption for
`Integration.token` and `Integration.refreshToken`. It does not contain credentials and is not enabled
by the current Compose runtime.

Runtime contract:

- `POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY`: non-secret key id, for example `k2026_10`.
- `POSTIZ_INTEGRATION_TOKEN_KEYS_FILE` (required): path to a runtime-mounted secret JSON keyring whose
  values are exactly 32 random bytes encoded as canonical base64. Inline
  `POSTIZ_INTEGRATION_TOKEN_KEYS` is rejected. Never commit the keyring or pass it as a Docker build
  argument.
- `POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE`: omitted/`reject` in normal runtime. `allow-read` exists only for
  the explicit migration command.

Before first encrypted startup, inspect legacy state without changing it:

```sh
node /opt/postiz-token-envelope/migrate-integration-tokens.mjs
```

The command reports counts only. Applying the migration additionally requires both `--apply` and the
one-shot environment guard `POSTIZ_INTEGRATION_TOKEN_MIGRATION_APPLY=YES`. Back up the Postiz database
before applying. Rotation is additive: install a new key id alongside the previous key, make it active,
then run the one-shot migrator. Remove an old key only after the dry-run reports no ciphertext using it.

The overlay deliberately fails startup if the active keyring file is absent or malformed, rejects inline
key material, and refuses legacy plaintext by default. AES-GCM additional authenticated data binds each
ciphertext to both `Integration.id` and its field name, so swapping ciphertext between rows or fields is
rejected. The migrator applies each row with compare-and-swap over `id`, `token`, and `refreshToken`; a
concurrent write aborts with `integration_token_migration_conflict`. Errors contain stable codes, never
token values.
