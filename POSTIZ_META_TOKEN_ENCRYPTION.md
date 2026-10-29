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
- `POSTIZ_META_REVOCATION_SIGNING_KEY_FILE`: required runtime-only JSON keyring
  `{ "activeKeyId": "...", "keys": { "id": "Ed25519 PKCS#8 PEM" } }`. Inline signing keys are
  rejected. Only `activeKeyId` signs new receipts; all still-present keys verify persisted receipts, so
  signing-key rotation does not break replay/read-back. The prepared schema currently requires PKCS#8
  private material even for inactive verifier entries; this is a keyring-format limitation, while Admin
  receives only the matching public-key ring.

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

## Meta grant revocation

Facebook Pages and Instagram Business rows can share one long-lived Meta user grant. The overlay never
revokes the provider grant while another non-deleted Meta row has the same `rootInternalId` or decrypted
`refreshToken`. It first engages the kill switch for the requested target, then locally invalidates and
soft-deletes only that target. This non-last path performs zero provider egress and returns a signed
receipt with `providerAccess:'retained_for_siblings'` and the positive `siblingCount`. Provider revocation
is allowed only when the target is the last active row for that grant.

All three v1.47.0 channel-delete entry points (dashboard, Public API and enterprise callback) are patched
to return `meta_provider_revoke_receipt_required` for `facebook` and `instagram` before they delete posts
or soft-delete the row. `IntegrationService.deleteChannel` repeats the guard centrally as defense in
depth. Non-Meta channel deletion is unchanged. The receipt-bound internal CLI is the only prepared Meta
**channel-removal** path. The separate upstream whole-account erasure/anonymization routine remains an
account-lifecycle exception: it hashes/soft-deletes integrations and is not a provider-revocation receipt
flow. The CLI request matches the Admin contract and contains public metadata only:

```json
{
  "integrationId": "public-integration-id",
  "expectedPlatform": "facebook",
  "expectedExternalAccountId": "public-page-id",
  "expectedCredentialVersion": 17,
  "idempotencyKey": "64-lowercase-hex-characters",
  "actorPrincipal": "public-actor-reference",
  "reason": "disconnect requested"
}
```

Unknown or secret-shaped keys are rejected. `expectedCredentialVersion` is the positive caller-owned
Admin counter: Postiz validates, persists and echoes it exactly, while its local CAS independently binds
the operation to the current ciphertext snapshot. Admin derives `idempotencyKey` as SHA-256 over its
documented brand/platform/identity/version tuple; Postiz validates, binds and persists the exact key, but
does not need `brandId` or any credential in the request.

Run without `--apply` first. Planning performs no provider request and returns the public identity,
credential version, kill-switch state and whether an active sibling blocks provider revocation:

```sh
node /opt/postiz-token-envelope/meta-revoke-cli.mjs --request /run/meta-request.json
```

An apply additionally requires `--apply`, `POSTIZ_META_REVOKE_APPLY=YES`, and
`--operator-quiescence-assertion /run/meta-oauth-quiescence.json`. This public, nonsecret, self-asserted
file is only a fail-closed operator guard, not an attestation or proof. It is accepted only while it says
`oauthCallbacksQuiesced:true`, `inFlightFlows:0` and has an unexpired observation window.
It proceeds in this order:

1. Acquire PostgreSQL advisory session locks on a dedicated connection, in canonical order, for both
   `rootInternalId` and the SHA-256 grant reference, then reload the group under the locks. Concurrent
   sibling removals remain serialized even when rows share a grant but have divergent roots.
2. CAS-enable `disabled=true` for the target before any provider call.
3. If a sibling remains, skip provider egress and locally invalidate only the target.
4. For the last channel only, persist a provider-attempt marker, then call Graph v25
   `/{rootInternalId}/permissions` with a Bearer header.
5. Require a 2xx `{success:true}` ACK and an independent read-back showing error 190 or no permissions.
6. CAS-match the original ciphertexts/settings, replace the access token with an encrypted invalid
   sentinel, null `refreshToken`, keep the kill switch on, soft-delete only the target, and persist the
   exact Admin-compatible receipt in `additionalSettings`.

The receipt contains the requested integration/platform/external identity/version/key plus
`provider:'meta'`, provider/local states, `siblingCount`, deterministic `receiptId`, and timestamps. It is
signed Ed25519 over canonical JSON including identity, version, idempotency, status, sibling count, key id
and timestamps; output adds base64url `receiptSignature` and non-secret `receiptKeyId`. A replay with the
same binding verifies the stored signature and returns the byte-equivalent receipt without provider
egress. A divergent key, identity or version returns `postiz_meta_revocation_conflict`.
`--read-receipt` implements the internal `readMetaRevocation` contract and returns that identical signed
receipt from the soft-deleted row; the minimal public integrations GET is not revocation evidence.

For the last-channel provider path, the provider-attempt marker is durable before egress. Any timeout,
missing ACK, ambiguous read-back, or crash before local CAS leaves the target kill-switched and returns no
revoked receipt. Automatic retry is refused with `meta_revoke_recovery_required`; recovery must reconcile
the provider state and the pending marker explicitly before a new operation. The system never infers
provider revocation from a timeout or local state alone.

The current tests inject the provider and make no Meta request. No provider revocation has been executed
against a real account.

The same root and grant-reference advisory keys are patched into the v1.47.0 Integration upsert
transaction. A pending provider attempt carries the non-reversible grant reference and blocks a callback
for either matching identity fail-closed; a completed old receipt does not permanently block an explicit
fresh reconnect. v1.47.0 does not carry OAuth-flow start epoch/nonce into the repository, so the locks
alone cannot distinguish a genuinely fresh callback from a pre-revocation flow that returns late.
Therefore Meta revocation remains an activation gate: the one-shot may run only while Add Channel and
OAuth callback processing are quiesced, with no flow in flight. **[NEIMPLEMENTAT EXTERN]** This branch
does not contain a runtime producer/read-back that drains or stops the callback worker and measures a
real zero-flow census. The operator assertion does not satisfy that missing proof. No real Meta OAuth or
provider revocation is enabled by this branch.

The fixed public cross-contract verification vector is
`postiz-token-envelope/meta-receipt-cross-contract.fixture.json`: exact canonical bytes, receipt,
Ed25519 public key and base64url signature, with no private key.
