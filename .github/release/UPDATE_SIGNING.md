# Citrus update signing

Release jobs build `update-manifest.json` and sign its exact bytes, prefixed by
`CITRUS-UPDATE-MANIFEST-V1\n`, with two Ed25519 keys. Private keys exist only
as repository secrets:

- `CITRUS_UPDATE_PRIMARY_PRIVATE_KEY`
- `CITRUS_UPDATE_RECOVERY_PRIVATE_KEY`

Each value is base64 of the 64-byte Ed25519 private key. Public keys and key
IDs are embedded in `component/updater/update_manifest.go`.

## Rotation

1. Generate a new Ed25519 key outside the repository and add its public key to
   the embedded keyring under a new ID.
2. Add the matching private value as a GitHub secret and make the manifest job
   emit both the old and new signatures.
3. Publish at least one overlap release.
4. Mark the retired ID in `revokedUpdateKeys`, stop emitting its signature and
   publish with a still-trusted key.

Never commit, log or pass private keys in argv. If both active keys may be
compromised, stop release publication and require a manually verified recovery
release; an already installed binary cannot learn a new trust root from an
untrusted channel.

`GITHUB_RUN_ID` is embedded as `constant.BuildSequence` and copied into the
manifest. Clients also persist the highest accepted sequence per channel in
`update-state.json`; `force=true` never bypasses signatures, expiry, revocation
or rollback checks.
