---
format: aep.planning-md/3
id: story:vault-storage-backend
kind: story
status: draft
title: A Vault storage backend
summary: Store values in Vault's KV v2 engine behind SecretStorage, held to the storage conformance suite
relations:
- informed_by: epic:named-federated-storage
revision: 1
---
# A Vault storage backend

## Need

The operator wants the service to store the secrets a customer provides for custom connectors and
custom operations in HashiCorp Vault, through a storage adapter like the existing ones. Main has
three backends behind `SecretStorage` (`crates/secrets-core/src/storage.rs:628`):
`crates/secrets-postgres`, `crates/secrets-keychain` and `crates/secrets-remote`. The epic
`epic:named-federated-storage` lists Vault as out of scope of its round of 2026-09-26/27 (its
"Out of scope" section). No crate talks to Vault.

## Acceptance

- A `secrets-vault` backend implements `SecretStorage` against Vault's KV version 2 engine: a
  write stores a value at the target, a read returns it with its version, a delete removes it, and
  the capabilities it lists are the ones it passes.
- The storage conformance suite (`checks/conformance/src/storage.rs`) runs the same scenarios
  against it, on a Vault dev server in CI, and passes.
- A Vault fault, a refused token or a missing mount is `StorageError::Unavailable` or the matching
  refusal and carries none of Vault's own text; no value appears in a log, error or label.
- The Vault address and the way the service authenticates to Vault (token or Kubernetes auth) are
  configuration; the Vault token is read as a secret input, never from an argument.
