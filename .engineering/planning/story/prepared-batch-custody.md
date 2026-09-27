---
format: aep.planning-md/2
id: story:prepared-batch-custody
kind: story
status: implemented
title: Prepared batches are held under envelope custody for a bounded time
relations:
- decomposes: epic:named-federated-storage
scope:
- confidence: cited
  path: crates/secrets-crypto/src/lib.rs
- confidence: cited
  path: crates/secrets-postgres/migrations
- confidence: cited
  path: crates/secrets-postgres/src/lib.rs
- confidence: cited
  path: crates/secrets-postgres/tests/lifecycle.rs
- confidence: cited
  path: spec/domains/custody.yaml
revision: 9
---
## Acceptance

A prepared batch is held under the same custody as a stored secret version, and only for a bounded
time:

- `PrepareTransaction` stores the batch's mutations only as an AES-256-GCM envelope from the
  service keyring. The associated data binds the envelope to the tenant, the transaction id and the
  actor, so a row moved to another tenant, id or actor fails to open.
- A batch older than its lifetime (600 seconds) cannot be committed: `CommitTransaction` answers
  `not-found` and the batch is gone. Expired batches are removed when a batch is prepared or
  committed.
- `rewrap_all` re-seals every held batch under the active key, so retiring a key never strands a
  prepared batch.
- A batch that fails to open answers `unavailable` and applies nothing.
- Migration `0002` replaces the `mutations` column. Batches held by an earlier release are
  discarded by the migration; they are transient by contract.

## Spec first

`spec/domains/custody.yaml` states the lifetime and the envelope on
`secrets.custody.PreparedTransaction`, `PrepareTransaction` and `CommitTransaction`, and
`ess specify validate --path spec` exits 0 before code changes.

## Evidence

- `cargo test -p secrets-postgres` against `SECRETS_TEST_DATABASE_URL`: a raw `SELECT` of the
  prepared row contains no plaintext value bytes; tampered tenant, id or actor fails to open; an
  expired batch commits as `NotFound`; rewrap keeps a held batch committable.
- `task check` exits 0.
