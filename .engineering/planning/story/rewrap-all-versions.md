---
format: aep.planning-md/3
id: story:rewrap-all-versions
kind: story
status: implemented
title: Rewrap re-encrypts every stored version, not only the current one
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-custody
- depends_on: story:ess-custody-retrofit
scope:
- confidence: cited
  path: crates/secrets-app/src/main.rs
- confidence: cited
  path: crates/secrets-postgres/src/lib.rs
- confidence: cited
  path: crates/secrets-postgres/tests/lifecycle.rs
- confidence: cited
  path: spec/domains/custody.yaml
- confidence: cited
  path: website/docs
revision: 10
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T08:24:42Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T08:24:43Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "active", to: "implemented", at: "2026-10-05T08:25:00Z", actor: "human:timo", revision: 10, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
---
## Context

`secrets rewrap` re-encrypted only each secret's current version
(`crates/secrets-postgres/src/lib.rs:53-96` before this story), while the operations page told the
operator to keep the old key afterwards. Older versions then needed every old key forever, and
removing one made them undecryptable. Found by the `secrets.custody` retrofit, 2026-09-27.

## Acceptance

After a key rotation and `secrets rewrap`, every stored version of every secret decrypts under the
new key alone, and a second rewrap reports nothing left.

## Evidence

`spec/domains/custody.yaml` `RewrapSecrets`; `crates/secrets-postgres/src/lib.rs` `rewrap_all`.
Pre-existing defect.

## Verification

`crates/secrets-postgres/tests/lifecycle.rs` `rewrap_reencrypts_every_stored_version` stores three
versions under `v1`, rewraps with `v2` active, and decrypts each stored version with a keyring that
holds only `v2`; a second rewrap returns 0. It runs in `task check` against PostgreSQL.

Not an authored ESS scenario: no view reads a stored version, and ESS 0.52.0 `expect_event`
matches an event by name, so one `SecretsRewrapped` satisfies three expected ones. A scenario
written for this passed against the defective code and was dropped; the limit is recorded as an
`ESS-LIMIT` marker on `RewrapSecrets`.

## Scenarios

- a secret with three versions decrypts at every version under the new key alone after rewrap
- a falsification record shows the test fails when rewrap selects only the current version
