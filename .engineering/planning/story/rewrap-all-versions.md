---
format: aep.planning-md/2
id: story:rewrap-all-versions
kind: story
status: draft
title: Rewrap re-encrypts every stored version, not only the current one
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-custody
- depends_on: story:ess-custody-retrofit
scope:
- confidence: cited
  path: contracts/custody/scenarios/rewrap
- confidence: cited
  path: crates/secrets-postgres/src/lib.rs
- confidence: inferred
  path: docs/architecture.md
revision: 5
---
## Context

`secrets rewrap` re-encrypts only each secret's current version
(`crates/secrets-postgres/src/lib.rs:34`), while `docs/architecture.md:25` says it re-encrypts
active versions and the README's rotation removes the old key afterwards. Older versions then
cannot be decrypted. Found by the `secrets.custody` retrofit, 2026-09-27.

## Acceptance

The `contracts/custody/scenarios/rewrap` scenario set passes: after a key rotation and
`secrets rewrap`, every stored version of every secret decrypts under the new key alone.

## Evidence

`spec/domains/custody.yaml` `RewrapSecrets`; the lines above. Pre-existing defect.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- a secret with three versions decrypts at every version after rotation and rewrap
- a falsification record shows the set fails when rewrap skips a non-current version
