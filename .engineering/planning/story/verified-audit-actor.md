---
format: aep.planning-md/3
id: story:verified-audit-actor
kind: story
status: draft
title: Audit events record the verified principal as actor
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-custody
- depends_on: story:ess-custody-retrofit
scope:
- confidence: cited
  path: contracts/custody/scenarios/audit
- confidence: cited
  path: crates/secrets-http/src/lib.rs
- confidence: cited
  path: crates/secrets-postgres/src/lib.rs
revision: 4
---
## Context

The audit actor is chosen by the caller for workload delete and for prepare/commit
(`crates/secrets-http/src/lib.rs:264,279`), and for put it is `owner_subject` rather than the
verified principal (`crates/secrets-postgres/src/lib.rs:155`). Found by the retrofit,
2026-09-27.

## Acceptance

The `contracts/custody/scenarios/audit` scenario set passes: every audit event records the
verified principal as its actor.

## Evidence

`spec/domains/custody.yaml` audit comments; the lines above. Pre-existing defect.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- put, delete, revoke, prepare and commit each record the verified principal
- a request naming a different actor records it beside the verified one, never instead
- a falsification record shows the set fails when the caller-supplied actor is used
