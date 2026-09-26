---
format: aep.planning-md/1
id: story:local-authorizer
kind: story
status: draft
title: Local mode allows tenant and user default and denies every other
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: cited
  path: contracts/storage/scenarios/authorize
- confidence: cited
  path: crates/secrets-core/src/authorize.rs
revision: 4
---
## Context

Every storage command is decided before any backend call. Local mode has one tenant
and one user, both `default`.

## Acceptance

The `contracts/storage/scenarios/authorize` scenario set passes against the local authorizer.

## Evidence

`spec/domains/storage.yaml` `denied` outcomes and the authorizer comments.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- every action is allowed for tenant `default` and user `default` in any namespace
- a second tenant is denied by name before any backend is reached
- a second user is denied by name before any backend is reached
