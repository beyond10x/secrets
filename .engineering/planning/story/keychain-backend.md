---
format: aep.planning-md/3
id: story:keychain-backend
kind: story
status: active
title: The OS keychain is a storage backend
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/keychain.rs
- confidence: cited
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/ess-inputs.yaml
- confidence: cited
  path: contracts/storage-baseline.json
- confidence: cited
  path: contracts/storage-suite.json
- confidence: cited
  path: contracts/storage/scenarios/keychain
- confidence: cited
  path: crates/secrets-keychain
revision: 9
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:57:56Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":2}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:57:56Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"review_outcome":2}}}
---
## Context

The local default backend, ported with attribution from
`llm-credentials/src/keychain.rs` (`keyring-core`, native stores).

## Acceptance

The `contracts/storage/scenarios/keychain` scenario set passes against the keychain backend
over the mock `keyring-core` store.

## Evidence

`spec/domains/storage.yaml`; `llm/crates/llm-credentials/src/keychain.rs`.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- read, write, delete and list round trips
- two tenants, two namespaces and two users holding the same name stay separate
- a backend fault surfaces as `unavailable` with no backend text
- Registration with the conformance runner is `checks/conformance/src/target.rs`, which is
coordinator-owned and pre-wired with this backend's hook when the wave opens; this story
writes only its own module.
