---
format: aep.planning-md/1
id: story:storage-port
kind: story
status: draft
title: The storage port exists as secrets.storage declares it
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:ess-custody-retrofit
scope:
- confidence: inferred
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/storage/scenarios/port
- confidence: inferred
  path: crates/secrets-core/Cargo.toml
- confidence: cited
  path: crates/secrets-core/src/lib.rs
- confidence: cited
  path: crates/secrets-core/src/storage.rs
revision: 5
---
## Context

`secrets-core` gains the backend port the whole epic rests on: the `secrets.storage`
model in Rust. The existing service-level `SecretStore` stays unchanged.

## Acceptance

The `contracts/storage/scenarios/port` scenario set passes against `secrets-core`'s storage
types as `spec/domains/storage.yaml` declares them.

## Evidence

`spec/domains/storage.yaml` entities and errors; `crates/secrets-core/src/lib.rs` (existing types);
`llm-credentials` `Secret` and `SecretError` as the shape to match.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- names are refused at 128 bytes in total and 64 per segment, by name
- values are refused above 1 MiB as `too-large`
- secret bytes have no Debug, Display or Serialize (compile-fail doctests)
- every `StorageError` is a closed code with no free text
