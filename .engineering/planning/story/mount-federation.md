---
format: aep.planning-md/3
id: story:mount-federation
kind: story
status: draft
title: Each namespace routes to exactly one backend, with no fallback
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/federation.rs
- confidence: cited
  path: contracts/storage/scenarios/federation
- confidence: cited
  path: crates/secrets-federation
revision: 6
---
## Context

`FederatedStorage` routes each address to the one backend its namespace is mounted
to, applying bindings for backends that need a locator. It implements `SecretStorage`.

## Acceptance

The `contracts/storage/scenarios/federation` scenario set passes against `FederatedStorage`
over recording fake backends.

## Evidence

`spec/domains/storage.yaml` Namespace, BackendRef, Binding, and the coordinator decisions.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- a name with no mount or binding is `not-found` and the fakes record no call
- write, delete and rename on a read-only mount are `unsupported`
- SetMount, RemoveNamespace, Bind and Rename give `conflict` in the cases the spec names
- every request reaches exactly one backend
- Registration with the conformance runner is `checks/conformance/src/target.rs`, which is
coordinator-owned and pre-wired with this backend's hook when the wave opens; this story
writes only its own module.
