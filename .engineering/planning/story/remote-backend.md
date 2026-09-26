---
format: aep.planning-md/1
id: story:remote-backend
kind: story
status: draft
title: The custody service is a storage backend
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/remote.rs
- confidence: cited
  path: contracts/storage/scenarios/remote
- confidence: inferred
  path: crates/secrets-client
- confidence: cited
  path: crates/secrets-remote
revision: 6
---
## Context

The running custody service as one backend, through the existing `secrets-client`.

## Acceptance

The `contracts/storage/scenarios/remote` scenario set passes against the remote backend over an
in-process custody service.

## Evidence

`spec/domains/storage.yaml` remote mapping comment; `spec/domains/custody.yaml`; `crates/secrets-client`.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- read, write, delete and list round trips through `secrets-client`
- each address maps to custody's reference `{tenant, namespace, key = name}` with the user as owner
- two tenants and two users holding the same name stay separate
- a service failure surfaces as `unavailable` with no response text
- Registration with the conformance runner is `checks/conformance/src/target.rs`, which is
  coordinator-owned and pre-wired with this backend's hook when the wave opens; this story
  writes only its own module.
