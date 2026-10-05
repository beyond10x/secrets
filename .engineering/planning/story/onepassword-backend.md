---
format: aep.planning-md/3
id: story:onepassword-backend
kind: story
status: draft
title: 1Password is a read-only storage backend
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/onepassword.rs
- confidence: cited
  path: contracts/storage/scenarios/onepassword
- confidence: cited
  path: crates/secrets-onepassword
revision: 6
---
## Context

A read-only backend resolving bound `op://<vault>/<item>/<field>` locators through a
transport trait: the `op` CLI with desktop-app integration locally, a service-account token
on servers.

## Acceptance

The `contracts/storage/scenarios/onepassword` scenario set passes against the 1Password
backend over a fake transport.

## Evidence

`spec/domains/storage.yaml` onepassword capabilities and locator decision.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- a bound `op://` locator reads its value and version
- write, delete and list are `unsupported`
- an unbound name is `not-found` with no transport call
- a transport failure surfaces as `unavailable` with no transport text
- Registration with the conformance runner is `checks/conformance/src/target.rs`, which is
coordinator-owned and pre-wired with this backend's hook when the wave opens; this story
writes only its own module.
