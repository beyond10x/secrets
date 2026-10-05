---
format: aep.planning-md/3
id: story:mount-federation
kind: story
status: implemented
title: Each namespace routes to exactly one backend, with no fallback
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/federation.rs
- confidence: cited
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/ess-inputs.yaml
- confidence: cited
  path: contracts/storage-baseline.json
- confidence: cited
  path: contracts/storage-suite.json
- confidence: cited
  path: contracts/storage/scenarios/federation
- confidence: cited
  path: crates/secrets-federation
revision: 11
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:57:57Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:57:57Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "active", to: "implemented", at: "2026-10-05T11:16:37Z", actor: "human:timo", revision: 11, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
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

## Guards

Authored `ess-scenario/1` under `contracts/storage/scenarios/federation`, run by
`checks/conformance` (`secrets-library`) through the composed stack. The runner wraps every mounted
backend and the namespace configuration store in call counters: a command that reaches more than
one backend, or one its namespace was not mounted on when it began, takes no declared branch, and
`unresolved`, `unsupported`, `bound` and `is-default` are read only when no backend was reached.

- `a-name-in-a-namespace-that-does-not-exist-is-unresolved`: write, read, delete, rename and list in
  a namespace that never existed, and write after RemoveNamespace, are `unresolved` and reach no
  backend
- `changes-on-a-read-only-mount-are-unsupported`: write, delete, rename and list on a read-only
  recording fake are `unsupported` before any call
- `conflicts-the-specification-names`: AddNamespace `exists`, SetMount and RemoveNamespace `in-use`,
  RemoveNamespace `is-default`, Bind `already-bound`, Rename `bound` (no backend reached) and
  `taken` (the backend's)
- `each-namespace-routes-to-its-own-mount`: three namespaces on two keychain mounts, one re-mounted
  with SetMount, each reaching only its own backend

Falsification (2026-10-05): resolving every namespace to the default mount in
`crates/secrets-federation/src/lib.rs` (`mounted`) fails 15 scenarios, among them
`each-namespace-routes-to-its-own-mount`, `changes-on-a-read-only-mount-are-unsupported` and
`a-remote-secret-round-trips`; the file was restored byte for byte (sha256 `b3abcc58…ce3aa` before
and after).

ESS cannot express these, so Rust tests in `crates/secrets-federation/src/tests.rs` guard them:

- "no backend is called" in the specification itself (ESS-LIMIT #27): the runner observes it; the
  crate asserts it on the recording fakes,
  `a_name_in_a_namespace_that_does_not_exist_is_not_found_and_no_backend_is_called`,
  `a_mount_naming_an_unregistered_backend_is_not_found_and_no_backend_is_called`
- an unbound name on a binding-required backend is `not-found`: only the runner's own arrangement
  mounts one; `an_unbound_name_on_a_binding_backend_is_not_found_and_no_backend_is_called`,
  `a_bound_name_reads_through_its_locator_and_after_unbind_is_not_found_again`
- renaming onto a bound name is `conflict`: forcing `bound` binds the source, so the destination
  case cannot be told apart; `renaming_a_bound_name_or_onto_a_bound_name_is_conflict_and_no_backend_renames`
- Delete never removes a binding: no view holds a binding; `delete_never_removes_a_binding`
- no fallback after a fault or a miss: `a_fault_or_a_miss_on_the_mounted_backend_never_falls_back`
