---
format: aep.planning-md/3
id: story:local-authorizer
kind: story
status: implemented
title: Local mode allows tenant and user default and denies every other
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: cited
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/ess-inputs.yaml
- confidence: cited
  path: contracts/storage-baseline.json
- confidence: cited
  path: contracts/storage-suite.json
- confidence: cited
  path: contracts/storage/scenarios/authorize
- confidence: cited
  path: crates/secrets-core/src/authorize.rs
revision: 9
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:57:57Z", actor: "human:timo", revision: 6, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:57:57Z", actor: "human:timo", revision: 7, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "active", to: "implemented", at: "2026-10-05T11:16:38Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
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

## Guards

Authored `ess-scenario/1` under `contracts/storage/scenarios/authorize`, run by
`checks/conformance` (`secrets-library`) through the composed stack. Secret commands go through
`Authorized<FederatedStorage>`; namespace and binding commands are decided by the same
`LocalAuthorizer` with `manage-namespace` before routing is called. The runner reads `denied` and
`denied-user` only when no backend was reached and the configuration store was not consulted, and
asks the authorizer first when the port refuses a name.

- `tenant-and-user-default-may-do-everything-in-any-namespace`: all ten commands succeed in
  namespace `team.a-1`
- `a-second-tenant-is-denied-before-any-backend`: all ten commands in tenant `acme` are `denied`,
  including a 129-byte name and a name the grammar refuses
- `a-second-user-is-denied-before-any-backend`: the seven scope commands for user `alice` in tenant
  `default` are `denied-user`, including a 129-byte name

The synthesized `denied` and `denied-user` scenarios of every command (17) run through the same
stack.

Falsification (2026-10-05): letting every user through in `LocalAuthorizer::decide`
(`crates/secrets-core/src/authorize.rs`) fails `a-second-user-is-denied-before-any-backend` and the
seven synthesized `denied-user` scenarios; the file was restored byte for byte (sha256
`633f376f…f94d0` before and after).

ESS cannot express these, so Rust tests in `crates/secrets-core/src/authorize.rs` guard them:

- every action gets the same answer, per action rather than per command:
  `every_action_is_allowed_for_tenant_and_user_default_in_any_namespace`,
  `a_second_tenant_is_denied_for_every_action`, `a_second_user_in_tenant_default_is_denied_for_every_action`
- a denial repeats nothing of the request: `a_denial_is_the_closed_code_denied_and_repeats_nothing`
- a denial is decided before a backend fault: `a_denial_is_decided_before_a_backend_fault`
