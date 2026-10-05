---
format: aep.planning-md/3
id: story:ess-custody-retrofit
kind: story
status: implemented
title: The shipped custody service passes its retrofitted conformance suite
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-custody
scope:
- confidence: cited
  path: Taskfile.yml
- confidence: cited
  path: checks/conformance
- confidence: cited
  path: checks/conformance/src/target.rs
- confidence: inferred
  path: contracts/baseline.json
- confidence: cited
  path: contracts/custody/scenarios
- confidence: inferred
  path: contracts/ess-inputs.yaml
- confidence: inferred
  path: contracts/schema
- confidence: inferred
  path: contracts/suite.json
revision: 10
transitions:
- {from: "draft", to: "proposed", at: "2026-09-27T12:38:45Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-27T12:38:48Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"review_outcome":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-27T18:27:56Z", actor: "human:timo", revision: 10, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}, imported: true}
---
## Context

The shipped custody service has a retrofitted specification (`spec/domains/custody.yaml`) and no
suite that runs it. This story builds the conformance runner, the contract manifests and the
gate, and holds the shipped service to the retrofit.

## Acceptance

`task check` passes with a conformance step that runs every `secrets.custody` scenario
against the shipped service code, three times with identical counts.

## Evidence

`spec/domains/custody.yaml` (validates; synthesis 46 scenarios, 0 refusals, 2026-09-27). The retrofit's
source disagreements are the first scenarios: the OpenAPI document omits request bodies,
timestamps and error responses the code has (`crates/secrets-http/src/lib.rs:94-109,376-384`).

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- the 46 synthesized `secrets.custody` scenarios run and pass
- authored scenarios for each OpenAPI-versus-code disagreement the retrofit found
- the check refuses a suite or schema that drifts from `spec/`
- the check refuses any failed, error, unsupported or skipped scenario
- `checks/conformance/src/target.rs` dispatches to one module per domain, so later stories
  add a module without editing a shared function
