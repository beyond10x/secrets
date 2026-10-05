---
format: aep.planning-md/3
id: story:read-response-scenarios
kind: story
status: draft
title: Read's returned value is asserted by ESS scenarios
relations:
- decomposes: epic:named-federated-storage
- depends_on: story:local-cli
scope:
- confidence: inferred
  path: checks/conformance/src/cli.rs
- confidence: inferred
  path: checks/conformance/src/storage.rs
- confidence: inferred
  path: checks/conformance/src/target.rs
- confidence: inferred
  path: contracts/cli-suite.json
- confidence: inferred
  path: contracts/ess-inputs.yaml
- confidence: inferred
  path: contracts/storage-suite.json
- confidence: inferred
  path: contracts/storage/scenarios/response
- confidence: cited
  path: spec/domains/storage.yaml
revision: 3
---
## Outcome

"Read returns the bytes written" is an ESS scenario instead of a Rust-only guard: `Read.read`
declares `returns: true`, the runners answer its typed response, and authored scenarios assert the
value a preceding `Write` stored.

## Context

Probed 2026-10-05 on ESS 0.52.0: with `returns: true` on `Read.read`, synthesis emits an
`expect_direct_response` step (suite/28) with the response's shape; authored scenarios may add
literal assertions. The keychain, remote and federation Guards sections name the Rust tests this
replaces as primary evidence.

## Acceptance

- `spec/domains/storage.yaml` `Read.read` declares `returns: true`; `ess specify validate` passes.
- The in-process and CLI runners return the typed response (`value`, `version`) for `Read`.
- Authored scenarios: a value written reads back equal, in a keychain mount and in a remote mount.
- Falsification: a backend that returns other bytes fails a named scenario.

## Scope

- `spec/domains/storage.yaml` — cited
- `checks/conformance/src/storage.rs`, `checks/conformance/src/cli.rs`, `checks/conformance/src/target.rs` — inferred
- `contracts/storage/scenarios/response`, `contracts/ess-inputs.yaml`, `contracts/storage-suite.json`, `contracts/cli-suite.json` — inferred

## Scenarios

- a value written to a keychain mount reads back equal
- a value written to a remote mount reads back equal
