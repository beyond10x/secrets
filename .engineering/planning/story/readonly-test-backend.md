---
format: aep.planning-md/3
id: story:readonly-test-backend
kind: story
status: implemented
title: Conformance mounts a read-only 1Password-kind backend played by the recording fake
relations:
- decomposes: epic:named-federated-storage
- depends_on: story:local-cli
scope:
- confidence: cited
  path: checks/conformance/src/cli.rs
- confidence: cited
  path: checks/conformance/src/storage.rs
- confidence: inferred
  path: contracts/cli-baseline.json
- confidence: inferred
  path: contracts/storage-baseline.json
- confidence: inferred
  path: crates/secretsctl
revision: 6
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T16:14:38Z", actor: "human:timo", revision: 4}
- {from: "proposed", to: "active", at: "2026-10-05T16:14:39Z", actor: "human:timo", revision: 5}
- {from: "active", to: "implemented", at: "2026-10-05T18:33:01Z", actor: "human:timo", revision: 6, decided_on: {"recorded":{"test_result":1}}}
---
## Outcome

The conformance runs mount a read-only, binding-required backend of the 1Password kind, played by
`secrets_core::storage::testing::RecordingBackend`, so the scenarios that need a read-only mount or
a 1Password mount are answered (1 in `contracts/storage-suite.json`, 5 in `contracts/cli-suite.json`)
while the real 1Password backend stays deferred.

## Context

`story:onepassword-backend` is archived (operator, 2026-10-05). The scenarios check federation's
routing and capability rules, not 1Password itself, so a fake with the declared capabilities answers
them honestly. The CLI reaches it only under the `test-hooks` feature.

## Acceptance

- `contracts/storage-baseline.json`: 108 answered, 0 unsupported.
- The CLI suite answers the read-only and 1Password-mount scenarios through the binary built with
  `test-hooks`; a default build cannot mount the fake.

## Scope

- `checks/conformance/src/storage.rs`, `checks/conformance/src/cli.rs` — cited
- `crates/secretsctl` (test hook only) — inferred
- `contracts/storage-baseline.json`, `contracts/cli-baseline.json` — inferred

## Scenarios

- `SetMount` onto a 1Password-kind backend is answered
- write, delete and rename on a read-only mount are `unsupported` through the CLI
