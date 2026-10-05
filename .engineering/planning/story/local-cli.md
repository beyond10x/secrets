---
format: aep.planning-md/3
id: story:local-cli
kind: story
status: active
title: The local CLI manages names, namespaces, mounts and bindings without printing a secret
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:mount-federation
- depends_on: story:keychain-backend
- depends_on: story:local-authorizer
scope:
- confidence: cited
  path: contracts/storage/scenarios/cli
- confidence: cited
  path: crates/secretsctl
revision: 8
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T11:50:40Z", actor: "human:timo", revision: 7, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T11:50:40Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":1}}}
---
## Context

`secretsctl` gains the local commands: put, describe, list, delete, rename,
namespace add|list|remove, mount set, bind, unbind. Configuration lives in
`$XDG_CONFIG_HOME/b10x-secrets/config.toml` and holds no secret.

## Acceptance

The `contracts/storage/scenarios/cli` scenario set passes against the real `secretsctl`
binary.

## Evidence

`spec/domains/storage.yaml` commands; operator decision that the CLI never prints a secret.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- one scenario per command: put, describe, list, delete, rename, namespace add|list|remove,
  mount set, bind, unbind
- put refuses a value passed in argv and accepts only a hidden prompt, a stdin FIFO or a
  protected file
- no command, under any flag, writes secret bytes to stdout or stderr
