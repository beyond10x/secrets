---
format: aep.planning-md/3
id: story:cli-scope-flags
kind: story
status: implemented
title: secretsctl names a tenant and user, and every non-default scope is denied
relations:
- decomposes: epic:named-federated-storage
- depends_on: story:local-cli
scope:
- confidence: inferred
  path: checks/conformance/src/cli.rs
- confidence: inferred
  path: contracts/cli-baseline.json
- confidence: inferred
  path: contracts/cli-suite.json
- confidence: cited
  path: crates/secretsctl
revision: 6
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T16:14:39Z", actor: "human:timo", revision: 4}
- {from: "proposed", to: "active", at: "2026-10-05T16:14:39Z", actor: "human:timo", revision: 5}
- {from: "active", to: "implemented", at: "2026-10-05T18:33:01Z", actor: "human:timo", revision: 6, decided_on: {"recorded":{"test_result":1}}}
---
## Outcome

`secretsctl` takes `--tenant` and `--user`, and every scope other than tenant `default` and user
`default` is denied before any backend or configuration is touched, so the CLI answers the
`denied` and `denied-user` scenarios that are unsupported today (15 in `contracts/cli-suite.json`).

## Context

Operator decision 2026-10-05 (D2A). Local mode still serves one tenant and one user; the flags make
a mistyped scope a named refusal instead of an unreachable case. Depends on `story:local-cli`
(PR #29).

## Acceptance

- `--tenant` and `--user` default to `default`; any other value answers `denied` through
  `secrets_core::authorize::LocalAuthorizer`, before any backend call and before the configuration
  file is read or written.
- The CLI suite answers every `denied` and `denied-user` scenario.

## Scope

- `crates/secretsctl` — cited
- `checks/conformance/src/cli.rs`, `contracts/cli-suite.json`, `contracts/cli-baseline.json` — inferred

## Scenarios

- a second tenant is denied by name and the configuration file is untouched
- a second user is denied by name and no backend is reached
