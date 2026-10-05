---
format: aep.planning-md/3
id: story:cli-read-out-file
kind: story
status: draft
title: secretsctl reads a value into a protected file, never to stdout
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
revision: 3
---
## Outcome

`secretsctl read <name> --out <file>` hands a stored value to the operator without printing it, so
the CLI answers the `secrets.storage` `Read` scenarios that are unsupported today (8 in
`contracts/cli-suite.json`).

## Context

Operator decision 2026-10-05 (D1A): the CLI may write a secret to a protected file; it still never
writes secret bytes to stdout or stderr. Depends on `story:local-cli` (PR #29).

## Acceptance

- `read --out` creates a new file only (refuses an existing path), with mode 0600, and refuses a
  symlink at the path or in a final component it would follow; it never writes the value to
  stdout or stderr.
- The CLI suite answers every `Read` scenario the local scope can reach.

## Scope

- `crates/secretsctl` — cited
- `checks/conformance/src/cli.rs`, `contracts/cli-suite.json`, `contracts/cli-baseline.json` — inferred

## Scenarios

- a value written by `put` reads back byte for byte into a new 0600 file
- `read --out` refuses an existing file and a symlink, and writes nothing
- no `read` invocation writes secret bytes to stdout or stderr
