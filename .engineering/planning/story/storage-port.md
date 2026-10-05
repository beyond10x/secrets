---
format: aep.planning-md/3
id: story:storage-port
kind: story
status: implemented
title: The storage port exists as secrets.storage declares it
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:ess-custody-retrofit
scope:
- confidence: inferred
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/storage/scenarios/port
- confidence: inferred
  path: crates/secrets-core/Cargo.toml
- confidence: cited
  path: crates/secrets-core/src/lib.rs
- confidence: cited
  path: crates/secrets-core/src/storage.rs
revision: 9
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:33:43Z", actor: "human:timo", revision: 6, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:33:43Z", actor: "human:timo", revision: 7, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "active", to: "implemented", at: "2026-10-05T09:46:34Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
---
## Context

`secrets-core` gains the backend port the whole epic rests on: the `secrets.storage`
model in Rust. The existing service-level `SecretStore` stays unchanged.

## Acceptance

The `contracts/storage/scenarios/port` scenario set passes against `secrets-core`'s storage
types as `spec/domains/storage.yaml` declares them.

## Evidence

`spec/domains/storage.yaml` entities and errors; `crates/secrets-core/src/lib.rs` (existing types);
`llm-credentials` `Secret` and `SecretError` as the shape to match.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- names are refused at 128 bytes in total and 64 per segment, by name
- values are refused above 1 MiB as `too-large`
- secret bytes have no Debug, Display or Serialize (compile-fail doctests)
- every `StorageError` is a closed code with no free text

## Guards

Authored `ess-scenario/1` under `contracts/storage/scenarios/port`, run by `checks/conformance`
(`secrets-library` component, in-process, no database) against `secrets_core::storage`:

- `a-name-of-129-bytes-is-too-long`: two 64-byte segments, refused as `name-too-long`
- `a-name-of-128-bytes-with-a-64-byte-segment-reaches-the-value-check`: both bounds admit the name, so the forced oversized value is `too-large`
- `a-segment-of-65-bytes-is-an-invalid-name`: total 70 bytes, refused as `invalid-name`
- `a-new-name-of-129-bytes-is-too-long`: a rename target over 128 bytes is `new-name-too-long`
- `a-value-above-one-mib-is-too-large`: the runner sends 1 MiB + 1 bytes, refused as `too-large`

The runner reports a refusal by the text the port's error displays, looked up among the seven
declared wire codes, so a `StorageError` that displays free text fails every refusal scenario.

ESS cannot express these, so Rust tests guard them in `crates/secrets-core/src/storage.rs`:

- secret bytes have no Debug, Display or Serialize: three `compile_fail` doctests on `SecretValue`,
  with a positive doctest showing the same lines compile for a metadata type; `task test` runs
  `cargo test --doc`
- every `StorageError` is a closed code: `every_storage_error_is_a_closed_code_with_no_free_text`
  covers all seven, including the five no port-level scenario can reach (not-found, denied,
  unsupported, unavailable, conflict)
- a value of exactly 1 MiB is accepted: `a_value_of_one_mib_is_a_value_and_one_byte_more_is_too_large`;
  an accepted write needs a backend, so no scenario can observe it

Library suite baseline (`contracts/storage-baseline.json`): 82 scenarios, 19 answered (14
synthesized name and size refusals plus the 5 above), 63 unsupported, 0 skipped. Of the 63, 17
(`denied`, `denied-user`) need the authorizer, story:local-authorizer; 46 need mount routing, a
backend or the namespace configuration store, story:mount-federation, story:keychain-backend and
story:remote-backend. Each later story raises the floor and lowers the ceiling.

The port also carries the `Action` set and a recording fake backend
(`secrets_core::storage::testing`, feature `testing`) for the stories that build on it.
