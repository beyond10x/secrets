---
format: aep.planning-md/3
id: story:keychain-backend
kind: story
status: implemented
title: The OS keychain is a storage backend
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/keychain.rs
- confidence: cited
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/ess-inputs.yaml
- confidence: cited
  path: contracts/storage-baseline.json
- confidence: cited
  path: contracts/storage-suite.json
- confidence: cited
  path: contracts/storage/scenarios/keychain
- confidence: cited
  path: crates/secrets-keychain
revision: 12
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:57:56Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":2}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:57:56Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"review_outcome":2}}}
- {from: "active", to: "implemented", at: "2026-10-05T11:16:37Z", actor: "human:timo", revision: 11, decided_on: {"recorded":{"test_result":1,"review_outcome":2}}}
---
## Context

The local default backend, ported with attribution from
`llm-credentials/src/keychain.rs` (`keyring-core`, native stores).

## Acceptance

The `contracts/storage/scenarios/keychain` scenario set passes against the keychain backend
over the mock `keyring-core` store.

## Evidence

`spec/domains/storage.yaml`; `llm/crates/llm-credentials/src/keychain.rs`.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- read, write, delete and list round trips
- two tenants, two namespaces and two users holding the same name stay separate
- a backend fault surfaces as `unavailable` with no backend text
- Registration with the conformance runner is `checks/conformance/src/target.rs`, which is
coordinator-owned and pre-wired with this backend's hook when the wave opens; this story
writes only its own module.

## Guards

Authored scenarios under `contracts/storage/scenarios/keychain` and `contracts/storage/scenarios/response`,
run by `checks/conformance` (`secrets-library`) through the composed stack: `Authorized<FederatedStorage>`
with namespace `default` on the keychain backend over a fresh `keyring_core::mock::Store` per scenario.

- `a-value-written-to-a-keychain-mount-reads-back-equal` (`ess-scenario/4`, story:read-response-scenarios):
  the primary evidence that a read returns the bytes written. `Read.read` declares `returns: true`;
  the runner hands ESS the value and version the read returned, and the scenario asserts the value
  literally after a write and again, binary, after a replace
- `a-keychain-secret-round-trips`: write (created, then replaced), read, list, rename, delete, and
  the forced `not-found` afterwards; SecretMetadata holds what remains and excludes what was
  renamed or deleted
- `the-same-name-in-two-namespaces-stays-separate`: one name in two namespaces is two entries; the
  second `created` is forced, and the runner refuses to arrange it while the keychain holds the name
- `a-keychain-fault-is-unavailable`: the runner arms the mock entry behind the address to fail its
  next call; write, read and delete answer `unavailable`, store nothing and remove nothing

Falsification (2026-10-05): `failure()` in `crates/secrets-keychain/src/lib.rs` mapping every
keychain error to `NotFound` fails `a-keychain-fault-is-unavailable`; the file was restored byte
for byte (sha256 `444247aa…07e2e9` before and after). Falsification (2026-10-05,
story:read-response-scenarios): `read` returning the stored bytes reversed fails
`a-value-written-to-a-keychain-mount-reads-back-equal`; restored byte for byte (same sha256).

ESS cannot express these, so Rust tests in `crates/secrets-keychain/tests/backend.rs` guard them:

- a read returns the bytes written, kept beside the ESS scenario above:
  `a_written_value_reads_back_and_is_listed_with_its_version`, `empty_and_binary_values_round_trip`
- two tenants and two users holding one name stay separate: the local authorizer denies every
  scope but tenant and user `default` before the keychain is reached, so no scenario can write
  there; `the_same_name_in_different_scopes_stays_separate`
- no backend text in the error (the error declares no field):
  `a_backend_fault_is_unavailable_with_no_backend_text`,
  `every_keychain_error_but_a_missing_entry_is_unavailable`
- every write changes the version: `every_write_changes_the_version_even_for_the_same_value`
