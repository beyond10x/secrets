---
format: aep.planning-md/3
id: story:remote-backend
kind: story
status: implemented
title: The custody service is a storage backend
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:storage-port
scope:
- confidence: inferred
  path: checks/conformance/src/remote.rs
- confidence: cited
  path: checks/conformance/src/storage.rs
- confidence: cited
  path: contracts/ess-inputs.yaml
- confidence: cited
  path: contracts/storage-baseline.json
- confidence: cited
  path: contracts/storage-suite.json
- confidence: cited
  path: contracts/storage/scenarios/remote
- confidence: inferred
  path: crates/secrets-client
- confidence: cited
  path: crates/secrets-remote
- confidence: cited
  path: spec/domains/storage.yaml
revision: 13
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:57:56Z", actor: "human:timo", revision: 10, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:57:56Z", actor: "human:timo", revision: 11, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "active", to: "implemented", at: "2026-10-05T11:16:37Z", actor: "human:timo", revision: 13, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
---
## Context

The running custody service as one backend, through the existing `secrets-client`.

## Acceptance

The `contracts/storage/scenarios/remote` scenario set passes against the remote backend over an
in-process custody service.

## Evidence

`spec/domains/storage.yaml` remote mapping comment; `spec/domains/custody.yaml`; `crates/secrets-client`.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- read, write, delete and list round trips through `secrets-client`
- each address maps to custody's reference `{tenant, namespace, key = name}` with the user as owner
- two tenants and two users holding the same name stay separate
- a service failure surfaces as `unavailable` with no response text
- Registration with the conformance runner is `checks/conformance/src/target.rs`, which is
  coordinator-owned and pre-wired with this backend's hook when the wave opens; this story
  writes only its own module.

## Decisions

Decided by the coordinator 2026-10-05, superseding the 2026-09-27 mapping in
`spec/domains/storage.yaml` (`BackendKind` comment): a remote backend maps an address to the custody
reference `{tenant, namespace, key = "<user>/<name>"}`, with the scope's user as `owner_subject`.

- Reason: with `key = name`, two users writing the same name in one namespace share one custody row.
  Custody's put upserts on `(tenant, namespace, secret_key)` and overwrites `owner_subject`
  (`crates/secrets-postgres/src/lib.rs` `put_tx`), so the second user's write would take over the
  first user's secret, and the scenario "two users holding the same name stay separate" could not pass.
- A `ScopeName` holds no `/` (a `SecretName` may), so the first `/` in the key splits user from name
  unambiguously.
- The backend also filters reads and lists to keys under its user's prefix. Workload get and list do
  not check the owner (`crates/secrets-http/src/lib.rs` `workload_get`, `workload_list`).
- This story updates the `BackendKind` comment in `spec/domains/storage.yaml` to this mapping.
- Tests reach the custody service without network by serving the conformance fixture's router on
  `127.0.0.1:0` and pointing `secrets_client::Client` at it, with tokens from the fixture.

## Guards

Authored `ess-scenario/1` under `contracts/storage/scenarios/remote`, run by `checks/conformance`
(`secrets-library`) through the composed stack, with a namespace mounted on `remote/custody`: the
remote backend over `secrets_client::Client` against the shipped router and PostgreSQL store,
served on `127.0.0.1:0` per scenario, with a workload token of tenant `default`.

- `a-remote-secret-round-trips`: add the namespace, write (created, then replaced), read, list,
  rename to a `/` name, delete, and the forced `not-found` after each move; Namespaces shows the
  mount and SecretMetadata what remains
- `the-same-name-in-two-remote-namespaces-stays-separate`: one name in two namespaces on one
  custody service is two records
- `a-custody-failure-is-unavailable`: the custody database refuses connections for one command at a
  time; write, read, delete and list answer `unavailable`, and the secret survives
- `a-value-the-custody-service-cannot-carry-is-too-large`: a 1 MiB value, which the port accepts,
  is `too-large` on the remote mount (`spec/domains/storage.yaml`, Write `too-large`, decided
  2026-10-05) and stores nothing

Falsification (2026-10-05): bounding `write` in `crates/secrets-remote/src/lib.rs` by the port's
1 MiB instead of `max_value_bytes()` fails `a-value-the-custody-service-cannot-carry-is-too-large`;
the file was restored byte for byte (sha256 `b2250aa4…0b662` before and after).

ESS cannot express these, so Rust tests in `crates/secrets-remote` guard them:

- each address maps to `{tenant, namespace, key = "<user>/<name>"}` with the user as owner: a
  library scenario cannot read the custody component's records;
  `a_write_lands_on_the_user_prefixed_reference_with_the_user_as_owner`,
  `a_custody_record_under_the_user_prefix_is_that_user_s_secret`,
  `an_address_maps_to_the_user_prefixed_key_and_back`
- two tenants and two users stay separate: the local authorizer denies both before the backend;
  `two_users_holding_the_same_name_stay_separate`, `two_tenants_holding_the_same_name_stay_separate`,
  `a_listing_keeps_only_keys_under_the_user_s_prefix`
- no response text in the error: `a_5xx_answer_is_unavailable_and_repeats_none_of_its_body`,
  `a_service_nobody_answers_for_is_unavailable`, `an_unreadable_success_body_is_unavailable`
- a read returns the bytes written, and the largest value round-trips:
  `write_read_list_and_delete_round_trip`,
  `the_largest_value_the_service_takes_round_trips_and_one_byte_more_is_too_large`
