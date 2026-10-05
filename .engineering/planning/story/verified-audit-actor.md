---
format: aep.planning-md/3
id: story:verified-audit-actor
kind: story
status: active
title: Audit events record the verified principal as actor
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-custody
- depends_on: story:ess-custody-retrofit
scope:
- confidence: cited
  path: checks/conformance/src
- confidence: cited
  path: crates/secrets-core/src/lib.rs
- confidence: cited
  path: crates/secrets-http/src/lib.rs
- confidence: cited
  path: crates/secrets-postgres/migrations
- confidence: cited
  path: crates/secrets-postgres/src/lib.rs
- confidence: cited
  path: crates/secrets-postgres/tests/lifecycle.rs
- confidence: cited
  path: spec/domains/custody.yaml
revision: 8
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:06:49Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T09:06:49Z", actor: "human:timo", revision: 6, decided_on: {"recorded":{"review_outcome":1}}}
---
## Context

The audit actor was chosen by the caller for workload delete and for prepare/commit
(`crates/secrets-http/src/lib.rs` `workload_delete`, `workload_prepare`), and for put it was
`owner_subject` rather than the verified principal (`crates/secrets-postgres/src/lib.rs` `put`).
Found by the retrofit, 2026-09-27.

## Acceptance

Every audit event records the verified principal as its actor, and an actor the request names is
recorded beside it as `claimed_actor`, never in its place.

## Evidence

`spec/domains/custody.yaml` actors `User` and `Workload` declare the `subject` attribute; the put,
revoke, delete and commit events carry `actor: {caller: subject}`. Pre-existing defect.

## Verification

- The synthesized `secrets.custody` suite sends each of those commands as a caller and requires the
  event's `actor` to equal the caller's `subject`, also when a delete body names another actor, and
  again with the two callers swapped. Blocked until ESS ships beyond10x/ess#430: the swapped run
  reuses the struct `reference`, which errors 14 scenarios and fails 2.
- `crates/secrets-postgres/tests/lifecycle.rs` `audit_records_the_verified_actor_beside_the_claimed_one`
  reads the audit rows of a put, a delete with a claim and a committed batch. Falsification: with
  `audit` recording the claim in place of the verified actor, it fails.

## Scenarios

- put, delete, revoke and commit each record the verified principal
- a request naming a different actor records it beside the verified one, never instead
- a falsification record shows the set fails when the caller-supplied actor is used
