---
format: aep.planning-md/3
id: story:spec-limits-ess-052
kind: story
status: implemented
title: Specification limit markers match ESS 0.52.0
relations:
- decomposes: epic:encrypted-custody
scope:
- confidence: cited
  path: contracts
- confidence: cited
  path: spec/domains/custody.yaml
- confidence: cited
  path: spec/domains/storage.yaml
- confidence: cited
  path: website/docs/reference/ess
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T09:13:01Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-05T09:13:01Z", actor: "human:timo", revision: 4}
- {from: "active", to: "implemented", at: "2026-10-05T09:13:01Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1}}}
---
## Outcome

Every `ESS-LIMIT` marker in `spec/` states a limit that ESS 0.52.0 still has, names the version it
was checked against and the ESS issue that tracks it; limits 0.52.0 lifted are declared instead.

## Context

The markers were written against ESS 0.36. `deletes:` (removal), `instances:`/`affects:` (set
effects) and actor `attributes:` arrived since. Caller-attribute markers (custody `PreparedTransaction`
identity, `PutSecret.owner_subject` fallback, `not-owned`, `OwnedSecrets` filter,
`cross-tenant-batch`) belong to `story:verified-audit-actor`, which waits for beyond10x/ess#430.

## Acceptance

- `CommitTransaction.committed` declares `deletes: secrets.custody.PreparedTransaction`.
- `RemoveNamespace.removed`, `Unbind.unbound` and `Delete.deleted` declare `deletes:` on their entity.
- Every remaining non-caller marker cites ESS 0.52.0 or an open ESS issue (#229, #233, #428, #429).
- `task check` exits 0: conformance 111/111 three times; `secrets-library` synthesizes with 0 refusals.

## Ambiguities

None.
