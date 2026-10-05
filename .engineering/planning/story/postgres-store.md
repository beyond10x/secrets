---
format: aep.planning-md/3
id: story:postgres-store
kind: story
status: implemented
title: Persist encrypted resources transactionally
summary: Store metadata, bindings, versions, transactions and audit events in PostgreSQL.
relations:
- derived_from: epic:encrypted-custody
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

Secret mutations, revocation, cryptographic deletion and prepared batches remain tenant-isolated and correct across process restart.
