---
format: aep.planning-md/1
id: story:postgres-store
kind: story
status: implemented
title: Persist encrypted resources transactionally
summary: Store metadata, bindings, versions, transactions and audit events in PostgreSQL.
relations:
- derived_from: epic:encrypted-custody
revision: 4
---
## Acceptance

Secret mutations, revocation, cryptographic deletion and prepared batches remain tenant-isolated and correct across process restart.
