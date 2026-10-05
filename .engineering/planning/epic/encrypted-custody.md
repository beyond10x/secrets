---
format: aep.planning-md/3
id: epic:encrypted-custody
kind: epic
status: implemented
title: Encrypted secret custody service
summary: Publish tenant-scoped encrypted custody for user and workload lifecycle.
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T11:07:39Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T11:07:39Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T11:07:39Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Outcome

A public service stores encrypted secret values in PostgreSQL, authenticates people and Kubernetes workloads, and exposes safe metadata, revocation and cryptographic deletion.

## Acceptance

A released service survives restart, refuses cross-tenant or reveal access, and serves its documented API over encrypted PostgreSQL state.
