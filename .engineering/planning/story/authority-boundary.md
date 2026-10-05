---
format: aep.planning-md/3
id: story:authority-boundary
kind: story
status: implemented
title: Verify user and workload authority
summary: Resolve exact Identity audiences and projected Kubernetes workload tokens.
relations:
- derived_from: epic:encrypted-custody
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

Wrong audiences, subjects, service accounts, scopes and tenants are refused before any secret metadata or value is read.
