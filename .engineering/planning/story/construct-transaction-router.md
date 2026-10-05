---
format: aep.planning-md/3
id: story:construct-transaction-router
kind: story
status: implemented
title: Construct every shipped transaction route
summary: Prevent invalid Axum path syntax from reaching a service image.
relations:
- derived_from: epic:encrypted-custody
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T12:00:14Z", actor: "human:timo", revision: 3, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T12:00:14Z", actor: "human:timo", revision: 4, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T12:00:15Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

The service router constructs without panic. Commit and abort use valid path segments, the OpenAPI contract and client use the same paths, and a regression test exercises route registration.
