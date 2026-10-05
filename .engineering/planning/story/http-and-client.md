---
format: aep.planning-md/3
id: story:http-and-client
kind: story
status: implemented
title: Publish the HTTP contract and Rust client
summary: Expose user lifecycle and workload store operations with embedded docs and OpenAPI.
relations:
- derived_from: epic:encrypted-custody
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

The official client exercises every documented user and workload operation while secret values never enter paths, queries, errors, metrics or logs.
