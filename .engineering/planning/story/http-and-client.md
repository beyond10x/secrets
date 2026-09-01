---
format: aep.planning-md/1
id: story:http-and-client
kind: story
status: implemented
title: Publish the HTTP contract and Rust client
summary: Expose user lifecycle and workload store operations with embedded docs and OpenAPI.
relations:
- derived_from: epic:encrypted-custody
revision: 4
---
## Acceptance

The official client exercises every documented user and workload operation while secret values never enter paths, queries, errors, metrics or logs.
