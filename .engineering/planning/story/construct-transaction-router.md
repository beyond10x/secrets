---
format: aep.planning-md/1
id: story:construct-transaction-router
kind: story
status: implemented
title: Construct every shipped transaction route
summary: Prevent invalid Axum path syntax from reaching a service image.
relations:
- derived_from: epic:encrypted-custody
revision: 5
---
## Acceptance

The service router constructs without panic. Commit and abort use valid path segments, the OpenAPI contract and client use the same paths, and a regression test exercises route registration.
