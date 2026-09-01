---
format: aep.planning-md/1
id: story:authority-boundary
kind: story
status: implemented
title: Verify user and workload authority
summary: Resolve exact Identity audiences and projected Kubernetes workload tokens.
relations:
- derived_from: epic:encrypted-custody
revision: 4
---
## Acceptance

Wrong audiences, subjects, service accounts, scopes and tenants are refused before any secret metadata or value is read.
