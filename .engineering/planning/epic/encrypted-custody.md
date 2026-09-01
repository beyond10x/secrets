---
format: aep.planning-md/1
id: epic:encrypted-custody
kind: epic
status: implemented
title: Encrypted secret custody service
summary: Publish tenant-scoped encrypted custody for user and workload lifecycle.
revision: 4
---
## Outcome

A public service stores encrypted secret values in PostgreSQL, authenticates people and Kubernetes workloads, and exposes safe metadata, revocation and cryptographic deletion.

## Acceptance

A released service survives restart, refuses cross-tenant or reveal access, and serves its documented API over encrypted PostgreSQL state.
