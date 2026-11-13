---
format: aep.planning-md/3
id: story:deployment-of-its-own
kind: story
status: draft
title: The service can be deployed on Kubernetes from what this repository ships
revision: 1
---
## Why

A team that plans to run this service on Kubernetes beside a service of its own, outside the
composing product, read the repository at `v0.6.0` and found nothing to deploy it with.
`website/docs/operations.md` says so itself: "There is no Helm chart here; the composing
product's chart provides PostgreSQL, the keyring Secret, the workload token projection,
`TokenReview` RBAC and network policy." That chart keeps the service off by default.

So a deployment of its own writes, from the configuration table alone: the Deployment, the mount
of the keyring Secret (`SECRETS_KEYRING_FILE`), the workload grant file
(`SECRETS_WORKLOAD_GRANTS_FILE`), the projected workload token and its audience, the ClusterRole
for `tokenreviews`, and the database settings. Nothing in the repository shows one of these as a
manifest, and no test holds a manifest to what `secrets serve` reads.

Reported by a reader of the source and the documentation; nothing here was run.

## Acceptance

- Either the repository holds a chart of its own that starts the service with a database the
  operator names, or `website/docs/operations.md` holds a minimal manifest set (Deployment,
  Service, the two mounted files, the ServiceAccount with the `tokenreviews` rule) that a reader
  can apply as written. The story says which and why.
- A test holds what is shipped to the service's own flags and variables: a variable the service
  requires and the chart or manifests do not set is a failing test.
- A run on a test cluster starts the service from what is shipped and `GET /health/ready`
  answers `204`.

## Notes

- Not decided: chart or documented manifests. A chart is one more thing to release; manifests in
  a page go stale unless a test reads them.
- The composing product's chart stays as it is.
