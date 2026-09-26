---
title: Known limitations
description: What Secrets 0.1.4 does not do, or does differently from what its model implies.
sidebar_position: 9
---

# Known limitations

These apply to version 0.1.4. Each describes the code as it is; the first two are tracked for a
fix.

## Rewrap covers only current versions

`secrets rewrap` re-encrypts only the current version of each secret. Older versions stay wrapped
by the key they were written with. Removing that key from the keyring after a rotation makes those
versions undecryptable. No API reads a non-current version today, but the rotation procedure must
keep every old key until rewrap covers all versions. Fix tracked.

## Audit actors can be caller-chosen

The actor recorded on an audit event is not always the verified principal:

- `POST /v1/workload/secrets:delete` records the `actor` from the request body when one is given.
- A prepared batch records the `actor` from the prepare request, and every event written when it
  commits uses that actor.
- `PUT /v1/workload/secrets` records the secret's `owner_subject`, which the calling workload sets.

Treat audit actors on these routes as claims made by an authorized workload, not as verified
identities. Fix tracked.


## No user reveal

`user_revealable` is recorded and bound into the ciphertext, but there is no route through which
a person can read a value. Workload reads ignore disclosure.

## Serving requires Kubernetes

The workload authority starts only inside a cluster: without `KUBERNETES_SERVICE_HOST` and the
service-account CA file, `secrets serve` exits with `Error: Unavailable`. There is no local or
development authority.

## Delete is not cryptographic erasure

Delete removes the database rows. Every version is wrapped by a shared key-encryption key, so
copies in backups or replicas remain decryptable with the keyring.

## Other gaps

- Grant and keyring files are read once at startup; changes need a restart.
- A workload subject acts in exactly one tenant: the first matching grant wins.
- Audit events can be written but not read through the API.
- `/metrics` exposes only `secrets_up`.
- `SIGTERM` is not handled; only `SIGINT` drains in-flight requests.
- The OpenAPI document omits some request bodies, all error responses and the service routes; the
  [HTTP API](http-api.md#differences-from-the-openapi-document) page lists them.
