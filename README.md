# Secrets

Secrets is an encrypted, tenant-scoped custody service for credentials that belong to people and
to the workloads acting for them. A workload hands Secrets a value; Secrets encrypts it in the
application, stores only ciphertext in PostgreSQL, and gives it back only to a workload that is
authorized for that exact tenant and action. The person who owns the value can see its metadata,
revoke it or delete it, but in this release no one can read a stored value back through a user
endpoint.

Status: development, version 0.3.1. The HTTP contract is [OpenAPI 3.1](docs/openapi.json).

## Why it exists

Services that call external providers on a user's behalf end up holding that user's tokens and
keys. Keeping those bytes in each service's own database spreads plaintext, key material and
ad-hoc access rules across the platform. Secrets gives them one place with one set of rules:

- **Encrypted before storage.** Every version of every value gets its own data key, wrapped by a
  versioned key-encryption key that PostgreSQL never sees.
- **Tenant-bound.** Every reference names a tenant, a namespace and a key, and the caller's
  verified tenant must match before storage is touched.
- **Least privilege.** Workloads are Kubernetes service accounts granted explicit actions; people
  are verified by an Identity authority and can act only on what they own.
- **Custody, not provider logic.** OAuth exchange, refresh and upstream revocation stay in the
  integrating service. Secrets holds bytes, versions, bindings and audit records.

The first consumer is the remote secret-store backend of Connectors.

## Guide

| Page | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Build, create a keyring, migrate a local database |
| [Security model](docs/security-model.md) | Envelope encryption, associated data, disclosure, revoke and delete, audit |
| [Authentication](docs/authentication.md) | Workload tokens and grants, user tokens, the action list |
| [HTTP API](docs/http-api.md) | Every route, its action, body and status codes |
| [Rust client](docs/rust-client.md) | The `secrets-client` crate for workloads |
| [Operations](docs/operations.md) | Configuration, probes, logs, key rotation, backups, image |
| [Architecture](docs/architecture.md) | Ownership, request path, deployment boundary |
| [Known limitations](docs/limitations.md) | What the current release does not do, or does differently from what you might expect |
| [Roadmap](docs/roadmap.md) | Planned: named, scoped secrets across several storage backends |

## Quick start

Requirements: Rust 1.97, PostgreSQL 16 or later, and `task`.

```sh
export SECRETS_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets
cargo run -p secretsctl -- generate-keyring > keyring.json
cargo run -p secrets-app -- migrate --keyring-file keyring.json
```

`keyring.json` holds a raw encryption key: keep it out of version control. Serving needs a
Kubernetes cluster; see [Getting started](docs/getting-started.md).

## Workspace

- `secrets-core`: resource model and storage port
- `secrets-crypto`: envelope encryption and versioned keyring
- `secrets-postgres`: migrations and transactional store
- `secrets-auth`: Identity and Kubernetes authority adapters
- `secrets-http`: HTTP API and embedded docs
- `secrets-client`: official Rust workload client
- `secrets-app`: the `secrets` service, migration and rewrap binary
- `secretsctl`: operator helpers

## Development

```sh
task check
```

`task check` runs formatting, tests, clippy, the documentation build, plan validation and a
provenance check. The PostgreSQL lifecycle test runs only when `SECRETS_TEST_DATABASE_URL` points
at a disposable database.

## License

Apache-2.0.

<!-- b10x-docs:start -->
## Documentation

[Secrets documentation](https://beyond10x.github.io/docs/secrets/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->
