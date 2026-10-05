# Secrets

Encrypted, tenant-scoped custody for the credentials that workloads hold on people's behalf.

A workload hands Secrets a value. Secrets encrypts it in the application, stores only ciphertext
in PostgreSQL, and gives it back only to a workload granted that exact tenant and action. The
person who owns the value can see its metadata, revoke it or delete it; no user route returns a
value.

**Documentation: <https://beyond10x.github.io/secrets/>**

Version 0.4.1, in development. HTTP contract: [OpenAPI 3.1](docs/openapi.json).

## Why

Services that call providers for a user end up holding that user's tokens. Kept in each service's
own database, they spread plaintext, key material and access rules across the platform. Secrets
keeps them in one place with one set of rules:

- **Encrypted before storage**: a data key per version, wrapped by a versioned key that PostgreSQL
  never sees, with the reference bound in as associated data.
- **Tenant-bound, least privilege**: workloads are Kubernetes service accounts granted explicit
  actions in one tenant; people are verified by Identity and act only on what they own.
- **Custody, not provider logic**: OAuth exchange, refresh and upstream revocation stay in the
  integrating service.

## Quick start

Requires Rust 1.97, PostgreSQL 16 or later, and [`task`](https://taskfile.dev).

```sh
export SECRETS_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets
cargo run -p secretsctl -- generate-keyring > keyring.json
cargo run -p secrets-app -- migrate --keyring-file keyring.json
```

`keyring.json` holds a raw key; keep it out of version control. Serving needs a Kubernetes
cluster: see [Getting started](https://beyond10x.github.io/secrets/docs/getting-started).

## Workspace

| Crate | Role |
|---|---|
| `secrets-core` | resource model and storage port |
| `secrets-crypto` | envelope encryption and the versioned keyring |
| `secrets-postgres` | migrations and the transactional store |
| `secrets-auth` | Identity and Kubernetes authorities |
| `secrets-http` | the HTTP API |
| `secrets-client` | Rust client for workloads |
| `secrets-app` | the `secrets` binary: `serve`, `migrate`, `rewrap` |
| `secretsctl` | operator helpers |
| `secrets-docs` | generates the site's specification pages |
| `checks/conformance` | runs the ESS specification against the service |

The specification is in [`spec/`](spec/) (ESS), the site in [`website/`](website/).

## Development

```sh
export SECRETS_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets_check
task check
```

How to work in this repository as an agent: [AGENTS.md](AGENTS.md).

## License

Apache-2.0. Security reports: [SECURITY.md](SECURITY.md).
