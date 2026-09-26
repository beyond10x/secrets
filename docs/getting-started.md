---
title: Getting started
description: Build Secrets, create a keyring, and migrate a local PostgreSQL database.
sidebar_position: 2
---

# Getting started

This page takes you from a checkout to a migrated database. It also says where local use stops:
the service itself only starts inside a Kubernetes cluster.

## Prerequisites

- Rust 1.97 (the workspace's `rust-version`)
- PostgreSQL 16 or later; CI runs against PostgreSQL 17
- `task` ([go-task](https://taskfile.dev)) for the repository checks

## Build

```sh
cargo build --locked -p secrets-app -p secretsctl
```

This produces two binaries:

| Binary | Package | Commands |
|---|---|---|
| `secrets` | `secrets-app` | `serve`, `migrate`, `rewrap` |
| `secretsctl` | `secretsctl` | `generate-keyring`, `health` |

## Create a keyring

A keyring is a JSON file holding one or more 32-byte keys and naming the active one. Generate a
first keyring with a single key, `v1`:

```sh
secretsctl generate-keyring > keyring.json
chmod 600 keyring.json
```

`--key-id` changes the key identifier (default `v1`). The file contains a raw key in base64:
anyone holding it and a copy of the database can decrypt every value. Keep it out of version
control and out of shared temporary directories.

## Migrate a database

```sh
export SECRETS_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets
secrets migrate --keyring-file keyring.json
```

Every `secrets` command connects, validates the keyring and applies pending migrations, so
`migrate` is that step alone. It creates four tables: `secrets`, `secret_versions`,
`prepared_transactions` and `audit_events`. Every option also reads an environment variable;
`secrets <command> --help` lists them.

## Serve

`secrets serve` needs a database, a keyring, an Identity origin and audience for people, and a
workload audience and grants file for service accounts:

```sh
secrets serve \
  --keyring-file keyring.json \
  --identity-origin https://identity.example \
  --identity-audience secrets \
  --workload-audience secrets \
  --workload-grants-file grants.json
```

Outside a cluster this exits with `Error: Unavailable`. The workload authority reads
`KUBERNETES_SERVICE_HOST` and the service-account CA certificate at
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` when it starts, and there is no mode that
disables it. Run the service in a cluster, as a composition chart does; see
[Operations](operations.md) and [Authentication](authentication.md).

Once running, the service listens on `0.0.0.0:8080` by default (`--bind`) and hosts its own
reference page at `/docs` and its contract at `/openapi.json`.

## Run the checks

```sh
task check
```

This runs `cargo fmt --check`, the workspace tests, clippy with warnings denied, `cargo doc`,
a check that `docs/openapi.json` is OpenAPI 3.1.0 at the workspace version, planning validation
and a provenance check. The PostgreSQL lifecycle test in `crates/secrets-postgres/tests` returns
early unless `SECRETS_TEST_DATABASE_URL` names a database; point it at a disposable one to
exercise real persistence.
