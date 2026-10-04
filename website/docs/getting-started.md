---
title: Getting started
sidebar_position: 2
description: Build Secrets, create a keyring, migrate a local PostgreSQL database, and run the checks.
---

# Getting started

From a checkout to a migrated database. Serving needs a Kubernetes cluster; this page says why.

## Prerequisites

- Rust 1.97
- PostgreSQL 16 or later (CI runs 17)
- [`task`](https://taskfile.dev) and the [`ess`](https://beyond10x.github.io/docs/ess/) CLI 0.52.0
  for `task check`

## Build

```sh
cargo build --locked -p secrets-app -p secretsctl
```

| Binary | Package | Commands |
|---|---|---|
| `secrets` | `secrets-app` | `serve`, `migrate`, `rewrap` |
| `secretsctl` | `secretsctl` | `generate-keyring`, `health` |

## Create a keyring

A keyring is a JSON file of 32-byte keys that names the active one.

```sh
secretsctl generate-keyring > keyring.json
chmod 600 keyring.json
```

`--key-id` sets the key's ID (default `v1`). The file holds a raw key: with it and a copy of the
database, anyone can decrypt every value. Keep it out of version control and shared directories.

## Migrate a database

```sh
export SECRETS_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets
secrets migrate --keyring-file keyring.json
```

Every `secrets` command validates the keyring and applies pending migrations when it connects;
`migrate` does only that. It creates `secrets`, `secret_versions`, `prepared_transactions` and
`audit_events`.

## Serve

```sh
secrets serve \
  --keyring-file keyring.json \
  --identity-origin https://identity.example \
  --identity-audience secrets \
  --workload-audience secrets \
  --workload-grants-file grants.json
```

Outside a cluster this exits with `Error: Unavailable`: the workload authority reads
`KUBERNETES_SERVICE_HOST` and the service-account CA certificate at startup, and there is no mode
without it. Run it as a composition chart does; see [Operations](./operations.md). A running
instance listens on `0.0.0.0:8080` and serves `/openapi.json` and a short reference at `/docs`.

## Run the checks

```sh
export SECRETS_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets_check
task check
```

`task check` runs formatting, tests, clippy, `cargo doc`, plan and specification validation, the
generated-page drift check, a provenance check, and the conformance suite against PostgreSQL. The
conformance step refuses to run without `SECRETS_TEST_DATABASE_URL`; point it at a disposable
database.
