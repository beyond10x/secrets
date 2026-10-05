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
- [`task`](https://taskfile.dev) and the [`ess`](https://beyond10x.github.io/docs/ess/) CLI 0.53.0
  for `task check`

## Build

```sh
cargo build --locked -p secrets-app -p secretsctl
```

| Binary | Package | Commands |
|---|---|---|
| `secrets` | `secrets-app` | `serve`, `migrate`, `rewrap` |
| `secretsctl` | `secretsctl` | `generate-keyring`, `health`, and the [local commands](#local-cli) |

## Create a keyring

A keyring is a JSON file of 32-byte keys that names the active one.

```sh
secretsctl generate-keyring > keyring.json
chmod 600 keyring.json
```

`--key-id` sets the key's ID (default `v1`). The file holds a raw key: with it and a copy of the
database, anyone can decrypt every value. Keep it out of version control and shared directories.

## Local CLI

`secretsctl` also manages [named secrets](./status.mdx#named-secrets-over-several-backends) on
this machine, in tenant `default` and user `default`, in namespace `default` unless `--namespace`
names another.

```sh
printf '%s' "$API_KEY" | secretsctl put openai   # or a hidden prompt, or --file
secretsctl list --all
secretsctl describe openai
secretsctl read openai --out ./openai.key   # a new mode-0600 file; never stdout
secretsctl rename openai openai-work
secretsctl namespace add work --mount remote/prod
secretsctl bind openai op://Work/OpenAI/credential --namespace work
```

The commands are `put`, `read`, `describe`, `list`, `delete`, `rename`, `namespace add|list|remove`,
`mount set`, `bind` and `unbind`; `--json` prints results and refusals as JSON.

- **No value is printed.** `describe` and `list` show name, scope, backend and version. `put` reads
  from a hidden prompt, a pipe or `--file`, refuses a value on the command line, and refuses a
  file its group or others can access.
- **Reading a value.** `read <name> --out <file>` writes the value, byte for byte, into a new file
  of mode 0600 and prints only where it went. It refuses a path that exists, a symlink (dangling
  or not) and a directory before any backend is asked, and the file appears whole or not at all:
  the value goes into a temporary file beside it, which is then linked into place without
  replacing anything that appeared there meanwhile.
- **Scope.** `--tenant` and `--user` name the scope a command acts in; both default to `default`,
  the only tenant and user local mode serves. Any other value is refused as `denied`, naming the
  flag, before the configuration file is read or any backend is opened.
- **Configuration.** `$XDG_CONFIG_HOME/b10x-secrets/config.toml` (`~/.config/...` when unset)
  holds namespaces, mounts, bindings and backends, and no secret. Each change replaces it
  atomically with mode 0600.
- **Backends.** `keychain/default` is always configured; the OS keychain needs a build with
  `--features native-keychain` and answers `unavailable` without it. A remote backend takes its
  token from an environment variable or a mode-0600 file:

  ```toml
  [backends.remote.prod]
  origin = "https://secrets.example"
  token_env = "B10X_SECRETS_TOKEN"   # or token_file = "/path/to/token"
  ```

- **Exit codes.** 2 for a refused command line or value; 3 to 9 for `not-found`, `denied`,
  `unsupported`, `unavailable`, `invalid-name`, `too-large` and `conflict`.

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
