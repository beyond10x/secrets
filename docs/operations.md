---
title: Operations
description: Configure, deploy, observe, rotate keys for, and back up a Secrets service.
sidebar_position: 7
---

# Operations

## Image

Each release tag publishes `ghcr.io/beyond10x/secrets:<tag>` (and `latest`) for `linux/amd64`.
The image is distroless, runs as a non-root user, exposes port `8080`, has `secrets` as its entry
point and also contains `secretsctl`.

This repository ships no Helm chart. The composing product's chart owns PostgreSQL selection, the
keyring Secret, the service-account token projection, RBAC for `TokenReview`, network policy and
wiring; see [Architecture](architecture.md#deployment-boundary).

## Configuration

`secrets serve` options, each also read from an environment variable:

| Option | Variable | Meaning |
|---|---|---|
| `--database-url` | `SECRETS_DATABASE_URL` | PostgreSQL connection URL |
| `--keyring-file` | `SECRETS_KEYRING_FILE` | path to the keyring JSON, mounted read-only |
| `--bind` | `SECRETS_BIND` | listen address, default `0.0.0.0:8080` |
| `--identity-origin` | `SECRETS_IDENTITY_ORIGIN` | Identity service origin for user tokens |
| `--identity-audience` | `SECRETS_IDENTITY_AUDIENCE` | audience user tokens must carry |
| `--workload-audience` | `SECRETS_WORKLOAD_AUDIENCE` | audience projected workload tokens must carry |
| `--workload-grants-file` | `SECRETS_WORKLOAD_GRANTS_FILE` | path to the workload grant JSON |

The service also reads `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT_HTTPS` (default
`443`), and the mounted service-account token and CA certificate under
`/var/run/secrets/kubernetes.io/serviceaccount/`. The keyring and grant files are read once at
startup: restart the service to apply a change. The reviewer token is read on every workload
request, so its rotation needs no restart.

`secrets migrate` and `secrets rewrap` take `--database-url` and `--keyring-file`; `rewrap` also
takes `--actor` (default `secretsctl`), the name recorded on its audit events. Every command
applies pending migrations when it connects.

## Probes and metrics

| Endpoint | Use |
|---|---|
| `GET /health/live` | liveness: `204` while the process serves HTTP |
| `GET /health/ready` | readiness: `204` when `SELECT 1` succeeds, `503` otherwise |
| `GET /metrics` | Prometheus text; currently the single gauge `secrets_up 1` |

`secretsctl health <origin>` calls `<origin>/health/ready`, prints `ready` on success and exits
non-zero otherwise.

## Logs

Logs are JSON lines on standard output. The level filter comes from `RUST_LOG` and defaults to
`info`. Workload refusals log a `stage` field, listed in
[Authentication](authentication.md#workloads); no log event carries a token, subject or value.

## Shutdown

The server stops accepting connections and drains in-flight requests on `SIGINT`. It installs no
handler for `SIGTERM`, which therefore ends the process immediately; allow for that in the pod's
termination settings.

## Rotate the key-encryption key

1. Generate a new key: `secretsctl generate-keyring --key-id v2` prints a one-key keyring.
2. Merge its key into the existing keyring file and set `"active": "v2"`. Keep `v1` in `keys`.
3. Update the keyring Secret and restart the service. New versions are now wrapped by `v2`.
4. Run `secrets rewrap`. It re-encrypts, in one transaction, every current version still wrapped by
   another key, records a `rewrap` audit event for each, and prints
   `rewrapped <n> active secret(s)`.
5. Verify: a second `secrets rewrap` prints `rewrapped 0 active secret(s)`.
6. Keep `v1` in the keyring. Rewrap does not re-encrypt versions older than the current one, which
   still name `v1` ([Known limitations](limitations.md#rewrap-covers-only-current-versions)).
   Removing `v1` makes them undecryptable.

## Backups

Back up PostgreSQL and the keyring through separate protected mechanisms. The database alone
cannot be decrypted, and the keyring alone holds no values; together they expose every stored
value, including rows removed from the live database after the backup was taken.
