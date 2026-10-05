---
title: Operations
sidebar_position: 7
description: Image, configuration, probes, logs, key rotation and backups.
---

# Operations

## Image

Each release tag publishes `ghcr.io/beyond10x/secrets:<tag>` and `latest` for `linux/amd64`:
distroless, non-root, port `8080`, entry point `secrets`, with `secretsctl` included. There is no
Helm chart here; the composing product's chart provides PostgreSQL, the keyring Secret, the
workload token projection, `TokenReview` RBAC and network policy.

## Configuration

| Option | Variable | Meaning |
|---|---|---|
| `--database-url` | `SECRETS_DATABASE_URL` | PostgreSQL URL |
| `--keyring-file` | `SECRETS_KEYRING_FILE` | keyring JSON, mounted read-only |
| `--bind` | `SECRETS_BIND` | listen address, default `0.0.0.0:8080` |
| `--identity-origin` | `SECRETS_IDENTITY_ORIGIN` | Identity origin for user tokens |
| `--identity-audience` | `SECRETS_IDENTITY_AUDIENCE` | audience user tokens must carry |
| `--workload-audience` | `SECRETS_WORKLOAD_AUDIENCE` | audience workload tokens must carry |
| `--workload-grants-file` | `SECRETS_WORKLOAD_GRANTS_FILE` | workload grant JSON |

The service also reads `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT_HTTPS` (default `443`)
and the service-account token and CA under `/var/run/secrets/kubernetes.io/serviceaccount/`. The
keyring and grant files are read once at startup, so a change needs a restart; the reviewer token
is read per request. `secrets migrate` and `secrets rewrap` take `--database-url` and
`--keyring-file`; `rewrap` also takes `--actor` (default `secretsctl`) for its audit events.

## Probes, metrics and logs

| Endpoint | Use |
|---|---|
| `GET /health/live` | `204` while the process serves HTTP |
| `GET /health/ready` | `204` when `SELECT 1` succeeds, else `503` |
| `GET /metrics` | Prometheus text: the gauge `secrets_up 1` |

`secretsctl health <origin>` prints `ready` or exits non-zero. Logs are JSON lines on standard
output, filtered by `RUST_LOG` (default `info`). `SIGINT` drains in-flight requests; `SIGTERM` has
no handler and ends the process at once.

## Rotate the key-encryption key

1. `secretsctl generate-keyring --key-id v2` prints a one-key keyring.
2. Merge its key into the keyring file, set `"active": "v2"`, and keep `v1`.
3. Update the keyring Secret and restart. New versions are now wrapped by `v2`.
4. Run `secrets rewrap`. In one transaction it re-encrypts every current version wrapped by another
   key, writes a `rewrap` audit event for each and prints `rewrapped <n> secret(s)`. A second
   transaction then deletes expired batches and re-seals held ones under `v2`.
5. Run it again: it prints `rewrapped 0 secret(s)`.
6. Keep `v1`. Versions older than the current one still name it, and removing it makes them
   undecryptable.

## Backups

Back up PostgreSQL and the keyring through separate protected channels. Neither alone exposes a
value; together they expose every value in the backup, including rows deleted since.
