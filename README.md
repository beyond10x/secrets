# Secrets

Secrets is a public, provider-neutral custody service for user and workload credentials. It encrypts every value in the application before PostgreSQL sees it and gives people safe metadata, revocation, and deletion without making connector-created values revealable.

The first integration is a remote secret-store backend for Connectors. The contract is intentionally general enough for later user-created secrets, without moving OAuth refresh or provider revocation into this service.

## Security model

- A random AES-256-GCM data-encryption key protects each version. A versioned key-encryption key wraps that key.
- Authenticated data binds tenant, namespace, key, version, disclosure, and format. Moving ciphertext to another record fails authentication.
- PostgreSQL stores ciphertext, nonces, wrapped keys, key IDs, metadata, and audit records—never plaintext or KEK bytes.
- A keyring is mounted read-only from a pre-created Kubernetes Secret. Rotation adds a key, changes `active`, runs `secrets rewrap`, verifies, then removes the old key in a later operation.
- Workloads authenticate with projected Kubernetes service-account tokens for an exact audience. A local grant file maps exact service-account subjects to one tenant and explicit actions.
- People authenticate through a configured Identity authority and can list, inspect, revoke, or delete only their owned resources. There is no user reveal endpoint in v0.1.

See [architecture](docs/architecture.md), the embedded [API page](docs/index.html), and [OpenAPI](docs/openapi.json).

## Run locally

Requirements: Rust 1.97, PostgreSQL 16+, and `task`.

```sh
export SECRETS_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/secrets
cargo run -p secretsctl -- generate-keyring > /tmp/secrets-keyring.json
cargo run -p secrets-app -- migrate --keyring-file /tmp/secrets-keyring.json
```

Serving also requires a user authority origin and an in-cluster Kubernetes TokenReview environment. Production configuration is listed by `secrets serve --help`. The service hosts documentation at `/docs`, OpenAPI at `/openapi.json`, liveness at `/health/live`, readiness at `/health/ready`, and Prometheus text metrics at `/metrics`.

## Workspace

- `secrets-core`: resource model and storage port
- `secrets-crypto`: envelope encryption and versioned keyring
- `secrets-postgres`: migrations and transactional store
- `secrets-auth`: Identity and Kubernetes authority adapters
- `secrets-http`: HTTP API and embedded docs
- `secrets-client`: official Rust workload client
- `secrets-app`: service and migration binary
- `secretsctl`: operator helpers

## Development

```sh
task check
```

The project uses AEP artifacts under `.engineering/planning`; architecture spanning repositories belongs in the central Atlas, not this product-local plan.

## License

Apache-2.0.

<!-- b10x-docs:start -->
## Documentation

[Secrets documentation](https://beyond10x.github.io/docs/secrets/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->
