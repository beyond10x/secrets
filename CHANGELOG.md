# Changelog

## 0.1.2 - 2026-09-01

- Verify user tokens through Identity's generic access-authority endpoint with the exact configured
  audience header and interpret opaque returned scopes only inside Secrets.

## 0.1.1 - 2026-09-01

- Add authorized, metadata-only workload reference enumeration for remote store adapters.

## 0.1.0 - 2026-09-01

- Add tenant-scoped PostgreSQL custody with per-version envelope encryption.
- Add exact user and Kubernetes workload authority adapters.
- Add non-reveal user lifecycle and transactional workload APIs.
- Add an official Rust client, embedded docs/OpenAPI, probes, metrics, migrations, and key rewrap tooling.
