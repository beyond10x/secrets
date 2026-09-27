# Changelog

## Unreleased

- A JSON body that does not parse into a route's request type is refused with `400` and
  `{"error": "Bad Request"}`, instead of axum's `422`/`415` text that quoted the offending input.

## 0.3.1 - 2026-09-27

- `secrets rewrap` prints `rewrapped <n> secret(s)`: the count covers secrets in every state, not
  only active ones.
- The specification moves to format `ess/14` and CI installs ESS 0.36.0 and AEP 0.61.1; the
  planning store's protocol pin moves to AEP 0.61.1. A put over an existing reference now declares
  its version as the previous one plus one, put and revoke declare the `updated_at` the database
  sets, and put and revoke declare the metadata they return. In the planned storage model a write
  declares its version as assigned by the backend.

## 0.3.0 - 2026-09-27

- Prepared batches are held encrypted, in the same envelope custody as secret versions, and
  expire after 600 seconds. Commit or abort of an expired batch is `404`. Migration `0002`
  discards batches prepared by an earlier release; commit or abort every held batch before
  upgrading.
- `secrets rewrap` re-encrypts held batches in a transaction of its own after the secrets, so a
  commit during a live key rotation completes.
- `SecretBytes` zeroizes its value on drop and redacts it from `Debug` output.

## 0.2.0 - 2026-09-27

- The system is specified in ESS (`spec/`, format `ess/13`): `secrets.custody` retrofits the
  shipped service from its code and OpenAPI document, and `secrets.storage` specifies the next
  milestone, named secrets scoped by tenant, namespace and user behind several storage backends.
  `task check` validates the specification.
- The planning store moves to `aep.project/3` on a tree Git merges, planned with AEP 0.60.0; CI
  installs AEP 0.60.0.
- Public documentation: getting started, security model, authentication, HTTP API, Rust client,
  operations, known limitations and a roadmap, and a rewritten README.
- The OpenAPI document and all crates are version 0.2.0. No runtime behaviour changes.

## 0.1.4 - 2026-09-01

- Emit value-free workload authorization stages so operators can distinguish Kubernetes authority
  failures from audience and grant refusals without exposing tokens or subjects.

## 0.1.3 - 2026-09-01

- Use valid Axum transaction action segments and construct those routes in a regression test before
  an image can be released.

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
