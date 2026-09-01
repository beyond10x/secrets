# Architecture

## Ownership

Secrets owns encrypted value custody, versions, bindings, prepared mutations, local revocation/deletion, and custody audit events. An integrating provider service owns exchange, refresh, provider policy, and upstream revocation. Identity remains a generic token authority.

## Request path

1. The HTTP boundary accepts a bounded JSON body and a bearer token.
2. The selected authority verifies the exact audience, subject, tenant, and action before storage is called.
3. The store locks the tenant-scoped binding and allocates a monotonically increasing version.
4. The crypto adapter generates a fresh DEK and independent value/wrapping nonces. It authenticates the complete resource identity as associated data.
5. One PostgreSQL transaction writes ciphertext, the wrapped DEK, metadata, and an audit event.

Delete removes the resource row and cascades through every encrypted version. Revocation preserves custody evidence but prevents workload reads. Prepared batches are tenant-homogeneous and become visible in one PostgreSQL transaction.

## Key operations

The keyring JSON has this shape:

```json
{"active":"v2","keys":{"v1":"base64-32-byte-key","v2":"base64-32-byte-key"}}
```

It is configuration, not database state. Keep the old key while `secrets rewrap` decrypts and re-encrypts active versions to the new key. Back up PostgreSQL and key material through separate protected mechanisms; neither is sufficient alone.

## Deployment boundary

This repository publishes source, binaries, and an OCI image. It deliberately has no standalone Helm chart. A composition chart—initially Devcenter—owns PostgreSQL selection, keyring Secret references, service-account token projection, RBAC for TokenReview, NetworkPolicy, and application wiring.

