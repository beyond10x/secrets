---
title: Security model
sidebar_position: 3
description: Envelope encryption, associated data, keyring rotation, disclosure, revoke versus delete, and audit records.
---

# Security model

Values are encrypted in the application, each ciphertext is bound to the record it belongs to, and
the caller's tenant and action are checked before any storage call. Gaps are listed on the
[Status](./status.mdx#known-limitations) page.

## What is stored where

| Where | What |
|---|---|
| PostgreSQL `secret_versions` | per version: ciphertext, value nonce, wrapped data key, wrap nonce, key ID |
| PostgreSQL `secrets` | tenant, namespace, key, owner subject, disclosure, state, current version, labels, timestamps |
| PostgreSQL `audit_events` | tenant, secret ID, actor, action, time |
| PostgreSQL `prepared_transactions` | sealed batches, each expiring 600 seconds after prepare |
| Keyring file, mounted read-only | the key-encryption keys and the active key ID |

The database never holds a key-encryption key or a plaintext value.

## Envelope encryption

For every write the service:

1. generates a random 256-bit data key and two random 96-bit nonces;
2. encrypts the value with AES-256-GCM under the data key;
3. wraps the data key with AES-256-GCM under the keyring's active key;
4. stores ciphertext, wrapped key, both nonces and the key ID as a new version.

Versions are numbered upwards; older ones stay until the secret is deleted. A read decrypts the
current version with the key its key ID names. Key and value buffers are zeroed when dropped.

## Associated data

Both encryptions authenticate a format tag (`secrets/v1`), the tenant, namespace, key, version
number and disclosure. A ciphertext copied to another record, tenant, version or disclosure fails
authentication, as does any changed byte.

## Keyring, rotation and rewrap

```json
{"active":"v2","keys":{"v1":"<base64 32-byte key>","v2":"<base64 32-byte key>"}}
```

The keyring is configuration, read once at startup. New versions are wrapped by the active key;
older versions keep the key ID they were written with, so a key stays while any version names it.
Rotation adds a key, makes it active and runs `secrets rewrap`, which re-encrypts the **current**
version of each secret and re-seals every held prepared batch. Older versions are not rewrapped
yet. The procedure is in [Operations](./operations.md#rotate-the-key-encryption-key).

## Disclosure

Each secret records `workload_only` (the default) or `user_revealable`, bound into its associated
data. No user route returns a value in this release, whatever the disclosure, and workload reads
do not consult it.

## Revoke versus delete

| | Revoke | Delete |
|---|---|---|
| Who | the owner | the owner, or a workload with `secret:delete` |
| Metadata | kept, `state: revoked` | removed |
| Encrypted versions | kept | removed with the record |
| Workload read / exists | `404` / `false` | `404` / `false` |
| Listed | yes, as `revoked` | no |
| Audit event | `revoke` | `delete`, which outlives the record |

Writing to a revoked reference creates a new version and makes it `active` again. Delete is not
cryptographic erasure: a backup that still holds the rows can be decrypted with the keyring.

## Tenant and ownership

Every route that names a reference or tenant requires the caller's verified tenant to equal it and
answers `403` otherwise, before storage is called. User routes act only on secrets whose
`owner_subject` is the caller and answer `404` for anything else, so a person cannot learn whether
another owner's secret exists. See [Authentication](./authentication.md).

## What never leaves the service

- Values travel only in JSON bodies, base64-encoded, never in paths or query strings.
- A refusal is `{"error": <reason phrase>, "code": <code>}` and never repeats the request.
- Log events carry stage names and status codes, not tokens, subjects or values.
- Metrics carry no labels.
