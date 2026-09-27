---
title: Security model
description: Envelope encryption, keyring rotation and rewrap, associated data, disclosure, revoke versus delete, and audit records.
sidebar_position: 3
---

# Security model

Secrets protects values with envelope encryption in the application, binds each ciphertext to the
record it belongs to, and checks the caller's tenant and action before any storage call. This page
describes what the current release does. Where it falls short, [Known limitations](limitations.md)
says so.

## What is stored where

| Where | What |
|---|---|
| PostgreSQL `secret_versions` | ciphertext, value nonce, wrapped data key, wrap nonce, key ID, per version |
| PostgreSQL `secrets` | tenant, namespace, key, owner subject, disclosure, state, current version, labels, timestamps |
| PostgreSQL `audit_events` | tenant, secret ID, actor, action, time |
| Keyring file (read-only mount) | the key-encryption keys and the active key ID |

The database never holds key-encryption keys, and committed values are only ever stored
encrypted.

## Envelope encryption

For every write, the service:

1. Generates a fresh random 256-bit data-encryption key (DEK) and two random 96-bit nonces.
2. Encrypts the value with AES-256-GCM under the DEK.
3. Encrypts (wraps) the DEK with AES-256-GCM under the keyring's active key-encryption key (KEK).
4. Stores the ciphertext, the wrapped DEK, both nonces and the KEK's ID as a new version.

Each write creates a new version with a monotonically increasing number; earlier versions stay in
`secret_versions` until the secret is deleted. Reads decrypt the current version with the KEK
named by that version's key ID. A new DEK lives in a buffer that is zeroed when dropped, a
decrypted DEK is zeroed after a successful decryption, and value buffers are zeroed on drop.

## Associated data

Both encryptions authenticate the same associated data: a format tag (`secrets/v1`), the tenant,
namespace, key, version number and disclosure. A ciphertext copied to another record, another
tenant, another version number or another disclosure fails authentication and is refused, as is
any modified byte. The crypto crate's unit test checks a round trip, a flipped ciphertext byte and a
changed tenant.

## Keyring, rotation and rewrap

The keyring is configuration, not database state:

```json
{"active":"v2","keys":{"v1":"<base64 32-byte key>","v2":"<base64 32-byte key>"}}
```

It is read once when a `secrets` command starts; the `active` ID must be one of `keys`. New
versions are always wrapped by the active key. Older versions keep the key ID they were written
with, so a key must stay in the keyring while any version still names it.

Rotation adds a key, makes it active, and then runs `secrets rewrap`, which decrypts and
re-encrypts under the active key. In this release rewrap covers only the **current** version of
each secret; older versions remain under their original key. Keep old keys until that is fixed
(see [Known limitations](limitations.md#rewrap-covers-only-current-versions)). Rewrap also re-seals
every held prepared batch under the active key. A prepared batch is held encrypted the same way,
with associated data that binds its tenant, transaction ID and actor, and it expires 600 seconds
after it is prepared. The procedure is in
[Operations](operations.md#rotate-the-key-encryption-key).

## Disclosure

Every secret records a disclosure, bound into its associated data:

- `workload_only` (the default): the value is for workloads.
- `user_revealable`: the value may later be shown to its owner.

This release has **no user reveal endpoint**. User routes return metadata only, whatever the
disclosure. Workload reads do not consult disclosure either: a workload granted
`secret:read_value` in the tenant can read both kinds.

## Revoke versus delete

| | Revoke | Delete |
|---|---|---|
| Who | the owner (user route) | the owner (user route) or a workload with `secret:delete` |
| Metadata | kept, `state` becomes `revoked` | removed |
| Encrypted versions | kept | removed with the record |
| Workload read / exists | `404` / `false` | `404` / `false` |
| Appears in listings | yes, as `revoked` | no |
| Audit event | `revoke` | `delete` (the event outlives the record) |

Revocation stops workload reads while keeping custody evidence. Writing to a revoked reference
again creates a new version and sets the state back to `active`.

Delete removes the rows from the live database. It is not cryptographic erasure: every version is
wrapped by a shared KEK, so a database backup or replica that still holds the rows can be
decrypted by anyone who also holds the keyring.

## Tenant and ownership checks

Every route that names a reference or a tenant requires the caller's verified tenant to equal it,
and refuses with `403` otherwise, before storage is called. User routes additionally act only on
secrets whose `owner_subject` is the caller's subject, and answer `404` for anything else, so a
person cannot learn whether another owner's secret exists. See [Authentication](authentication.md)
for how tenant, subject and actions are established.

## Audit records

The store writes one audit event, in the same transaction as the change, for each `put`, `revoke`,
`delete`, `rewrap` and committed batch (`commit_batch`). Events are stored in `audit_events`;
there is no API to read them. On some routes the recorded actor is chosen by the caller rather than
taken from the verified token (see
[Known limitations](limitations.md#audit-actors-can-be-caller-chosen)).

## What never leaves the service

- Values travel only in JSON request and response bodies, base64-encoded, never in paths or
  query strings. Request bodies are capped at 1 MiB.
- A refusal carries only the HTTP reason phrase and a fixed code, such as
  `{"error":"Not Found","code":"not-owned"}`, never any part of the request: a body or a path
  that does not parse is refused the same way, not with the framework's parse message.
- The service's own log events carry stage names and status codes, not tokens, subjects or
  values.
- Metrics carry no labels.
