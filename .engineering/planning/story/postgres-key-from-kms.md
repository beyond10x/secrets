---
format: aep.planning-md/3
id: story:postgres-key-from-kms
kind: story
status: draft
title: KMS supplies the key-encryption key of the Postgres backend
summary: Data keys wrapped by a KMS key in place of the keyring file; keyring file stays supported
relations:
- informed_by: epic:named-federated-storage
revision: 1
---
# KMS supplies the key-encryption key of the Postgres backend

## Need

The operator wants the Postgres backend to store secrets encrypted in the database, with a key
management service (KMS) giving the key that encrypts and decrypts them. Today the Postgres
backend takes its keys from a keyring file: `--keyring-file` / `SECRETS_KEYRING_FILE`
(`crates/secrets-app/src/main.rs:26-28`), read by `Keyring::from_file`
(`crates/secrets-app/src/main.rs:80`, `crates/secrets-crypto/src/lib.rs:45-49`), a JSON document
with an `active` key id and 32-byte keys in base64 (`crates/secrets-crypto/src/lib.rs:34-43`).
The file is the only key source; the key material lives on the service's disk or mount.

## Acceptance

- The Postgres backend can take its key-encryption key from a KMS instead of the keyring file:
  each stored value's data key is wrapped and unwrapped by the KMS, and the KMS key never leaves it.
- With the KMS source configured, a value written is read back equal, and the row in the database
  holds neither the value nor an unwrapped data key (a test reads the row).
- A KMS refusal or outage is `StorageError::Unavailable` and carries none of the KMS's own text;
  the service starts with neither a keyring file nor a key in its environment.
- Values written under the keyring file can be rewrapped under the KMS key (the existing
  `rewrap` command or its successor), and a test shows reads succeed before and after.
- The keyring file stays a supported source; which KMS (AWS KMS first) is configuration, tested
  against a local KMS emulator in CI.
