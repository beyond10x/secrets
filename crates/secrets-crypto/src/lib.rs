use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrets_core::{Disclosure, SecretBytes, SecretRef};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};
use thiserror::Error;
pub use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub ciphertext: Vec<u8>,
    pub value_nonce: [u8; 12],
    pub wrapped_key: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub key_id: String,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid keyring")]
    InvalidKeyring,
    #[error("cryptographic operation failed")]
    Failed,
    #[error("key not found")]
    KeyNotFound,
    #[error("keyring could not be read")]
    Io,
}

#[derive(Clone)]
pub struct Keyring {
    active: String,
    keys: BTreeMap<String, [u8; 32]>,
}

#[derive(Deserialize)]
struct KeyringFile {
    active: String,
    keys: BTreeMap<String, String>,
}

impl Keyring {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let bytes = fs::read(path).map_err(|_| CryptoError::Io)?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, CryptoError> {
        let input: KeyringFile =
            serde_json::from_slice(bytes).map_err(|_| CryptoError::InvalidKeyring)?;
        let mut keys = BTreeMap::new();
        for (id, encoded) in input.keys {
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| CryptoError::InvalidKeyring)?;
            let key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyring)?;
            keys.insert(id, key);
        }
        if !keys.contains_key(&input.active) {
            return Err(CryptoError::InvalidKeyring);
        }
        Ok(Self {
            active: input.active,
            keys,
        })
    }

    pub fn encrypt(
        &self,
        reference: &SecretRef,
        version: i64,
        disclosure: Disclosure,
        value: &SecretBytes,
    ) -> Result<Envelope, CryptoError> {
        self.seal(&associated_data(reference, version, disclosure), &value.0)
    }

    pub fn decrypt(
        &self,
        reference: &SecretRef,
        version: i64,
        disclosure: Disclosure,
        envelope: &Envelope,
    ) -> Result<SecretBytes, CryptoError> {
        let aad = associated_data(reference, version, disclosure);
        let mut plaintext = self.open(&aad, envelope)?;
        Ok(SecretBytes(std::mem::take(&mut *plaintext)))
    }

    pub fn seal_batch(
        &self,
        tenant: &str,
        transaction: &[u8; 16],
        actor: &str,
        batch: &[u8],
    ) -> Result<Envelope, CryptoError> {
        self.seal(&batch_associated_data(tenant, transaction, actor), batch)
    }

    pub fn open_batch(
        &self,
        tenant: &str,
        transaction: &[u8; 16],
        actor: &str,
        envelope: &Envelope,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.open(&batch_associated_data(tenant, transaction, actor), envelope)
    }

    pub fn reseal_batch(
        &self,
        tenant: &str,
        transaction: &[u8; 16],
        actor: &str,
        envelope: &Envelope,
    ) -> Result<Envelope, CryptoError> {
        let aad = batch_associated_data(tenant, transaction, actor);
        let batch = self.open(&aad, envelope)?;
        self.seal(&aad, &batch)
    }

    pub fn active_key_id(&self) -> &str {
        &self.active
    }

    pub fn key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Envelope, CryptoError> {
        let key = self
            .keys
            .get(&self.active)
            .ok_or(CryptoError::KeyNotFound)?;
        let mut dek = Zeroizing::new([0_u8; 32]);
        getrandom::fill(dek.as_mut()).map_err(|_| CryptoError::Failed)?;
        let mut value_nonce = [0_u8; 12];
        let mut wrap_nonce = [0_u8; 12];
        getrandom::fill(&mut value_nonce).map_err(|_| CryptoError::Failed)?;
        getrandom::fill(&mut wrap_nonce).map_err(|_| CryptoError::Failed)?;
        let ciphertext = Aes256Gcm::new_from_slice(dek.as_ref())
            .map_err(|_| CryptoError::Failed)?
            .encrypt(
                Nonce::from_slice(&value_nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Failed)?;
        let wrapped_key = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::Failed)?
            .encrypt(
                Nonce::from_slice(&wrap_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad,
                },
            )
            .map_err(|_| CryptoError::Failed)?;
        Ok(Envelope {
            ciphertext,
            value_nonce,
            wrapped_key,
            wrap_nonce,
            key_id: self.active.clone(),
        })
    }

    fn open(&self, aad: &[u8], envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or(CryptoError::KeyNotFound)?;
        let dek = Zeroizing::new(
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::Failed)?
                .decrypt(
                    Nonce::from_slice(&envelope.wrap_nonce),
                    Payload {
                        msg: &envelope.wrapped_key,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Failed)?,
        );
        let plaintext = Aes256Gcm::new_from_slice(&dek)
            .map_err(|_| CryptoError::Failed)?
            .decrypt(
                Nonce::from_slice(&envelope.value_nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Failed)?;
        Ok(Zeroizing::new(plaintext))
    }
}

fn associated_data(reference: &SecretRef, version: i64, disclosure: Disclosure) -> Vec<u8> {
    format!(
        "secrets/v1\0{}\0{}\0{}\0{}\0{:?}",
        reference.tenant, reference.namespace, reference.key, version, disclosure
    )
    .into_bytes()
}

fn batch_associated_data(tenant: &str, transaction: &[u8; 16], actor: &str) -> Vec<u8> {
    let mut aad = b"secrets/prepared-batch/v1\0".to_vec();
    aad.extend_from_slice(&(tenant.len() as u64).to_be_bytes());
    aad.extend_from_slice(tenant.as_bytes());
    aad.extend_from_slice(transaction);
    aad.extend_from_slice(&(actor.len() as u64).to_be_bytes());
    aad.extend_from_slice(actor.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    fn ring() -> Keyring {
        Keyring {
            active: "v1".into(),
            keys: BTreeMap::from([("v1".into(), [7; 32])]),
        }
    }
    fn reference() -> SecretRef {
        SecretRef {
            tenant: "t".into(),
            namespace: "connectors".into(),
            key: "credential".into(),
        }
    }
    #[test]
    fn round_trip_and_tamper_refusal() {
        let encrypted = ring()
            .encrypt(
                &reference(),
                1,
                Disclosure::WorkloadOnly,
                &SecretBytes(b"token".to_vec()),
            )
            .unwrap();
        assert_eq!(
            ring()
                .decrypt(&reference(), 1, Disclosure::WorkloadOnly, &encrypted)
                .unwrap()
                .0,
            b"token"
        );
        let mut tampered = encrypted.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(
            ring()
                .decrypt(&reference(), 1, Disclosure::WorkloadOnly, &tampered)
                .is_err()
        );
        let mut wrong = reference();
        wrong.tenant = "other".into();
        assert!(
            ring()
                .decrypt(&wrong, 1, Disclosure::WorkloadOnly, &encrypted)
                .is_err()
        );
    }

    const ID: [u8; 16] = [3; 16];

    #[test]
    fn sealed_batch_opens_only_under_its_tenant_transaction_and_actor() {
        let sealed = ring().seal_batch("t", &ID, "workload:a", b"batch").unwrap();
        assert_eq!(sealed.key_id, "v1");
        assert!(!sealed.ciphertext.windows(5).any(|w| w == b"batch"));
        assert_eq!(
            ring()
                .open_batch("t", &ID, "workload:a", &sealed)
                .unwrap()
                .as_slice(),
            b"batch"
        );
        assert!(ring().open_batch("u", &ID, "workload:a", &sealed).is_err());
        assert!(
            ring()
                .open_batch("t", &[4; 16], "workload:a", &sealed)
                .is_err()
        );
        assert!(ring().open_batch("t", &ID, "workload:b", &sealed).is_err());
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(
            ring()
                .open_batch("t", &ID, "workload:a", &tampered)
                .is_err()
        );
    }

    #[test]
    fn batch_associated_data_is_separated_from_secret_versions() {
        let version = associated_data(&reference(), 1, Disclosure::WorkloadOnly);
        let batch = batch_associated_data("t", &ID, "workload:a");
        assert!(version.starts_with(b"secrets/v1\0"));
        assert!(!batch.starts_with(b"secrets/v1\0"));
        let encrypted = ring()
            .encrypt(
                &reference(),
                1,
                Disclosure::WorkloadOnly,
                &SecretBytes(b"token".to_vec()),
            )
            .unwrap();
        assert!(
            ring()
                .open_batch("t", &ID, "workload:a", &encrypted)
                .is_err()
        );
        assert_ne!(
            batch_associated_data("a", &ID, "bc"),
            batch_associated_data("ab", &ID, "c")
        );
    }

    #[test]
    fn resealed_batch_is_held_under_the_active_key() {
        let sealed = ring().seal_batch("t", &ID, "workload:a", b"batch").unwrap();
        let rotated = Keyring {
            active: "v2".into(),
            keys: BTreeMap::from([("v1".into(), [7; 32]), ("v2".into(), [8; 32])]),
        };
        let resealed = rotated
            .reseal_batch("t", &ID, "workload:a", &sealed)
            .unwrap();
        assert_eq!(resealed.key_id, "v2");
        let only_new = Keyring {
            active: "v2".into(),
            keys: BTreeMap::from([("v2".into(), [8; 32])]),
        };
        assert_eq!(
            only_new
                .open_batch("t", &ID, "workload:a", &resealed)
                .unwrap()
                .as_slice(),
            b"batch"
        );
        assert!(
            rotated
                .reseal_batch("t", &ID, "workload:b", &sealed)
                .is_err()
        );
    }
}
