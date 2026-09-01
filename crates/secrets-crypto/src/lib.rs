use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrets_core::{Disclosure, SecretBytes, SecretRef};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

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
        let aad = associated_data(reference, version, disclosure);
        let ciphertext = Aes256Gcm::new_from_slice(dek.as_ref())
            .map_err(|_| CryptoError::Failed)?
            .encrypt(
                Nonce::from_slice(&value_nonce),
                Payload {
                    msg: &value.0,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Failed)?;
        let wrapped_key = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::Failed)?
            .encrypt(
                Nonce::from_slice(&wrap_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad: &aad,
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

    pub fn decrypt(
        &self,
        reference: &SecretRef,
        version: i64,
        disclosure: Disclosure,
        envelope: &Envelope,
    ) -> Result<SecretBytes, CryptoError> {
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or(CryptoError::KeyNotFound)?;
        let aad = associated_data(reference, version, disclosure);
        let mut dek = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::Failed)?
            .decrypt(
                Nonce::from_slice(&envelope.wrap_nonce),
                Payload {
                    msg: &envelope.wrapped_key,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Failed)?;
        let plaintext = Aes256Gcm::new_from_slice(&dek)
            .map_err(|_| CryptoError::Failed)?
            .decrypt(
                Nonce::from_slice(&envelope.value_nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Failed)?;
        dek.zeroize();
        Ok(SecretBytes(plaintext))
    }

    pub fn active_key_id(&self) -> &str {
        &self.active
    }
}

fn associated_data(reference: &SecretRef, version: i64, disclosure: Disclosure) -> Vec<u8> {
    format!(
        "secrets/v1\0{}\0{}\0{}\0{}\0{:?}",
        reference.tenant, reference.namespace, reference.key, version, disclosure
    )
    .into_bytes()
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
}
