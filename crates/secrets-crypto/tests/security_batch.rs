#![allow(clippy::unwrap_used)]
//! Conformance checks of the prepared-batch envelope (`story:prepared-batch-custody`).

use secrets_core::{Disclosure, SecretBytes, SecretRef};
use secrets_crypto::Keyring;

const RING: &[u8] =
    br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#;
const ID: [u8; 16] = [9; 16];

fn ring() -> Keyring {
    Keyring::from_json(RING).unwrap()
}

/// The reverse direction of the unit's own separation test: a sealed batch must not open as any
/// secret version, including references built from the batch's own tenant and actor.
#[test]
fn sealed_batch_does_not_open_as_a_secret_version() {
    let sealed = ring().seal_batch("t", &ID, "workload:a", b"batch").unwrap();
    for (namespace, key) in [("workload:a", "x"), ("prepared-batch", "v1"), ("", "")] {
        for version in [0, 1, i64::MAX] {
            for disclosure in [Disclosure::WorkloadOnly, Disclosure::UserRevealable] {
                let reference = SecretRef {
                    tenant: "t".into(),
                    namespace: namespace.into(),
                    key: key.into(),
                };
                assert!(
                    ring()
                        .decrypt(&reference, version, disclosure, &sealed)
                        .is_err()
                );
            }
        }
    }
}

/// Every seal draws a fresh data key and fresh nonces, so two seals of the same batch under the
/// same binding share neither.
#[test]
fn two_seals_of_one_batch_share_no_nonce_or_data_key() {
    let a = ring().seal_batch("t", &ID, "workload:a", b"batch").unwrap();
    let b = ring().seal_batch("t", &ID, "workload:a", b"batch").unwrap();
    assert_ne!(a.value_nonce, b.value_nonce);
    assert_ne!(a.wrap_nonce, b.wrap_nonce);
    assert_ne!(a.wrapped_key, b.wrapped_key);
    assert_ne!(a.ciphertext, b.ciphertext);
    let resealed = ring().reseal_batch("t", &ID, "workload:a", &a).unwrap();
    assert_ne!(resealed.value_nonce, a.value_nonce);
    assert_ne!(resealed.wrapped_key, a.wrapped_key);
}

/// A secret version's envelope must not open as a batch whose tenant string mimics the version's
/// associated-data layout.
#[test]
fn secret_version_does_not_open_as_a_batch_with_a_mimicking_tenant() {
    let reference = SecretRef {
        tenant: "t".into(),
        namespace: "n".into(),
        key: "k".into(),
    };
    let version = ring()
        .encrypt(
            &reference,
            1,
            Disclosure::WorkloadOnly,
            &SecretBytes(b"token".to_vec()),
        )
        .unwrap();
    for tenant in ["t", "t\0n\0k\x001\0WorkloadOnly", "secrets/v1\0t"] {
        assert!(ring().open_batch(tenant, &ID, "", &version).is_err());
    }
}
