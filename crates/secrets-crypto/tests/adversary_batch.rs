#![allow(clippy::unwrap_used)]

use secrets_core::{Disclosure, SecretBytes, SecretRef};
use secrets_crypto::Keyring;

fn ring() -> Keyring {
    Keyring::from_json(
        br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#,
    )
    .unwrap()
}

/// The reverse of the unit's own separation test: a sealed batch must not open as a secret
/// version, whatever reference, version or disclosure the caller names.
#[test]
fn sealed_batch_never_opens_as_a_secret_version() {
    let sealed = ring().seal_batch("t", &[3; 16], "a", b"batch").unwrap();
    for (namespace, key) in [("", ""), ("a", ""), ("prepared-batch", "v1")] {
        for version in [0, 1, -1] {
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

/// Two seals of the same batch under the same binding never share a data key or a nonce.
#[test]
fn sealing_the_same_batch_twice_reuses_no_nonce() {
    let first = ring().seal_batch("t", &[3; 16], "a", b"batch").unwrap();
    let second = ring().seal_batch("t", &[3; 16], "a", b"batch").unwrap();
    assert_ne!(first.value_nonce, second.value_nonce);
    assert_ne!(first.wrap_nonce, second.wrap_nonce);
    assert_ne!(first.wrapped_key, second.wrapped_key);
    assert_ne!(first.ciphertext, second.ciphertext);
    let secret = ring()
        .encrypt(
            &SecretRef {
                tenant: "t".into(),
                namespace: "n".into(),
                key: "k".into(),
            },
            1,
            Disclosure::WorkloadOnly,
            &SecretBytes(b"batch".to_vec()),
        )
        .unwrap();
    assert_ne!(secret.value_nonce, first.value_nonce);
}
