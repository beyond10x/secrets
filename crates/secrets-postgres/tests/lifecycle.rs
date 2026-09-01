#![allow(clippy::unwrap_used)]

use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretBytes, SecretRef, SecretState, SecretStore, StoreError,
};
use secrets_crypto::Keyring;
use secrets_postgres::PostgresStore;
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

#[tokio::test]
async fn postgres_lifecycle_and_atomic_batch() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let keyring = Keyring::from_json(
        br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}}"#,
    )
    .unwrap();
    let store = PostgresStore::connect(&database_url, Arc::new(keyring))
        .await
        .unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let first = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "one".into(),
    };
    let second = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "two".into(),
    };
    let put = |reference: SecretRef, value: &[u8]| PutSecret {
        reference,
        owner_subject: "user:one".into(),
        value: SecretBytes(value.to_vec()),
        disclosure: Disclosure::WorkloadOnly,
        labels: BTreeMap::new(),
    };

    let metadata = store.put(put(first.clone(), b"alpha")).await.unwrap();
    assert_eq!(metadata.version, 1);
    assert_eq!(store.get(&first).await.unwrap().value.0, b"alpha");
    assert_eq!(
        store.revoke(&first, "user:one").await.unwrap().state,
        SecretState::Revoked
    );
    assert!(matches!(store.get(&first).await, Err(StoreError::NotFound)));

    let transaction = Uuid::now_v7();
    store
        .prepare(
            &tenant,
            transaction,
            vec![
                Mutation::Delete {
                    reference: first.clone(),
                },
                Mutation::Put {
                    secret: put(second.clone(), b"beta"),
                },
            ],
            "workload:test",
        )
        .await
        .unwrap();
    assert!(!store.exists(&second).await.unwrap());
    store.commit(&tenant, transaction).await.unwrap();
    assert!(!store.exists(&first).await.unwrap());
    assert_eq!(store.get(&second).await.unwrap().value.0, b"beta");
    store.delete(&second, "user:one").await.unwrap();
    assert!(store.list(&tenant, None).await.unwrap().is_empty());
}
