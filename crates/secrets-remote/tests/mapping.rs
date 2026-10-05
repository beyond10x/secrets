//! Story scenario: "each address maps to custody's reference `{tenant, namespace, key = name}` with
//! the user as owner", as the coordinator's 2026-10-05 decision amends it: `key = "<user>/<name>"`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use secrets_core::{
    Disclosure, PutSecret, SecretBytes, SecretRef,
    storage::{SecretStorage, StorageError},
};
use std::collections::BTreeMap;
use support::{Service, target, tenant, value};

#[tokio::test]
async fn a_write_lands_on_the_user_prefixed_reference_with_the_user_as_owner() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    let custody = service.client(&tenant);
    backend
        .write(
            &target(&tenant, "work", "alice", "team/openai"),
            value(b"mapped"),
        )
        .await
        .unwrap();

    let expected = SecretRef {
        tenant: tenant.clone(),
        namespace: "work".into(),
        key: "alice/team/openai".into(),
    };
    let stored = custody.get(&expected).await.unwrap();
    assert_eq!(stored.value.0, b"mapped");
    assert_eq!(stored.metadata.reference, expected);
    assert_eq!(stored.metadata.owner_subject, "alice");
    let records = custody.references(&tenant, "work").await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].reference, expected);
    assert!(
        custody
            .references(&tenant, "default")
            .await
            .unwrap()
            .is_empty(),
        "the namespace is the custody namespace"
    );
    service.close().await;
}

#[tokio::test]
async fn a_custody_record_under_the_user_prefix_is_that_user_s_secret() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    let custody = service.client(&tenant);
    custody
        .put(&PutSecret {
            reference: SecretRef {
                tenant: tenant.clone(),
                namespace: "work".into(),
                key: "alice/openai".into(),
            },
            owner_subject: "alice".into(),
            value: SecretBytes(b"from custody".to_vec()),
            disclosure: Disclosure::WorkloadOnly,
            labels: BTreeMap::new(),
        })
        .await
        .unwrap();

    let alice = target(&tenant, "work", "alice", "openai");
    assert_eq!(
        backend.read(&alice).await.unwrap().value.expose(),
        b"from custody"
    );
    let listed = backend.list(&alice.address.scope).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, alice.address);
    backend.delete(&alice).await.unwrap();
    assert!(
        custody
            .references(&tenant, "work")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        backend.read(&alice).await.err(),
        Some(StorageError::NotFound)
    );
    service.close().await;
}
