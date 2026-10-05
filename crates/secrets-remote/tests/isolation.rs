//! Story scenario: "two tenants and two users holding the same name stay separate".
//!
//! User isolation does not rest on custody: custody's put upserts on `(tenant, namespace, key)` and
//! overwrites the owner, and workload get and list check no owner. It rests on the key carrying the
//! user, and on reads and listings keeping only keys under the user's prefix.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use secrets_core::{
    Disclosure, PutSecret, SecretBytes, SecretRef,
    storage::{SecretStorage, StorageError},
};
use std::collections::BTreeMap;
use support::{Service, target, tenant, value};

#[tokio::test]
async fn two_users_holding_the_same_name_stay_separate() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    let alice = target(&tenant, "default", "alice", "openai");
    let bob = target(&tenant, "default", "bob", "openai");

    backend.write(&alice, value(b"alice's")).await.unwrap();
    backend.write(&bob, value(b"bob's")).await.unwrap();
    assert_eq!(
        backend.read(&alice).await.unwrap().value.expose(),
        b"alice's"
    );
    assert_eq!(backend.read(&bob).await.unwrap().value.expose(), b"bob's");

    let mut owners: Vec<(String, String)> = service
        .client(&tenant)
        .references(&tenant, "default")
        .await
        .unwrap()
        .into_iter()
        .map(|m| (m.reference.key, m.owner_subject))
        .collect();
    owners.sort();
    assert_eq!(
        owners,
        [
            ("alice/openai".to_owned(), "alice".to_owned()),
            ("bob/openai".to_owned(), "bob".to_owned())
        ]
    );

    let listed = backend.list(&alice.address.scope).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, alice.address);

    backend.delete(&alice).await.unwrap();
    assert_eq!(
        backend.read(&alice).await.err(),
        Some(StorageError::NotFound)
    );
    assert_eq!(backend.read(&bob).await.unwrap().value.expose(), b"bob's");
    assert!(backend.list(&alice.address.scope).await.unwrap().is_empty());
    assert_eq!(backend.list(&bob.address.scope).await.unwrap().len(), 1);
    service.close().await;
}

#[tokio::test]
async fn a_listing_keeps_only_keys_under_the_user_s_prefix() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    let custody = service.client(&tenant);
    // Records the namespace holds that are not alice's: an unprefixed key, another user's, a
    // prefix that only starts with hers, and a remainder that is not a name.
    for key in [
        "openai",
        "carol/openai",
        "alicex/openai",
        "alice/Not-A-Name",
    ] {
        custody
            .put(&PutSecret {
                reference: SecretRef {
                    tenant: tenant.clone(),
                    namespace: "default".into(),
                    key: key.into(),
                },
                owner_subject: "someone".into(),
                value: SecretBytes(b"foreign".to_vec()),
                disclosure: Disclosure::WorkloadOnly,
                labels: BTreeMap::new(),
            })
            .await
            .unwrap();
    }
    let alice = target(&tenant, "default", "alice", "openai");
    assert!(backend.list(&alice.address.scope).await.unwrap().is_empty());
    assert_eq!(
        backend.read(&alice).await.err(),
        Some(StorageError::NotFound)
    );
    backend.write(&alice, value(b"alice's")).await.unwrap();
    let listed = backend.list(&alice.address.scope).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, alice.address);
    assert_eq!(
        custody.references(&tenant, "default").await.unwrap().len(),
        5,
        "no foreign record was touched"
    );
    service.close().await;
}

#[tokio::test]
async fn two_tenants_holding_the_same_name_stay_separate() {
    let Some(service) = Service::start().await else {
        return;
    };
    let (first, second) = (tenant(), tenant());
    let first_backend = service.backend(&first);
    let second_backend = service.backend(&second);
    let in_first = target(&first, "default", "default", "openai");
    let in_second = target(&second, "default", "default", "openai");

    first_backend
        .write(&in_first, value(b"first"))
        .await
        .unwrap();
    second_backend
        .write(&in_second, value(b"second"))
        .await
        .unwrap();
    assert_eq!(
        first_backend.read(&in_first).await.unwrap().value.expose(),
        b"first"
    );
    assert_eq!(
        second_backend
            .read(&in_second)
            .await
            .unwrap()
            .value
            .expose(),
        b"second"
    );
    assert_eq!(
        first_backend
            .list(&in_first.address.scope)
            .await
            .unwrap()
            .len(),
        1
    );

    // A backend holding one tenant's token is refused the other tenant: `Refused` is `denied`.
    assert_eq!(
        first_backend.read(&in_second).await.err(),
        Some(StorageError::Denied)
    );
    assert_eq!(
        first_backend.write(&in_second, value(b"taken")).await.err(),
        Some(StorageError::Denied)
    );
    assert_eq!(
        first_backend.delete(&in_second).await.err(),
        Some(StorageError::Denied)
    );
    assert_eq!(
        first_backend.list(&in_second.address.scope).await.err(),
        Some(StorageError::Denied)
    );
    assert_eq!(
        second_backend
            .read(&in_second)
            .await
            .unwrap()
            .value
            .expose(),
        b"second"
    );

    first_backend.delete(&in_first).await.unwrap();
    assert_eq!(
        second_backend
            .read(&in_second)
            .await
            .unwrap()
            .value
            .expose(),
        b"second"
    );
    service.close().await;
}

#[tokio::test]
async fn an_unknown_token_is_denied() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = support::backend_at(&service.origin, "never-registered");
    let address = target(&tenant, "default", "default", "openai");
    assert_eq!(
        backend.read(&address).await.err(),
        Some(StorageError::Denied)
    );
    assert_eq!(
        backend.write(&address, value(b"x")).await.err(),
        Some(StorageError::Denied)
    );
    service.close().await;
}
