//! The keychain backend over a fresh `keyring_core::mock::Store` per test, passed to the
//! constructor; the process-wide default store is never set.
//!
//! Each test names the story:keychain-backend scenario it guards in its doc line.
#![allow(clippy::unwrap_used)]

use std::{collections::HashMap, sync::Arc};

use keyring_core::{CredentialStore, api::CredentialStoreApi, mock};
use secrets_core::storage::{
    Address, Capability, Scope, SecretMetadata, SecretName, SecretStorage, SecretValue,
    StorageError, Target, Version, Written,
};
use secrets_keychain::{DEFAULT_SERVICE, KeychainBackend, entry_user};

const MARKER: &str = "backend-text-marker";

fn fresh() -> (Arc<mock::Store>, KeychainBackend) {
    let store = mock::Store::new().unwrap();
    let backend = KeychainBackend::new(store.clone() as Arc<CredentialStore>);
    (store, backend)
}

fn address(tenant: &str, namespace: &str, user: &str, name: &str) -> Address {
    Address::parse(tenant, namespace, user, name).unwrap()
}

fn target(address: &Address) -> Target {
    Target::unbound(address.clone())
}

fn value(bytes: &[u8]) -> SecretValue {
    SecretValue::new(bytes.to_vec()).unwrap()
}

fn version(written: Written) -> Version {
    match written {
        Written::Created(version) | Written::Replaced(version) => version.unwrap(),
    }
}

async fn read(backend: &KeychainBackend, address: &Address) -> Result<Vec<u8>, StorageError> {
    backend
        .read(&target(address))
        .await
        .map(|revealed| revealed.value.expose().to_vec())
}

async fn names(backend: &KeychainBackend, scope: &Scope) -> Vec<String> {
    backend
        .list(scope)
        .await
        .unwrap()
        .into_iter()
        .map(|listed| listed.address.name.to_string())
        .collect()
}

/// Arms the mock entry behind `address` to fail its next call with `error`.
fn fail_next(store: &mock::Store, address: &Address, error: keyring_core::Error) {
    let entry = store
        .build(DEFAULT_SERVICE, &entry_user(address), None)
        .unwrap();
    let cred: &mock::Cred = entry.as_any().downcast_ref().unwrap();
    cred.set_error(error);
}

fn platform_failure() -> keyring_core::Error {
    keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(MARKER)))
}

fn no_backend_text(error: StorageError) {
    assert_eq!(error, StorageError::Unavailable);
    assert!(!format!("{error} {error:?} {error:#?}").contains(MARKER));
}

/// read, write, delete and list round trips: a written value reads back with the version the
/// write returned, and is listed under it.
#[tokio::test(flavor = "multi_thread")]
async fn a_written_value_reads_back_and_is_listed_with_its_version() {
    let (_store, backend) = fresh();
    assert_eq!(backend.capabilities(), &Capability::ALL);
    let openai = address("default", "default", "default", "team/openai");

    let written = backend
        .write(&target(&openai), value(b"sk-1"))
        .await
        .unwrap();
    let Written::Created(Some(created)) = written else {
        panic!("a first write creates");
    };
    let revealed = backend.read(&target(&openai)).await.unwrap();
    assert_eq!(revealed.value.expose(), b"sk-1");
    assert_eq!(revealed.version.as_ref(), Some(&created));
    assert_eq!(
        backend.list(&openai.scope).await.unwrap(),
        vec![SecretMetadata {
            address: openai.clone(),
            version: Some(created),
        }]
    );
}

/// read, write, delete and list round trips: empty and binary values are values.
#[tokio::test(flavor = "multi_thread")]
async fn empty_and_binary_values_round_trip() {
    let (_store, backend) = fresh();
    let empty = address("default", "default", "default", "empty");
    let binary = address("default", "default", "default", "binary");
    let bytes: Vec<u8> = (0..=255).collect();
    backend.write(&target(&empty), value(b"")).await.unwrap();
    backend
        .write(&target(&binary), value(&bytes))
        .await
        .unwrap();
    assert_eq!(read(&backend, &empty).await.unwrap(), b"");
    assert_eq!(read(&backend, &binary).await.unwrap(), bytes);
}

/// read, write, delete and list round trips: every write changes the version, rewriting the same
/// value included, and a rewrite replaces.
#[tokio::test(flavor = "multi_thread")]
async fn every_write_changes_the_version_even_for_the_same_value() {
    let (_store, backend) = fresh();
    let openai = address("default", "default", "default", "openai");
    let first = backend
        .write(&target(&openai), value(b"same"))
        .await
        .unwrap();
    assert!(matches!(first, Written::Created(Some(_))));
    let second = backend
        .write(&target(&openai), value(b"same"))
        .await
        .unwrap();
    assert!(matches!(second, Written::Replaced(Some(_))));
    let third = backend
        .write(&target(&openai), value(b"other"))
        .await
        .unwrap();
    let (first, second, third) = (version(first), version(second), version(third));
    assert_ne!(first, second);
    assert_ne!(second, third);
    assert_ne!(first, third);
    let revealed = backend.read(&target(&openai)).await.unwrap();
    assert_eq!(revealed.value.expose(), b"other");
    assert_eq!(revealed.version, Some(third));
}

/// read, write, delete and list round trips: a deleted name reads as not-found, deletes as
/// not-found, and is no longer listed, although the keychain search still returns its entry.
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_name_is_gone_and_no_longer_listed() {
    let (store, backend) = fresh();
    let scope = Scope::local();
    let kept = address("default", "default", "default", "kept");
    let gone = address("default", "default", "default", "gone");
    backend.write(&target(&kept), value(b"1")).await.unwrap();
    backend.write(&target(&gone), value(b"2")).await.unwrap();
    assert_eq!(names(&backend, &scope).await, ["gone", "kept"]);

    backend.delete(&target(&gone)).await.unwrap();
    assert_eq!(read(&backend, &gone).await, Err(StorageError::NotFound));
    assert_eq!(
        backend.delete(&target(&gone)).await,
        Err(StorageError::NotFound)
    );
    assert_eq!(names(&backend, &scope).await, ["kept"]);
    assert_eq!(read(&backend, &kept).await.unwrap(), b"1");

    // The safety fact the listing guards against: the store still answers the deleted entry.
    let spec = HashMap::from([("service", DEFAULT_SERVICE)]);
    assert_eq!(store.search(&spec).unwrap().len(), 2);
}

/// read, write, delete and list round trips: a name never written reads and deletes as
/// not-found, and an empty scope lists nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_never_written_is_not_found() {
    let (_store, backend) = fresh();
    let missing = address("default", "default", "default", "missing");
    assert_eq!(read(&backend, &missing).await, Err(StorageError::NotFound));
    assert_eq!(
        backend.delete(&target(&missing)).await,
        Err(StorageError::NotFound)
    );
    assert_eq!(backend.list(&Scope::local()).await.unwrap(), vec![]);
}

/// read, write, delete and list round trips: a rename moves the value and its version to the new
/// name, refuses a taken name as conflict and a missing one as not-found.
#[tokio::test(flavor = "multi_thread")]
async fn a_rename_moves_the_value_within_its_scope() {
    let (_store, backend) = fresh();
    let old = address("default", "default", "default", "openai");
    let new_name = SecretName::parse("openai-work").unwrap();
    let new = address("default", "default", "default", "openai-work");
    let written = version(backend.write(&target(&old), value(b"v")).await.unwrap());

    backend.rename(&target(&old), &new_name).await.unwrap();
    assert_eq!(read(&backend, &old).await, Err(StorageError::NotFound));
    let revealed = backend.read(&target(&new)).await.unwrap();
    assert_eq!(revealed.value.expose(), b"v");
    assert_eq!(revealed.version, Some(written));
    assert_eq!(names(&backend, &Scope::local()).await, ["openai-work"]);

    assert_eq!(
        backend.rename(&target(&old), &new_name).await,
        Err(StorageError::NotFound)
    );
    backend.write(&target(&old), value(b"w")).await.unwrap();
    assert_eq!(
        backend.rename(&target(&old), &new_name).await,
        Err(StorageError::Conflict)
    );
    assert_eq!(read(&backend, &old).await.unwrap(), b"w");
    assert_eq!(read(&backend, &new).await.unwrap(), b"v");
}

/// two tenants, two namespaces and two users holding the same name stay separate.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_name_in_different_scopes_stays_separate() {
    let (_store, backend) = fresh();
    let scopes = [
        address("t1", "ns1", "u1", "openai"),
        address("t2", "ns1", "u1", "openai"),
        address("t1", "ns2", "u1", "openai"),
        address("t1", "ns1", "u2", "openai"),
    ];
    for (index, at) in scopes.iter().enumerate() {
        let bytes = [u8::try_from(index).unwrap()];
        backend.write(&target(at), value(&bytes)).await.unwrap();
    }
    for (index, at) in scopes.iter().enumerate() {
        assert_eq!(
            read(&backend, at).await.unwrap(),
            [u8::try_from(index).unwrap()]
        );
        let listed = backend.list(&at.scope).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].address, *at);
    }

    backend.delete(&target(&scopes[0])).await.unwrap();
    assert_eq!(
        read(&backend, &scopes[0]).await,
        Err(StorageError::NotFound)
    );
    for (index, at) in scopes.iter().enumerate().skip(1) {
        assert_eq!(
            read(&backend, at).await.unwrap(),
            [u8::try_from(index).unwrap()]
        );
    }
}

/// two tenants, two namespaces and two users holding the same name stay separate: a scope whose
/// name is a prefix of another's lists none of the other's names, although the keychain search
/// matches by substring.
#[tokio::test(flavor = "multi_thread")]
async fn a_scope_lists_nothing_of_a_scope_whose_name_extends_its_own() {
    let (_store, backend) = fresh();
    let short = address("a", "n", "u", "mine");
    for other in [
        address("ab", "n", "u", "theirs"),
        address("ba", "n", "u", "theirs"),
        address("a", "nb", "u", "theirs"),
        address("a", "n", "ub", "theirs"),
        address("a", "n", "u-b", "theirs"),
    ] {
        backend.write(&target(&other), value(b"x")).await.unwrap();
    }
    backend.write(&target(&short), value(b"y")).await.unwrap();
    assert_eq!(names(&backend, &short.scope).await, ["mine"]);
}

/// two tenants, two namespaces and two users holding the same name stay separate: two backends
/// under different services share nothing, even over one store and with one service a prefix of
/// the other.
#[tokio::test(flavor = "multi_thread")]
async fn two_services_over_one_store_share_nothing() {
    let store = mock::Store::new().unwrap();
    let first = KeychainBackend::with_service(store.clone() as Arc<CredentialStore>, "svc");
    let second = KeychainBackend::with_service(store as Arc<CredentialStore>, "svc-two");
    let openai = address("default", "default", "default", "openai");
    second.write(&target(&openai), value(b"2")).await.unwrap();
    assert_eq!(read(&first, &openai).await, Err(StorageError::NotFound));
    assert_eq!(first.list(&Scope::local()).await.unwrap(), vec![]);
    first.write(&target(&openai), value(b"1")).await.unwrap();
    assert_eq!(read(&second, &openai).await.unwrap(), b"2");
}

/// a backend fault surfaces as `unavailable` with no backend text: on every operation, and the
/// value held before the fault is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_backend_fault_is_unavailable_with_no_backend_text() {
    let (store, backend) = fresh();
    let openai = address("default", "default", "default", "openai");
    backend
        .write(&target(&openai), value(b"held"))
        .await
        .unwrap();

    fail_next(&store, &openai, platform_failure());
    no_backend_text(read(&backend, &openai).await.unwrap_err());

    fail_next(&store, &openai, platform_failure());
    no_backend_text(
        backend
            .write(&target(&openai), value(b"new"))
            .await
            .unwrap_err(),
    );

    fail_next(&store, &openai, platform_failure());
    no_backend_text(backend.delete(&target(&openai)).await.unwrap_err());

    fail_next(&store, &openai, platform_failure());
    no_backend_text(backend.list(&Scope::local()).await.unwrap_err());

    fail_next(&store, &openai, platform_failure());
    let new_name = SecretName::parse("openai-work").unwrap();
    no_backend_text(
        backend
            .rename(&target(&openai), &new_name)
            .await
            .unwrap_err(),
    );

    assert_eq!(read(&backend, &openai).await.unwrap(), b"held");
}

/// a backend fault surfaces as `unavailable` with no backend text: every keychain error other than
/// a missing entry, a locked store included.
#[tokio::test(flavor = "multi_thread")]
async fn every_keychain_error_but_a_missing_entry_is_unavailable() {
    let (store, backend) = fresh();
    let openai = address("default", "default", "default", "openai");
    for error in [
        keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other(MARKER))),
        keyring_core::Error::BadEncoding(MARKER.as_bytes().to_vec()),
        keyring_core::Error::BadStoreFormat(MARKER.into()),
        keyring_core::Error::TooLong(MARKER.into(), 1),
        keyring_core::Error::Invalid(MARKER.into(), MARKER.into()),
        keyring_core::Error::NotSupportedByStore(MARKER.into()),
    ] {
        fail_next(&store, &openai, error);
        no_backend_text(read(&backend, &openai).await.unwrap_err());
    }
    assert_eq!(read(&backend, &openai).await, Err(StorageError::NotFound));
}
