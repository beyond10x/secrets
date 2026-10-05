//! Story scenario: "read, write, delete and list round trips through `secrets-client`".
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use secrets_core::storage::{
    Capability, SecretName, SecretStorage, StorageError, Target, Version, Written,
};
use secrets_remote::max_value_bytes;
use support::{Service, address, target, tenant, value};

fn version(written: Written) -> Version {
    match written {
        Written::Created(Some(version)) | Written::Replaced(Some(version)) => version,
        _ => panic!("a remote write always reports a version"),
    }
}

#[tokio::test]
async fn write_read_list_and_delete_round_trip() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    assert_eq!(backend.capabilities(), &Capability::ALL);
    let openai = target(&tenant, "default", "default", "openai");
    let team = target(&tenant, "default", "default", "team/openai");

    let created = backend.write(&openai, value(b"first")).await.unwrap();
    assert!(matches!(created, Written::Created(Some(_))), "{created:?}");
    let first = version(created);
    let read = backend.read(&openai).await.unwrap();
    assert_eq!(read.value.expose(), b"first");
    assert_eq!(read.version.as_ref(), Some(&first));

    let replaced = backend.write(&openai, value(b"second")).await.unwrap();
    assert!(
        matches!(replaced, Written::Replaced(Some(_))),
        "{replaced:?}"
    );
    let second = version(replaced);
    assert_ne!(first, second, "every successful write changes the version");
    let read = backend.read(&openai).await.unwrap();
    assert_eq!(read.value.expose(), b"second");
    assert_eq!(read.version.as_ref(), Some(&second));

    // Binary and empty values are values.
    backend
        .write(&team, value(&[0, 159, 255, 10]))
        .await
        .unwrap();
    assert_eq!(
        backend.read(&team).await.unwrap().value.expose(),
        &[0, 159, 255, 10]
    );
    let empty = target(&tenant, "default", "default", "empty");
    backend.write(&empty, value(b"")).await.unwrap();
    assert!(backend.read(&empty).await.unwrap().value.is_empty());

    let listed = backend.list(&openai.address.scope).await.unwrap();
    let names: Vec<&str> = listed.iter().map(|m| m.address.name.as_str()).collect();
    assert_eq!(names, ["empty", "openai", "team/openai"]);
    assert_eq!(listed[1].address, openai.address);
    assert_eq!(listed[1].version.as_ref(), Some(&second));

    backend.delete(&openai).await.unwrap();
    assert_eq!(
        backend.read(&openai).await.err(),
        Some(StorageError::NotFound)
    );
    assert_eq!(
        backend.delete(&openai).await.err(),
        Some(StorageError::NotFound)
    );
    let names: Vec<SecretName> = backend
        .list(&openai.address.scope)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.address.name)
        .collect();
    assert_eq!(
        names,
        [
            SecretName::parse("empty").unwrap(),
            SecretName::parse("team/openai").unwrap()
        ]
    );

    // A name written again after a delete is created, under a version it never had.
    let again = backend.write(&openai, value(b"third")).await.unwrap();
    assert!(matches!(again, Written::Created(Some(_))), "{again:?}");
    let third = version(again);
    assert_ne!(third, first);
    service.close().await;
}

#[tokio::test]
async fn an_empty_scope_lists_nothing_and_a_missing_name_is_not_found() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    let missing = target(&tenant, "work", "default", "missing");
    assert!(
        backend
            .list(&missing.address.scope)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        backend.read(&missing).await.err(),
        Some(StorageError::NotFound)
    );
    service.close().await;
}

#[tokio::test]
async fn rename_moves_the_value_and_refuses_a_taken_or_missing_name() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    let from = target(&tenant, "default", "default", "openai");
    let work = SecretName::parse("openai-work").unwrap();
    backend.write(&from, value(b"moved")).await.unwrap();

    backend.rename(&from, &work).await.unwrap();
    assert_eq!(
        backend.read(&from).await.err(),
        Some(StorageError::NotFound)
    );
    let moved = target(&tenant, "default", "default", "openai-work");
    assert_eq!(backend.read(&moved).await.unwrap().value.expose(), b"moved");
    let names: Vec<String> = backend
        .list(&from.address.scope)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.address.name.to_string())
        .collect();
    assert_eq!(names, ["openai-work"]);

    assert_eq!(
        backend.rename(&from, &work).await.err(),
        Some(StorageError::NotFound)
    );
    backend.write(&from, value(b"other")).await.unwrap();
    assert_eq!(
        backend.rename(&from, &work).await.err(),
        Some(StorageError::Conflict)
    );
    assert_eq!(backend.read(&moved).await.unwrap().value.expose(), b"moved");
    assert_eq!(backend.read(&from).await.unwrap().value.expose(), b"other");
    service.close().await;
}

#[tokio::test]
async fn the_largest_value_the_service_takes_round_trips_and_one_byte_more_is_too_large() {
    let max = max_value_bytes();
    // Refused before any request: an origin nothing listens on would answer `unavailable`.
    let offline = support::backend_at(&support::closed_origin().await, "unused");
    let over = target("default", "default", "default", "big");
    assert_eq!(
        offline.write(&over, value(&vec![7; max + 1])).await.err(),
        Some(StorageError::TooLarge)
    );

    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    // Namespace, user and both names as long as the grammar allows.
    let longest = |fill: &str| format!("{}/{}", fill.repeat(64), fill.repeat(63));
    let (namespace, user) = ("n".repeat(64), "u".repeat(64));
    let at = target(&tenant, &namespace, &user, &longest("a"));
    backend.write(&at, value(&vec![7; max])).await.unwrap();
    assert_eq!(backend.read(&at).await.unwrap().value.len(), max);
    let new_name = SecretName::parse(&longest("b")).unwrap();
    backend.rename(&at, &new_name).await.unwrap();
    let renamed = Target::unbound(address(&tenant, &namespace, &user, &longest("b")));
    assert_eq!(backend.read(&renamed).await.unwrap().value.len(), max);
    service.close().await;
}
