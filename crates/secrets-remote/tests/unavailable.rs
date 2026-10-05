//! Story scenario: "a service failure surfaces as `unavailable` with no response text".
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use secrets_core::storage::{SecretName, SecretStorage, StorageError};
use secrets_remote::RemoteBackend;
use support::{Service, backend_at, closed_origin, stub, target, tenant, value};

const MARKER: &str = "leak-marker-from-the-service";

/// Every command of the port, each answering the error it got, with nothing more than its code.
async fn every_command(backend: &RemoteBackend, tenant: &str) -> Vec<StorageError> {
    let at = target(tenant, "default", "default", "openai");
    let new_name = SecretName::parse("openai-work").unwrap();
    let errors = vec![
        backend.read(&at).await.err(),
        backend.write(&at, value(b"value")).await.err(),
        backend.delete(&at).await.err(),
        backend.rename(&at, &new_name).await.err(),
        backend.list(&at.address.scope).await.err(),
    ];
    errors
        .into_iter()
        .map(|error| error.expect("every command failed"))
        .collect()
}

fn assert_unavailable_without_text(errors: &[StorageError]) {
    for error in errors {
        assert_eq!(*error, StorageError::Unavailable);
        let shown = format!("{error} {error:?} {error:#?}");
        assert_eq!(shown, "unavailable Unavailable Unavailable");
        assert!(!shown.contains(MARKER));
    }
}

#[tokio::test]
async fn a_service_nobody_answers_for_is_unavailable() {
    let backend = backend_at(&closed_origin().await, "token");
    assert_unavailable_without_text(&every_command(&backend, "default").await);
}

#[tokio::test]
async fn a_5xx_answer_is_unavailable_and_repeats_none_of_its_body() {
    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (origin, server) = stub(status, MARKER).await;
        let backend = backend_at(&origin, "token");
        assert_unavailable_without_text(&every_command(&backend, "default").await);
        server.abort();
    }
}

#[tokio::test]
async fn an_unreadable_success_body_is_unavailable() {
    let (origin, server) = stub(StatusCode::OK, MARKER).await;
    let backend = backend_at(&origin, "token");
    let at = target("default", "default", "default", "openai");
    for error in [
        backend.read(&at).await.err(),
        backend.write(&at, value(b"value")).await.err(),
        backend.list(&at.address.scope).await.err(),
    ] {
        assert_unavailable_without_text(&[error.expect("refused")]);
    }
    server.abort();
}

#[tokio::test]
async fn a_404_answer_is_not_found() {
    let (origin, server) = stub(StatusCode::NOT_FOUND, MARKER).await;
    let backend = backend_at(&origin, "token");
    let at = target("default", "default", "default", "openai");
    assert_eq!(backend.read(&at).await.err(), Some(StorageError::NotFound));
    assert_eq!(
        backend.delete(&at).await.err(),
        Some(StorageError::NotFound)
    );
    server.abort();
}

#[tokio::test]
async fn a_lost_custody_database_is_unavailable() {
    let Some(service) = Service::start().await else {
        return;
    };
    let tenant = tenant();
    let backend = service.backend(&tenant);
    backend
        .write(
            &target(&tenant, "default", "default", "openai"),
            value(b"held"),
        )
        .await
        .unwrap();
    service.take_down().await;
    assert_unavailable_without_text(&every_command(&backend, &tenant).await);
    service.close().await;
}
