//! `FileConfig` over a real file under `CARGO_TARGET_TMPDIR`: what it keeps, how it writes and
//! what it answers when the file cannot be used.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};

use secrets_core::storage::{
    Address, BackendKind, BackendRef, Locator, NamespaceKey, ScopeName, StorageError,
};
use secrets_federation::{FileConfig, Namespace, NamespaceConfig};

fn directory() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "file-config-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&path);
    path
}

fn key(namespace: &str) -> NamespaceKey {
    NamespaceKey::parse("default", namespace).unwrap()
}

fn mount(kind: BackendKind, label: &str) -> BackendRef {
    BackendRef {
        kind,
        label: ScopeName::parse(label).unwrap(),
    }
}

#[tokio::test]
async fn a_missing_file_is_local_mode_and_writes_nothing_until_a_change() {
    let directory = directory();
    let config = FileConfig::new(directory.join("b10x-secrets/config.toml"));
    let namespaces = config.namespaces().await.unwrap();
    assert_eq!(
        namespaces,
        vec![Namespace {
            key: key("default"),
            mount: None
        }]
    );
    assert!(!config.path().exists());
}

#[tokio::test]
async fn namespaces_mounts_and_bindings_survive_a_second_store_over_the_same_file() {
    let directory = directory();
    let path = directory.join("b10x-secrets/config.toml");
    let config = FileConfig::new(&path);
    config
        .insert_namespace(Namespace {
            key: key("work"),
            mount: Some(mount(BackendKind::Remote, "prod")),
        })
        .await
        .unwrap();
    config
        .set_mount(&key("default"), mount(BackendKind::Keychain, "default"))
        .await
        .unwrap();
    let address = Address::parse("default", "work", "default", "team/openai").unwrap();
    config
        .insert_binding(address.clone(), Locator::new("op://Work/OpenAI/credential"))
        .await
        .unwrap();

    let reopened = FileConfig::new(&path);
    assert_eq!(
        reopened.namespace(&key("work")).await.unwrap(),
        Some(Namespace {
            key: key("work"),
            mount: Some(mount(BackendKind::Remote, "prod")),
        })
    );
    assert_eq!(
        reopened.binding(&address).await.unwrap(),
        Some(Locator::new("op://Work/OpenAI/credential"))
    );
    assert!(reopened.has_bindings(&key("work")).await.unwrap());
    assert!(!reopened.has_bindings(&key("default")).await.unwrap());
    assert_eq!(
        reopened
            .insert_binding(address.clone(), Locator::new("x"))
            .await,
        Err(StorageError::Conflict)
    );
    reopened.remove_binding(&address).await.unwrap();
    assert_eq!(
        reopened.remove_binding(&address).await,
        Err(StorageError::NotFound)
    );
    reopened.remove_namespace(&key("work")).await.unwrap();
    assert_eq!(
        reopened.remove_namespace(&key("work")).await,
        Err(StorageError::NotFound)
    );
    assert_eq!(
        reopened.remove_namespace(&key("default")).await,
        Err(StorageError::Conflict)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn the_file_is_mode_0600_in_a_0700_directory_and_no_staging_file_is_left() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = directory();
    let path = directory.join("b10x-secrets/config.toml");
    let config = FileConfig::new(&path);
    config
        .insert_namespace(Namespace {
            key: key("work"),
            mount: None,
        })
        .await
        .unwrap();
    let mode = |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let names: Vec<String> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().all(|name| !name.contains(".tmp-")),
        "{names:?}"
    );
}

#[tokio::test]
async fn keys_this_store_does_not_own_are_kept_as_they_were() {
    let directory = directory();
    let path = directory.join("config.toml");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        &path,
        "[backends.remote.prod]\norigin = \"https://secrets.example\"\ntoken_env = \"TOKEN\"\n",
    )
    .unwrap();
    let config = FileConfig::new(&path);
    config
        .insert_namespace(Namespace {
            key: key("work"),
            mount: Some(mount(BackendKind::Remote, "prod")),
        })
        .await
        .unwrap();
    let text = fs::read_to_string(&path).unwrap();
    let table: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(
        table["backends"]["remote"]["prod"]["origin"].as_str(),
        Some("https://secrets.example")
    );
    assert_eq!(
        table["backends"]["remote"]["prod"]["token_env"].as_str(),
        Some("TOKEN")
    );
    assert_eq!(table["namespace"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn a_file_that_is_not_a_valid_store_is_unavailable_and_is_not_rewritten() {
    let directory = directory();
    fs::create_dir_all(&directory).unwrap();
    for text in [
        "not toml at all [",
        "[[namespace]]\ntenant = \"default\"\nname = \"-bad\"\n",
        "[[namespace]]\ntenant = \"default\"\nname = \"a\"\n[[namespace]]\ntenant = \"default\"\nname = \"a\"\n",
        "[[binding]]\ntenant = \"default\"\nnamespace = \"default\"\nuser = \"default\"\nname = \"x\"\n",
        "namespace = 3\n",
    ] {
        let path = directory.join("config.toml");
        fs::write(&path, text).unwrap();
        let config = FileConfig::new(&path);
        assert_eq!(config.namespaces().await, Err(StorageError::Unavailable));
        assert_eq!(
            config
                .insert_namespace(Namespace {
                    key: key("work"),
                    mount: None
                })
                .await,
            Err(StorageError::Unavailable)
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }
}

#[tokio::test]
async fn a_path_that_is_a_directory_is_unavailable() {
    let directory = directory();
    let path = directory.join("config.toml");
    fs::create_dir_all(&path).unwrap();
    let config = FileConfig::new(&path);
    assert_eq!(config.namespaces().await, Err(StorageError::Unavailable));
    assert_eq!(
        config
            .set_mount(&key("default"), BackendRef::default_mount())
            .await,
        Err(StorageError::Unavailable)
    );
}
