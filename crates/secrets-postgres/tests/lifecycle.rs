#![allow(clippy::unwrap_used)]

use secrets_core::{
    Actor, Disclosure, Mutation, PutSecret, SecretBytes, SecretRef, SecretState, SecretStore,
    StoreError,
};
use secrets_crypto::{Envelope, Keyring};
use secrets_postgres::PostgresStore;
use sqlx::Row;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

#[tokio::test]
async fn postgres_lifecycle_and_atomic_batch() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let keyring = Keyring::from_json(RING).unwrap();
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

    let metadata = store
        .put(put(first.clone(), b"alpha"), &"workload:test".into())
        .await
        .unwrap();
    assert_eq!(metadata.version, 1);
    assert_eq!(store.get(&first).await.unwrap().value.0, b"alpha");
    assert_eq!(
        store
            .revoke(&first, &"user:one".into())
            .await
            .unwrap()
            .state,
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
    store
        .commit(&tenant, transaction, "workload:test")
        .await
        .unwrap();
    assert!(!store.exists(&first).await.unwrap());
    assert_eq!(store.get(&second).await.unwrap().value.0, b"beta");
    store.delete(&second, &"user:one".into()).await.unwrap();
    assert!(store.list(&tenant, None).await.unwrap().is_empty());
}

const RING: &[u8] = br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#;
const MARKER: &[u8] = b"prepared-batch-plaintext-marker";

async fn isolated_database() -> Option<String> {
    let admin = std::env::var("SECRETS_TEST_DATABASE_URL").ok()?;
    let pool = sqlx::PgPool::connect(&admin).await.unwrap();
    let name = format!("lifecycle_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&pool)
        .await
        .unwrap();
    let (base, _) = admin.rsplit_once('/').unwrap();
    Some(format!("{base}/{name}"))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn batch_put(tenant: &str, key: &str) -> Mutation {
    Mutation::Put {
        secret: PutSecret {
            reference: SecretRef {
                tenant: tenant.into(),
                namespace: "connectors".into(),
                key: key.into(),
            },
            owner_subject: "user:one".into(),
            value: SecretBytes(MARKER.to_vec()),
            disclosure: Disclosure::WorkloadOnly,
            labels: BTreeMap::new(),
        },
    }
}

#[tokio::test]
async fn prepared_batch_row_holds_no_plaintext_value() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let store = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    store
        .prepare(
            &tenant,
            transaction,
            vec![batch_put(&tenant, "held")],
            "workload:test",
        )
        .await
        .unwrap();
    let text: String = sqlx::query_scalar(
        "SELECT row_to_json(p)::text FROM prepared_transactions p WHERE tenant=$1 AND id=$2",
    )
    .bind(&tenant)
    .bind(transaction)
    .fetch_one(&pool)
    .await
    .unwrap();
    let encoded = base64_standard(MARKER);
    let hex: String = MARKER.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!contains(text.as_bytes(), MARKER), "{text}");
    assert!(!contains(text.as_bytes(), encoded.as_bytes()), "{text}");
    assert!(!contains(text.as_bytes(), hex.as_bytes()), "{text}");
    store
        .commit(&tenant, transaction, "workload:test")
        .await
        .unwrap();
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "held".into(),
    };
    assert_eq!(store.get(&reference).await.unwrap().value.0, MARKER);
}

async fn held(pool: &sqlx::PgPool, tenant: &str, transaction: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM prepared_transactions WHERE tenant=$1 AND id=$2")
        .bind(tenant)
        .bind(transaction)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn prepared_batch_lives_600_seconds() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let store = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    let before = unix_seconds();
    store
        .prepare(
            &tenant,
            transaction,
            vec![batch_put(&tenant, "held")],
            "workload:test",
        )
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT extract(epoch FROM expires_at)::float8 AS expires_at, ciphertext, value_nonce, wrapped_key, wrap_nonce, key_id FROM prepared_transactions WHERE tenant=$1 AND id=$2",
    )
    .bind(&tenant)
    .bind(transaction)
    .fetch_one(&pool)
    .await
    .unwrap();
    let after = unix_seconds();
    let envelope = Envelope {
        ciphertext: row.get("ciphertext"),
        value_nonce: row.get::<Vec<u8>, _>("value_nonce").try_into().unwrap(),
        wrapped_key: row.get("wrapped_key"),
        wrap_nonce: row.get::<Vec<u8>, _>("wrap_nonce").try_into().unwrap(),
        key_id: row.get("key_id"),
    };
    let payload = Keyring::from_json(RING)
        .unwrap()
        .open_batch(&tenant, transaction.as_bytes(), "workload:test", &envelope)
        .unwrap();
    let sealed_expiry = i64::from_be_bytes(payload[..8].try_into().unwrap());
    assert!(
        (before + 600..=after + 600).contains(&sealed_expiry),
        "{before} {sealed_expiry} {after}"
    );
    assert_eq!(sealed_expiry as f64, row.get::<f64, _>("expires_at"));
    store.abort(&tenant, transaction).await.unwrap();
}

#[tokio::test]
async fn expired_batch_commits_as_not_found_and_is_removed() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let store = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let expiring = store.clone().with_batch_lifetime(Duration::ZERO);
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "held".into(),
    };

    let committed = Uuid::now_v7();
    expiring
        .prepare(
            &tenant,
            committed,
            vec![batch_put(&tenant, "held")],
            "workload:test",
        )
        .await
        .unwrap();
    assert!(matches!(
        store.commit(&tenant, committed, "workload:test").await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(held(&pool, &tenant, committed).await, 0);
    assert!(!store.exists(&reference).await.unwrap());

    let purged = Uuid::now_v7();
    expiring
        .prepare(
            &tenant,
            purged,
            vec![batch_put(&tenant, "held")],
            "workload:test",
        )
        .await
        .unwrap();
    assert_eq!(held(&pool, &tenant, purged).await, 1);
    let fresh = Uuid::now_v7();
    store
        .prepare(
            &tenant,
            fresh,
            vec![batch_put(&tenant, "held")],
            "workload:test",
        )
        .await
        .unwrap();
    assert_eq!(held(&pool, &tenant, purged).await, 0);
    store.commit(&tenant, fresh, "workload:test").await.unwrap();
    assert_eq!(store.get(&reference).await.unwrap().value.0, MARKER);
}

#[tokio::test]
async fn moved_batch_fails_to_open_and_applies_nothing() {
    let Some(database_url) = isolated_database().await else {
        return;
    };
    let store = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    for column in ["tenant", "id", "actor"] {
        let tenant = format!("test-{}", Uuid::now_v7());
        let transaction = Uuid::now_v7();
        store
            .prepare(
                &tenant,
                transaction,
                vec![batch_put(&tenant, "held")],
                "workload:test",
            )
            .await
            .unwrap();
        let (to_tenant, to_transaction) = match column {
            "tenant" => (format!("test-{}", Uuid::now_v7()), transaction),
            "id" => (tenant.clone(), Uuid::now_v7()),
            _ => (tenant.clone(), transaction),
        };
        sqlx::query("UPDATE prepared_transactions SET tenant=$3, id=$4, actor=CASE WHEN $5 THEN 'workload:other' ELSE actor END WHERE tenant=$1 AND id=$2")
            .bind(&tenant)
            .bind(transaction)
            .bind(&to_tenant)
            .bind(to_transaction)
            .bind(column == "actor")
            .execute(&pool)
            .await
            .unwrap();
        let result = store
            .commit(&to_tenant, to_transaction, "workload:test")
            .await;
        assert!(
            matches!(result, Err(StoreError::Unavailable)),
            "{column}: {result:?}"
        );
        for owner in [&tenant, &to_tenant] {
            let reference = SecretRef {
                tenant: owner.clone(),
                namespace: "connectors".into(),
                key: "held".into(),
            };
            assert!(!store.exists(&reference).await.unwrap(), "{column}");
        }
        store.abort(&to_tenant, to_transaction).await.unwrap();
    }
}

#[tokio::test]
async fn rewrap_keeps_a_held_batch_committable() {
    let Some(database_url) = isolated_database().await else {
        return;
    };
    let old = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let rotated = PostgresStore::connect(
        &database_url,
        Arc::new(
            Keyring::from_json(
                br#"{"active":"v2","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#,
            )
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    let only_new = PostgresStore::connect(
        &database_url,
        Arc::new(
            Keyring::from_json(
                br#"{"active":"v2","keys":{"v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#,
            )
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    old.prepare(
        &tenant,
        transaction,
        vec![batch_put(&tenant, "held")],
        "workload:test",
    )
    .await
    .unwrap();
    rotated.rewrap_all("operator:test").await.unwrap();
    let key_id: String =
        sqlx::query_scalar("SELECT key_id FROM prepared_transactions WHERE tenant=$1 AND id=$2")
            .bind(&tenant)
            .bind(transaction)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(key_id, "v2");
    only_new
        .commit(&tenant, transaction, "workload:test")
        .await
        .unwrap();
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "held".into(),
    };
    assert_eq!(only_new.get(&reference).await.unwrap().value.0, MARKER);
}

fn base64_standard(bytes: &[u8]) -> String {
    serde_json::to_value(SecretBytes(bytes.to_vec()))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn abort_answers_not_found_for_a_batch_under_a_key_the_keyring_lacks() {
    let Some(database_url) = isolated_database().await else {
        return;
    };
    let foreign = PostgresStore::connect(
        &database_url,
        Arc::new(
            Keyring::from_json(
                br#"{"active":"v9","keys":{"v9":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="}}"#,
            )
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    let store = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    foreign
        .prepare(
            &tenant,
            transaction,
            vec![batch_put(&tenant, "held")],
            "workload:test",
        )
        .await
        .unwrap();
    assert!(matches!(
        store.abort(&tenant, transaction).await,
        Err(StoreError::NotFound)
    ));
    foreign.abort(&tenant, transaction).await.unwrap();
}

#[tokio::test]
async fn rewrap_reencrypts_every_stored_version() {
    let Some(database_url) = isolated_database().await else {
        return;
    };
    let old = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let rotated = PostgresStore::connect(
        &database_url,
        Arc::new(
            Keyring::from_json(
                br#"{"active":"v2","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#,
            )
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    let only_new = Keyring::from_json(
        br#"{"active":"v2","keys":{"v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#,
    )
    .unwrap();
    let reference = SecretRef {
        tenant: format!("test-{}", Uuid::now_v7()),
        namespace: "connectors".into(),
        key: "versioned".into(),
    };
    let values: [&[u8]; 3] = [b"first", b"second", b"third"];
    for value in values {
        old.put(
            PutSecret {
                reference: reference.clone(),
                owner_subject: "user:one".into(),
                value: SecretBytes(value.to_vec()),
                disclosure: Disclosure::WorkloadOnly,
                labels: BTreeMap::new(),
            },
            &"workload:test".into(),
        )
        .await
        .unwrap();
    }

    assert_eq!(rotated.rewrap_all("operator:test").await.unwrap(), 3);

    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let rows = sqlx::query("SELECT v.version,v.ciphertext,v.value_nonce,v.wrapped_key,v.wrap_nonce,v.key_id FROM secrets s JOIN secret_versions v ON v.secret_id=s.id WHERE s.tenant=$1 ORDER BY v.version")
        .bind(&reference.tenant)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    for (row, expected) in rows.iter().zip(values) {
        let version: i64 = row.get("version");
        let envelope = Envelope {
            ciphertext: row.get("ciphertext"),
            value_nonce: row.get::<Vec<u8>, _>("value_nonce").try_into().unwrap(),
            wrapped_key: row.get("wrapped_key"),
            wrap_nonce: row.get::<Vec<u8>, _>("wrap_nonce").try_into().unwrap(),
            key_id: row.get("key_id"),
        };
        assert_eq!(envelope.key_id, "v2", "version {version}");
        let value = only_new
            .decrypt(&reference, version, Disclosure::WorkloadOnly, &envelope)
            .unwrap();
        assert_eq!(value.0, expected, "version {version}");
    }
    assert_eq!(rotated.rewrap_all("operator:test").await.unwrap(), 0);
}

#[tokio::test]
async fn audit_records_the_verified_actor_beside_the_claimed_one() {
    let Some(database_url) = isolated_database().await else {
        return;
    };
    let store = PostgresStore::connect(&database_url, Arc::new(Keyring::from_json(RING).unwrap()))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "audited".into(),
    };
    store
        .put(
            PutSecret {
                reference: reference.clone(),
                owner_subject: "user:owner".into(),
                value: SecretBytes(b"value".to_vec()),
                disclosure: Disclosure::WorkloadOnly,
                labels: BTreeMap::new(),
            },
            &"workload:verified".into(),
        )
        .await
        .unwrap();
    store
        .delete(
            &reference,
            &Actor::verified("workload:verified").claiming(Some("someone-else".into())),
        )
        .await
        .unwrap();
    let transaction = Uuid::now_v7();
    store
        .prepare(
            &tenant,
            transaction,
            vec![batch_put(&tenant, "batched")],
            "claimed-by-prepare",
        )
        .await
        .unwrap();
    store
        .commit(&tenant, transaction, "workload:committer")
        .await
        .unwrap();

    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT action, actor, claimed_actor FROM audit_events WHERE tenant=$1 ORDER BY sequence",
    )
    .bind(&tenant)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![
            ("put".into(), "workload:verified".into(), None),
            (
                "delete".into(),
                "workload:verified".into(),
                Some("someone-else".into())
            ),
            (
                "put".into(),
                "workload:committer".into(),
                Some("claimed-by-prepare".into())
            ),
            (
                "commit_batch".into(),
                "workload:committer".into(),
                Some("claimed-by-prepare".into())
            ),
        ]
    );
}
