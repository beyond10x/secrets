#![allow(clippy::unwrap_used)]
//! Conformance checks of `story:prepared-batch-custody` against its acceptance statement.

use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretBytes, SecretRef, SecretStore, StoreError,
};
use secrets_crypto::Keyring;
use secrets_postgres::PostgresStore;
use std::{borrow::Cow, collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

const RING: &[u8] = br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#;
const ROTATED: &[u8] = br#"{"active":"v2","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#;
const VALUE: &[u8] = b"security-batch-value";

fn put(tenant: &str, key: &str) -> Mutation {
    Mutation::Put {
        secret: PutSecret {
            reference: SecretRef {
                tenant: tenant.into(),
                namespace: "connectors".into(),
                key: key.into(),
            },
            owner_subject: "user:one".into(),
            value: SecretBytes(VALUE.to_vec()),
            disclosure: Disclosure::WorkloadOnly,
            labels: BTreeMap::new(),
        },
    }
}

fn reference(tenant: &str, key: &str) -> SecretRef {
    SecretRef {
        tenant: tenant.into(),
        namespace: "connectors".into(),
        key: key.into(),
    }
}

async fn store(database_url: &str, ring: &[u8]) -> PostgresStore {
    PostgresStore::connect(database_url, Arc::new(Keyring::from_json(ring).unwrap()))
        .await
        .unwrap()
}

/// Acceptance: "A batch older than its lifetime (600 seconds) cannot be committed". The bound is
/// held in `expires_at`, which the envelope does not authenticate, while the same envelope does
/// authenticate tenant, id and actor against a row writer.
#[tokio::test]
async fn expired_batch_stays_uncommittable_when_its_expiry_column_is_rewritten() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let store = store(&database_url, RING).await;
    let expiring = store.clone().with_batch_lifetime(Duration::ZERO);
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("sec-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    expiring
        .prepare(
            &tenant,
            transaction,
            vec![put(&tenant, "revived")],
            "workload:test",
        )
        .await
        .unwrap();
    sqlx::query("UPDATE prepared_transactions SET expires_at = now() + interval '1 hour' WHERE tenant=$1 AND id=$2")
        .bind(&tenant)
        .bind(transaction)
        .execute(&pool)
        .await
        .unwrap();
    let result = store.commit(&tenant, transaction, "workload:test").await;
    let applied = store.exists(&reference(&tenant, "revived")).await.unwrap();
    sqlx::query("DELETE FROM prepared_transactions WHERE tenant=$1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        matches!(result, Err(StoreError::NotFound)) && !applied,
        "a batch prepared with a zero lifetime committed after its expires_at was rewritten: {result:?}, applied={applied}"
    );
}

/// Acceptance: an expired batch "is gone"; docs: "Commit or abort of an unknown ID is `404`".
#[tokio::test]
async fn abort_of_an_expired_batch_answers_not_found() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let store = store(&database_url, RING).await;
    let expiring = store.clone().with_batch_lifetime(Duration::ZERO);
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let tenant = format!("sec-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    expiring
        .prepare(
            &tenant,
            transaction,
            vec![put(&tenant, "late")],
            "workload:test",
        )
        .await
        .unwrap();
    let result = store.abort(&tenant, transaction).await;
    sqlx::query("DELETE FROM prepared_transactions WHERE tenant=$1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "abort of an expired batch answered {result:?}"
    );
}

/// Acceptance: rewrap keeps a held batch committable. A commit racing a rewrap must either see the
/// old envelope or the re-sealed one, never a torn row, and must apply exactly once.
#[tokio::test]
async fn commit_racing_rewrap_applies_the_batch_exactly_once() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let old = store(&database_url, RING).await;
    let rotated = store(&database_url, ROTATED).await;
    let tenant = format!("sec-{}", Uuid::now_v7());
    for round in 0..20 {
        let key = format!("raced-{round}");
        let transaction = Uuid::now_v7();
        old.prepare(
            &tenant,
            transaction,
            vec![put(&tenant, &key)],
            "workload:test",
        )
        .await
        .unwrap();
        let (rewrap, commit) = tokio::join!(
            rotated.rewrap_all("operator:test"),
            old.commit(&tenant, transaction, "workload:test")
        );
        rewrap.unwrap();
        commit.unwrap();
        assert!(matches!(
            old.commit(&tenant, transaction, "workload:test").await,
            Err(StoreError::NotFound)
        ));
        let stored = old.get(&reference(&tenant, &key)).await.unwrap();
        assert_eq!(stored.metadata.version, 1, "{round}");
        assert_eq!(stored.value.0, VALUE, "{round}");
    }
}

/// Acceptance: "Migration `0002` replaces the `mutations` column. Batches held by an earlier
/// release are discarded by the migration". Run against a database that holds a 0001-era batch.
#[tokio::test]
async fn migration_0002_discards_batches_held_by_an_earlier_release() {
    let Ok(database_url) = std::env::var("SECRETS_TEST_DATABASE_URL") else {
        return;
    };
    let admin = sqlx::PgPool::connect(&database_url).await.unwrap();
    let name = format!("sec_mig_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let (base, _) = database_url.rsplit_once('/').unwrap();
    let url = format!("{base}/{name}");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let full = sqlx::migrate!("./migrations");
    let first = sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            full.migrations
                .iter()
                .filter(|m| m.version == 1)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    first.run(&pool).await.unwrap();
    let tenant = "sec-migration";
    let held = Uuid::now_v7();
    let json = serde_json::to_value(vec![put(tenant, "old")]).unwrap();
    sqlx::query("INSERT INTO prepared_transactions(id,tenant,actor,mutations) VALUES($1,$2,$3,$4)")
        .bind(held)
        .bind(tenant)
        .bind("workload:test")
        .bind(json)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let upgraded = store(&url, RING).await;
    let check = sqlx::PgPool::connect(&url).await.unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM prepared_transactions")
        .fetch_one(&check)
        .await
        .unwrap();
    let old_column: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_name='prepared_transactions' AND column_name='mutations'")
        .fetch_one(&check)
        .await
        .unwrap();
    let commit_old = upgraded.commit(tenant, held, "workload:test").await;
    let fresh = Uuid::now_v7();
    upgraded
        .prepare(tenant, fresh, vec![put(tenant, "new")], "workload:test")
        .await
        .unwrap();
    upgraded
        .commit(tenant, fresh, "workload:test")
        .await
        .unwrap();
    let value = upgraded
        .get(&reference(tenant, "new"))
        .await
        .unwrap()
        .value
        .0
        .clone();
    check.close().await;
    drop(upgraded);
    let _ = sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await;
    assert_eq!(remaining, 0);
    assert_eq!(old_column, 0);
    assert!(
        matches!(commit_old, Err(StoreError::NotFound)),
        "{commit_old:?}"
    );
    assert_eq!(value, VALUE);
}
