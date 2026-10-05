#![allow(clippy::unwrap_used)]

use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretBytes, SecretRef, SecretStore, StoreError,
};
use secrets_crypto::Keyring;
use secrets_postgres::PostgresStore;
use std::{borrow::Cow, collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

const V0: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";
const V1: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const V2: &str = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=";

fn ring(active: &str, keys: &[(&str, &str)]) -> Arc<Keyring> {
    let keys: Vec<String> = keys
        .iter()
        .map(|(id, key)| format!("\"{id}\":\"{key}\""))
        .collect();
    let json = format!(r#"{{"active":"{active}","keys":{{{}}}}}"#, keys.join(","));
    Arc::new(Keyring::from_json(json.as_bytes()).unwrap())
}

/// A database of its own, so that `rewrap_all` (which is global) and rows this file leaves in an
/// unopenable state cannot reach any other test.
async fn isolated_database() -> Option<String> {
    let admin = std::env::var("SECRETS_TEST_DATABASE_URL").ok()?;
    let pool = sqlx::PgPool::connect(&admin).await.unwrap();
    let name = format!("adv_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&pool)
        .await
        .unwrap();
    let (base, _) = admin.rsplit_once('/').unwrap();
    Some(format!("{base}/{name}"))
}

fn put(tenant: &str, key: &str, value: &[u8]) -> PutSecret {
    PutSecret {
        reference: SecretRef {
            tenant: tenant.into(),
            namespace: "connectors".into(),
            key: key.into(),
        },
        owner_subject: "user:one".into(),
        value: SecretBytes(value.to_vec()),
        disclosure: Disclosure::WorkloadOnly,
        labels: BTreeMap::new(),
    }
}

fn batch(tenant: &str, key: &str) -> Vec<Mutation> {
    vec![Mutation::Put {
        secret: put(tenant, key, b"adversary-value"),
    }]
}

/// Acceptance: an expired batch "cannot be committed ... and the batch is gone", and `rewrap_all`
/// exists so that "retiring a key never strands a prepared batch". A batch that has already expired
/// is by contract gone, yet `rewrap_all` still selects it (`WHERE key_id <> $1`, no expiry filter)
/// and fails the whole rotation — secrets included — when it does not open.
#[tokio::test]
async fn rewrap_is_not_blocked_by_an_expired_batch() {
    let Some(url) = isolated_database().await else {
        return;
    };
    // A replica still on the pre-rotation keyring seals a batch under v0; it then expires.
    let stale = PostgresStore::connect(&url, ring("v0", &[("v0", V0)]))
        .await
        .unwrap()
        .with_batch_lifetime(Duration::ZERO);
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    stale
        .prepare(&tenant, transaction, batch(&tenant, "held"), "workload:a")
        .await
        .unwrap();
    // A secret under v1 that the next rotation has to rewrap.
    let current = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap();
    current
        .put(put(&tenant, "live", b"live-value"), &"workload:test".into())
        .await
        .unwrap();
    // The next rotation: v0 is long retired, v1 -> v2.
    let rotated = PostgresStore::connect(&url, ring("v2", &[("v1", V1), ("v2", V2)]))
        .await
        .unwrap();
    let other_tenant_quiet = rotated.rewrap_all("operator:test").await;
    assert!(
        matches!(other_tenant_quiet, Ok(1)),
        "an expired, contractually gone batch blocked the rotation: {other_tenant_quiet:?}"
    );
}

/// Acceptance: an expired batch is gone. Commit agrees (`not-found`), but abort answers `aborted`
/// for an expired batch until some unrelated prepare or commit in the tenant happens to purge it,
/// and `not-found` afterwards: the answer to one request depends on other traffic.
#[tokio::test]
async fn abort_of_an_expired_batch_is_not_found_like_commit() {
    let Some(url) = isolated_database().await else {
        return;
    };
    let store = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap();
    let expiring = store.clone().with_batch_lifetime(Duration::ZERO);
    let tenant = format!("test-{}", Uuid::now_v7());
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    expiring
        .prepare(&tenant, first, batch(&tenant, "held"), "workload:a")
        .await
        .unwrap();
    let before_purge = store.abort(&tenant, first).await;
    expiring
        .prepare(&tenant, second, batch(&tenant, "held"), "workload:a")
        .await
        .unwrap();
    store
        .prepare(
            &tenant,
            Uuid::now_v7(),
            batch(&tenant, "other"),
            "workload:a",
        )
        .await
        .unwrap();
    let after_purge = store.abort(&tenant, second).await;
    assert!(
        matches!(after_purge, Err(StoreError::NotFound)),
        "{after_purge:?}"
    );
    assert!(
        matches!(before_purge, Err(StoreError::NotFound)),
        "abort of an expired batch answered {before_purge:?} before a purge and {after_purge:?} after one"
    );
}

/// Acceptance: "Migration 0002 replaces the mutations column. Batches held by an earlier release are
/// discarded by the migration." Driven from a database that really holds a 0001-shaped row.
#[tokio::test]
async fn migration_0002_discards_batches_held_by_0001() {
    let Some(url) = isolated_database().await else {
        return;
    };
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let mut first_only = sqlx::migrate!("./migrations");
    first_only.migrations = Cow::Owned(first_only.migrations[..1].to_vec());
    first_only.run(&pool).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let old = Uuid::now_v7();
    sqlx::query("INSERT INTO prepared_transactions(id,tenant,actor,mutations) VALUES($1,$2,$3,$4)")
        .bind(old)
        .bind(&tenant)
        .bind("workload:a")
        .bind(serde_json::to_value(batch(&tenant, "held")).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let store = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap();
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM prepared_transactions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(held, 0);
    assert!(matches!(
        store.commit(&tenant, old, "workload:test").await,
        Err(StoreError::NotFound)
    ));
    let fresh = Uuid::now_v7();
    store
        .prepare(&tenant, fresh, batch(&tenant, "held"), "workload:a")
        .await
        .unwrap();
    store.commit(&tenant, fresh, "workload:test").await.unwrap();
}

/// Rewrap and commit racing on one held batch: rewrap takes the row lock first, commit queues on
/// it, and commit must then open the re-sealed envelope (a keyring that no longer holds v1).
#[tokio::test]
async fn commit_queued_behind_rewrap_opens_the_resealed_batch() {
    let Some(url) = isolated_database().await else {
        return;
    };
    let old = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap();
    let rotated = PostgresStore::connect(&url, ring("v2", &[("v1", V1), ("v2", V2)]))
        .await
        .unwrap();
    let only_new = PostgresStore::connect(&url, ring("v2", &[("v2", V2)]))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    old.prepare(&tenant, transaction, batch(&tenant, "held"), "workload:a")
        .await
        .unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM prepared_transactions WHERE tenant=$1 AND id=$2 FOR UPDATE")
        .bind(&tenant)
        .bind(transaction)
        .execute(&mut *gate)
        .await
        .unwrap();
    let rewrap = tokio::spawn(async move { rotated.rewrap_all("operator:test").await });
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .unwrap();
    let committing = only_new.clone();
    let commit_tenant = tenant.clone();
    let commit = tokio::spawn(async move {
        committing
            .commit(&commit_tenant, transaction, "workload:test")
            .await
    });
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .unwrap();
    gate.rollback().await.unwrap();
    rewrap.await.unwrap().unwrap();
    let committed = commit.await.unwrap();
    assert!(committed.is_ok(), "{committed:?}");
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "held".into(),
    };
    assert_eq!(
        only_new.get(&reference).await.unwrap().value.0,
        b"adversary-value"
    );
}

async fn pause() {
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .unwrap();
}

/// Documented rotation (operations.md steps 3-4): the service keeps serving while `secrets rewrap`
/// runs. `rewrap_all` locks every old-key secret, re-encrypts them one by one, and only then locks
/// the held batches. A commit that has already claimed its batch row by then, and whose batch
/// writes one of those old-key secrets, waits on rewrap while rewrap waits on it. The gate on
/// `staging` (a secret already under the new key, which rewrap does not select) stands in for the
/// re-encryption window, so the interleaving is deterministic.
#[tokio::test]
async fn commit_writing_an_old_key_secret_does_not_deadlock_with_rewrap() {
    let Some(url) = isolated_database().await else {
        return;
    };
    let old = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap();
    let rotated = PostgresStore::connect(&url, ring("v2", &[("v1", V1), ("v2", V2)]))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    old.put(
        put(&tenant, "rotating", b"old-value"),
        &"workload:test".into(),
    )
    .await
    .unwrap();
    rotated
        .put(
            put(&tenant, "staging", b"new-value"),
            &"workload:test".into(),
        )
        .await
        .unwrap();
    let transaction = Uuid::now_v7();
    old.prepare(
        &tenant,
        transaction,
        vec![
            Mutation::Put {
                secret: put(&tenant, "staging", b"batch-staging"),
            },
            Mutation::Put {
                secret: put(&tenant, "rotating", b"batch-rotating"),
            },
        ],
        "workload:a",
    )
    .await
    .unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM secrets WHERE tenant=$1 AND secret_key='staging' FOR UPDATE")
        .bind(&tenant)
        .execute(&mut *gate)
        .await
        .unwrap();
    let committing = rotated.clone();
    let commit_tenant = tenant.clone();
    let commit = tokio::spawn(async move {
        committing
            .commit(&commit_tenant, transaction, "workload:test")
            .await
    });
    pause().await;
    let rewrapping = rotated.clone();
    let rewrap = tokio::spawn(async move { rewrapping.rewrap_all("operator:test").await });
    pause().await;
    gate.rollback().await.unwrap();
    let rewrapped = rewrap.await.unwrap();
    let committed = commit.await.unwrap();
    assert!(
        committed.is_ok() && rewrapped.is_ok(),
        "commit racing a live rotation: commit={committed:?}, rewrap={rewrapped:?}"
    );
}

/// Coordinator decision D2 (custody.yaml AbortTransaction): abort opens nothing and decides expiry
/// from the column; commit decides from the sealed value. A forward-rewritten column therefore lets
/// abort remove a sealed-expired batch, and commit still refuses it and applies nothing.
#[tokio::test]
async fn abort_follows_the_column_while_commit_follows_the_sealed_expiry() {
    let Some(url) = isolated_database().await else {
        return;
    };
    let store = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap();
    let expiring = store.clone().with_batch_lifetime(Duration::ZERO);
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let committed = Uuid::now_v7();
    let aborted = Uuid::now_v7();
    for id in [committed, aborted] {
        expiring
            .prepare(&tenant, id, batch(&tenant, "held"), "workload:a")
            .await
            .unwrap();
    }
    sqlx::query(
        "UPDATE prepared_transactions SET expires_at = now() + interval '1 hour' WHERE tenant=$1",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .unwrap();
    let commit = store.commit(&tenant, committed, "workload:test").await;
    let abort = store.abort(&tenant, aborted).await;
    assert!(matches!(commit, Err(StoreError::NotFound)), "{commit:?}");
    assert!(matches!(abort, Ok(())), "{abort:?}");
    let held: i64 =
        sqlx::query_scalar("SELECT count(*) FROM prepared_transactions WHERE tenant=$1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(held, 0);
    assert!(matches!(
        store.get(&put(&tenant, "held", b"").reference).await,
        Err(StoreError::NotFound)
    ));
}

/// Rewrap with the column rewritten forward on a sealed-expired batch: the reseal must carry the
/// sealed expiry across, so the batch stays uncommittable under the new key only.
#[tokio::test]
async fn rewrap_keeps_the_sealed_expiry_when_the_column_is_rewritten_forward() {
    let Some(url) = isolated_database().await else {
        return;
    };
    let old = PostgresStore::connect(&url, ring("v1", &[("v1", V1)]))
        .await
        .unwrap()
        .with_batch_lifetime(Duration::ZERO);
    let rotated = PostgresStore::connect(&url, ring("v2", &[("v1", V1), ("v2", V2)]))
        .await
        .unwrap();
    let only_new = PostgresStore::connect(&url, ring("v2", &[("v2", V2)]))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let tenant = format!("test-{}", Uuid::now_v7());
    let transaction = Uuid::now_v7();
    old.prepare(&tenant, transaction, batch(&tenant, "held"), "workload:a")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE prepared_transactions SET expires_at = now() + interval '1 hour' WHERE tenant=$1",
    )
    .bind(&tenant)
    .execute(&pool)
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
    let commit = only_new.commit(&tenant, transaction, "workload:test").await;
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: "connectors".into(),
        key: "held".into(),
    };
    let applied = only_new.exists(&reference).await.unwrap();
    assert!(
        matches!(commit, Err(StoreError::NotFound)) && !applied,
        "{commit:?}, applied={applied}"
    );
}
