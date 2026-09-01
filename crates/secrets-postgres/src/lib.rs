use async_trait::async_trait;
use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretMetadata, SecretRef, SecretState, SecretStore,
    StoreError, StoredSecret,
};
use secrets_crypto::{Envelope, Keyring};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    keyring: Arc<Keyring>,
}

impl PostgresStore {
    pub async fn connect(database_url: &str, keyring: Arc<Keyring>) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { pool, keyring })
    }

    pub async fn ready(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    pub async fn rewrap_all(&self, actor: &str) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let rows = sqlx::query("SELECT s.id,s.tenant,s.namespace,s.secret_key,s.disclosure,s.current_version,v.ciphertext,v.value_nonce,v.wrapped_key,v.wrap_nonce,v.key_id FROM secrets s JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version WHERE v.key_id <> $1 FOR UPDATE")
            .bind(self.keyring.active_key_id()).fetch_all(&mut *tx).await.map_err(unavailable)?;
        let count = rows.len() as u64;
        for row in rows {
            let reference = SecretRef {
                tenant: row.try_get("tenant").map_err(unavailable)?,
                namespace: row.try_get("namespace").map_err(unavailable)?,
                key: row.try_get("secret_key").map_err(unavailable)?,
            };
            let disclosure = match row
                .try_get::<String, _>("disclosure")
                .map_err(unavailable)?
                .as_str()
            {
                "workload_only" => Disclosure::WorkloadOnly,
                "user_revealable" => Disclosure::UserRevealable,
                _ => return Err(StoreError::Unavailable),
            };
            let version: i64 = row.try_get("current_version").map_err(unavailable)?;
            let old = Envelope {
                ciphertext: row.try_get("ciphertext").map_err(unavailable)?,
                value_nonce: array12(row.try_get("value_nonce").map_err(unavailable)?)?,
                wrapped_key: row.try_get("wrapped_key").map_err(unavailable)?,
                wrap_nonce: array12(row.try_get("wrap_nonce").map_err(unavailable)?)?,
                key_id: row.try_get("key_id").map_err(unavailable)?,
            };
            let value = self
                .keyring
                .decrypt(&reference, version, disclosure, &old)
                .map_err(|_| StoreError::Crypto)?;
            let new = self
                .keyring
                .encrypt(&reference, version, disclosure, &value)
                .map_err(|_| StoreError::Crypto)?;
            let id: Uuid = row.try_get("id").map_err(unavailable)?;
            sqlx::query("UPDATE secret_versions SET ciphertext=$3,value_nonce=$4,wrapped_key=$5,wrap_nonce=$6,key_id=$7 WHERE secret_id=$1 AND version=$2")
                .bind(id).bind(version).bind(new.ciphertext).bind(new.value_nonce.as_slice()).bind(new.wrapped_key).bind(new.wrap_nonce.as_slice()).bind(new.key_id)
                .execute(&mut *tx).await.map_err(unavailable)?;
            audit(&mut tx, &reference.tenant, Some(id), actor, "rewrap").await?;
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(count)
    }

    async fn put_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        input: PutSecret,
        actor: &str,
    ) -> Result<SecretMetadata, StoreError> {
        validate_ref(&input.reference)?;
        let existing = sqlx::query("SELECT id, current_version, created_at::text FROM secrets WHERE tenant=$1 AND namespace=$2 AND secret_key=$3 FOR UPDATE")
            .bind(&input.reference.tenant).bind(&input.reference.namespace).bind(&input.reference.key)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        let (id, version) = match existing {
            Some(row) => (
                row.try_get::<Uuid, _>("id").map_err(unavailable)?,
                row.try_get::<i64, _>("current_version")
                    .map_err(unavailable)?
                    + 1,
            ),
            None => (Uuid::now_v7(), 1),
        };
        let envelope = self
            .keyring
            .encrypt(&input.reference, version, input.disclosure, &input.value)
            .map_err(|_| StoreError::Crypto)?;
        let disclosure = disclosure_text(input.disclosure);
        let labels = serde_json::to_value(&input.labels)
            .map_err(|_| StoreError::Invalid("invalid labels".into()))?;
        sqlx::query("INSERT INTO secrets(id,tenant,namespace,secret_key,owner_subject,disclosure,state,current_version,labels) VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8) ON CONFLICT(tenant,namespace,secret_key) DO UPDATE SET owner_subject=EXCLUDED.owner_subject, disclosure=EXCLUDED.disclosure, state='active', current_version=EXCLUDED.current_version, labels=EXCLUDED.labels, updated_at=now()")
            .bind(id).bind(&input.reference.tenant).bind(&input.reference.namespace).bind(&input.reference.key)
            .bind(&input.owner_subject).bind(disclosure).bind(version).bind(labels)
            .execute(&mut **tx).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO secret_versions(secret_id,version,ciphertext,value_nonce,wrapped_key,wrap_nonce,key_id) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(id).bind(version).bind(envelope.ciphertext).bind(envelope.value_nonce.as_slice())
            .bind(envelope.wrapped_key).bind(envelope.wrap_nonce.as_slice()).bind(envelope.key_id)
            .execute(&mut **tx).await.map_err(unavailable)?;
        audit(tx, &input.reference.tenant, Some(id), actor, "put").await?;
        self.metadata_tx(tx, &input.reference).await
    }

    async fn metadata_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        reference: &SecretRef,
    ) -> Result<SecretMetadata, StoreError> {
        let row = sqlx::query("SELECT id,tenant,namespace,secret_key,owner_subject,disclosure,state,current_version,labels,created_at::text,updated_at::text FROM secrets WHERE tenant=$1 AND namespace=$2 AND secret_key=$3")
            .bind(&reference.tenant).bind(&reference.namespace).bind(&reference.key)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(StoreError::NotFound)?;
        row_to_metadata(&row)
    }

    async fn delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        reference: &SecretRef,
        actor: &str,
    ) -> Result<(), StoreError> {
        let row = sqlx::query(
            "DELETE FROM secrets WHERE tenant=$1 AND namespace=$2 AND secret_key=$3 RETURNING id",
        )
        .bind(&reference.tenant)
        .bind(&reference.namespace)
        .bind(&reference.key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(StoreError::NotFound)?;
        let id: Uuid = row.try_get("id").map_err(unavailable)?;
        audit(tx, &reference.tenant, Some(id), actor, "delete").await
    }
}

#[async_trait]
impl SecretStore for PostgresStore {
    async fn ready(&self) -> Result<(), StoreError> {
        PostgresStore::ready(self).await
    }

    async fn put(&self, input: PutSecret) -> Result<SecretMetadata, StoreError> {
        let actor = input.owner_subject.clone();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let result = self.put_tx(&mut tx, input, &actor).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(result)
    }

    async fn get(&self, reference: &SecretRef) -> Result<StoredSecret, StoreError> {
        let row = sqlx::query("SELECT s.id,s.tenant,s.namespace,s.secret_key,s.owner_subject,s.disclosure,s.state,s.current_version,s.labels,s.created_at::text,s.updated_at::text,v.ciphertext,v.value_nonce,v.wrapped_key,v.wrap_nonce,v.key_id FROM secrets s JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version WHERE s.tenant=$1 AND s.namespace=$2 AND s.secret_key=$3 AND s.state='active'")
            .bind(&reference.tenant).bind(&reference.namespace).bind(&reference.key)
            .fetch_optional(&self.pool).await.map_err(unavailable)?.ok_or(StoreError::NotFound)?;
        let metadata = row_to_metadata(&row)?;
        let value_nonce = array12(row.try_get("value_nonce").map_err(unavailable)?)?;
        let wrap_nonce = array12(row.try_get("wrap_nonce").map_err(unavailable)?)?;
        let envelope = Envelope {
            ciphertext: row.try_get("ciphertext").map_err(unavailable)?,
            value_nonce,
            wrapped_key: row.try_get("wrapped_key").map_err(unavailable)?,
            wrap_nonce,
            key_id: row.try_get("key_id").map_err(unavailable)?,
        };
        let value = self
            .keyring
            .decrypt(reference, metadata.version, metadata.disclosure, &envelope)
            .map_err(|_| StoreError::Crypto)?;
        Ok(StoredSecret { metadata, value })
    }

    async fn exists(&self, reference: &SecretRef) -> Result<bool, StoreError> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM secrets WHERE tenant=$1 AND namespace=$2 AND secret_key=$3 AND state='active')")
            .bind(&reference.tenant).bind(&reference.namespace).bind(&reference.key).fetch_one(&self.pool).await.map_err(unavailable)?;
        Ok(exists)
    }

    async fn delete(&self, reference: &SecretRef, actor: &str) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        self.delete_tx(&mut tx, reference, actor).await?;
        tx.commit().await.map_err(unavailable)
    }

    async fn revoke(
        &self,
        reference: &SecretRef,
        actor: &str,
    ) -> Result<SecretMetadata, StoreError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let row = sqlx::query("UPDATE secrets SET state='revoked',updated_at=now() WHERE tenant=$1 AND namespace=$2 AND secret_key=$3 RETURNING id")
            .bind(&reference.tenant).bind(&reference.namespace).bind(&reference.key).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(StoreError::NotFound)?;
        let id = row.try_get("id").map_err(unavailable)?;
        audit(&mut tx, &reference.tenant, Some(id), actor, "revoke").await?;
        let result = self.metadata_tx(&mut tx, reference).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(result)
    }

    async fn list(
        &self,
        tenant: &str,
        owner: Option<&str>,
    ) -> Result<Vec<SecretMetadata>, StoreError> {
        let rows = sqlx::query("SELECT id,tenant,namespace,secret_key,owner_subject,disclosure,state,current_version,labels,created_at::text,updated_at::text FROM secrets WHERE tenant=$1 AND ($2::text IS NULL OR owner_subject=$2) ORDER BY updated_at DESC")
            .bind(tenant).bind(owner).fetch_all(&self.pool).await.map_err(unavailable)?;
        rows.iter().map(row_to_metadata).collect()
    }

    async fn prepare(
        &self,
        tenant: &str,
        transaction: Uuid,
        mutations: Vec<Mutation>,
        actor: &str,
    ) -> Result<(), StoreError> {
        if mutations.is_empty() {
            return Err(StoreError::Invalid("empty batch".into()));
        }
        for mutation in &mutations {
            let reference = match mutation {
                Mutation::Put { secret } => &secret.reference,
                Mutation::Delete { reference } => reference,
            };
            if reference.tenant != tenant {
                return Err(StoreError::Invalid("cross-tenant batch".into()));
            }
        }
        let json = serde_json::to_value(mutations)
            .map_err(|_| StoreError::Invalid("invalid batch".into()))?;
        sqlx::query(
            "INSERT INTO prepared_transactions(id,tenant,actor,mutations) VALUES($1,$2,$3,$4)",
        )
        .bind(transaction)
        .bind(tenant)
        .bind(actor)
        .bind(json)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique(&e) {
                StoreError::Conflict
            } else {
                unavailable(e)
            }
        })?;
        Ok(())
    }

    async fn commit(&self, tenant: &str, transaction: Uuid) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let row = sqlx::query(
            "DELETE FROM prepared_transactions WHERE tenant=$1 AND id=$2 RETURNING actor,mutations",
        )
        .bind(tenant)
        .bind(transaction)
        .fetch_optional(&mut *tx)
        .await
        .map_err(unavailable)?
        .ok_or(StoreError::NotFound)?;
        let actor: String = row.try_get("actor").map_err(unavailable)?;
        let mutations: Vec<Mutation> =
            serde_json::from_value(row.try_get("mutations").map_err(unavailable)?)
                .map_err(|_| StoreError::Unavailable)?;
        for mutation in mutations {
            match mutation {
                Mutation::Put { secret } => {
                    self.put_tx(&mut tx, secret, &actor).await?;
                }
                Mutation::Delete { reference } => {
                    self.delete_tx(&mut tx, &reference, &actor).await?;
                }
            }
        }
        audit(&mut tx, tenant, None, &actor, "commit_batch").await?;
        tx.commit().await.map_err(unavailable)
    }

    async fn abort(&self, tenant: &str, transaction: Uuid) -> Result<(), StoreError> {
        let affected = sqlx::query("DELETE FROM prepared_transactions WHERE tenant=$1 AND id=$2")
            .bind(tenant)
            .bind(transaction)
            .execute(&self.pool)
            .await
            .map_err(unavailable)?
            .rows_affected();
        if affected == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }
}

async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: Option<Uuid>,
    actor: &str,
    action: &str,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO audit_events(tenant,secret_id,actor,action) VALUES($1,$2,$3,$4)")
        .bind(tenant)
        .bind(id)
        .bind(actor)
        .bind(action)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(())
}

fn row_to_metadata(row: &sqlx::postgres::PgRow) -> Result<SecretMetadata, StoreError> {
    let disclosure = match row
        .try_get::<String, _>("disclosure")
        .map_err(unavailable)?
        .as_str()
    {
        "workload_only" => Disclosure::WorkloadOnly,
        "user_revealable" => Disclosure::UserRevealable,
        _ => return Err(StoreError::Unavailable),
    };
    let state = match row
        .try_get::<String, _>("state")
        .map_err(unavailable)?
        .as_str()
    {
        "active" => SecretState::Active,
        "revoked" => SecretState::Revoked,
        _ => return Err(StoreError::Unavailable),
    };
    let labels: BTreeMap<String, String> =
        serde_json::from_value(row.try_get("labels").map_err(unavailable)?)
            .map_err(|_| StoreError::Unavailable)?;
    Ok(SecretMetadata {
        id: row.try_get("id").map_err(unavailable)?,
        reference: SecretRef {
            tenant: row.try_get("tenant").map_err(unavailable)?,
            namespace: row.try_get("namespace").map_err(unavailable)?,
            key: row.try_get("secret_key").map_err(unavailable)?,
        },
        owner_subject: row.try_get("owner_subject").map_err(unavailable)?,
        disclosure,
        state,
        version: row.try_get("current_version").map_err(unavailable)?,
        labels,
        created_at: row.try_get("created_at").map_err(unavailable)?,
        updated_at: row.try_get("updated_at").map_err(unavailable)?,
    })
}

fn validate_ref(reference: &SecretRef) -> Result<(), StoreError> {
    for value in [&reference.tenant, &reference.namespace, &reference.key] {
        if value.is_empty() || value.len() > 255 || value.contains('\0') {
            return Err(StoreError::Invalid("invalid reference".into()));
        }
    }
    Ok(())
}
fn disclosure_text(value: Disclosure) -> &'static str {
    match value {
        Disclosure::WorkloadOnly => "workload_only",
        Disclosure::UserRevealable => "user_revealable",
    }
}
fn array12(value: Vec<u8>) -> Result<[u8; 12], StoreError> {
    value.try_into().map_err(|_| StoreError::Unavailable)
}
fn unavailable<E>(_error: E) -> StoreError {
    StoreError::Unavailable
}
fn is_unique(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.is_unique_violation())
}
