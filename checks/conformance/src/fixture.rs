//! One disposable PostgreSQL database per scenario, the shipped store and router over it, and the
//! two bearer authorities the router consults.
//!
//! Nothing here reads a suite, a scenario name or an expected assertion. The authorities are the
//! only stand-ins: the Identity service and Kubernetes TokenReview are outside this repository, so
//! a token here resolves to the principal the adapter registered for it, and an unregistered token
//! is refused exactly as `secrets_auth::AuthError::Unauthorized` says a remote authority refuses.
use async_trait::async_trait;
use axum::Router;
use secrets_auth::{AuthError, Authority, Principal};
use secrets_crypto::Keyring;
use secrets_http::AppState;
use secrets_postgres::PostgresStore;
use sqlx::PgPool;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{Arc, Mutex},
};
use url::Url;
use uuid::Uuid;

/// The keyring the service runs with: `v1` active, `v2` held.
pub const SERVICE_RING: &[u8] = br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#;
/// The keyring an operator rotates to: `v2` active, `v1` still held so old versions decrypt.
pub const ROTATED_RING: &[u8] = br#"{"active":"v2","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#;
/// A keyring that holds none of the keys the service wrote with.
pub const FOREIGN_RING: &[u8] =
    br#"{"active":"v3","keys":{"v3":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="}}"#;

type Tokens = Arc<Mutex<BTreeMap<String, Principal>>>;

struct TokenAuthority {
    tokens: Tokens,
}
#[async_trait]
impl Authority for TokenAuthority {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        self.tokens
            .lock()
            .map_err(|_| AuthError::Unavailable)?
            .get(token)
            .cloned()
            .ok_or(AuthError::Unauthorized)
    }
}

/// The server every scenario database is created on.
pub struct Admin {
    pool: PgPool,
    base: Url,
}

impl Admin {
    pub async fn connect(database_url: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            pool: PgPool::connect(database_url).await?,
            base: Url::parse(database_url)?,
        })
    }

    /// A fresh database, migrated by the shipped store's own `connect`.
    pub async fn open(&self) -> Result<Scenario, Box<dyn Error>> {
        let name = format!("custody_conformance_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&self.pool)
            .await?;
        let mut url = self.base.clone();
        url.set_path(&name);
        let url = url.to_string();
        let store = Arc::new(
            PostgresStore::connect(&url, Arc::new(Keyring::from_json(SERVICE_RING)?)).await?,
        );
        let users: Tokens = Arc::default();
        let workloads: Tokens = Arc::default();
        let router = secrets_http::router(AppState {
            store: store.clone(),
            user_authority: Arc::new(TokenAuthority {
                tokens: users.clone(),
            }),
            workload_authority: Arc::new(TokenAuthority {
                tokens: workloads.clone(),
            }),
        });
        Ok(Scenario {
            observer: PgPool::connect(&url).await?,
            name,
            url,
            store,
            router,
            users,
            workloads,
            minted: 0,
            references: BTreeSet::new(),
            owners: BTreeSet::new(),
        })
    }

    pub async fn close(&self, scenario: Scenario) -> Result<(), Box<dyn Error>> {
        let name = scenario.name.clone();
        scenario.observer.close().await;
        drop(scenario);
        sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Makes the scenario's database refuse every connection and ends the ones it holds, so the
    /// store's next statement fails the way a lost database does.
    pub async fn take_down(&self, scenario: &Scenario) -> Result<(), Box<dyn Error>> {
        sqlx::query(&format!(
            "ALTER DATABASE {} WITH ALLOW_CONNECTIONS false",
            scenario.name
        ))
        .execute(&self.pool)
        .await?;
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
            .bind(&scenario.name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn bring_up(&self, scenario: &Scenario) -> Result<(), Box<dyn Error>> {
        sqlx::query(&format!(
            "ALTER DATABASE {} WITH ALLOW_CONNECTIONS true",
            scenario.name
        ))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// A reference the scenario addressed, as `(tenant, namespace, key)`.
pub type Address = (String, String, String);

/// One scenario's isolated service.
pub struct Scenario {
    name: String,
    /// The scenario database, for a second store the operator runs with another keyring.
    pub url: String,
    /// The shipped store the router serves; the adapter arranges fixture state through it.
    pub store: Arc<PostgresStore>,
    pub router: Router,
    /// Reads rows the service wrote (audit records, prepared batches) and never writes them,
    /// except where an arrangement says it does.
    pub observer: PgPool,
    users: Tokens,
    workloads: Tokens,
    minted: u64,
    /// Every reference a command addressed, so an unparameterised view is read over each scope
    /// the scenario touched.
    pub references: BTreeSet<Address>,
    /// Every owner subject a command named or an arrangement stored.
    pub owners: BTreeSet<String>,
}

/// Which authority a token is registered with.
#[derive(Clone, Copy)]
pub enum Audience {
    User,
    Workload,
}

impl Scenario {
    /// A bearer token the chosen authority resolves to this principal.
    pub fn token(
        &mut self,
        audience: Audience,
        subject: &str,
        tenant: &str,
        actions: &[&str],
    ) -> Result<String, Box<dyn Error>> {
        self.minted += 1;
        let token = format!("fixture-token-{}", self.minted);
        let tokens = match audience {
            Audience::User => &self.users,
            Audience::Workload => &self.workloads,
        };
        tokens.lock().map_err(|_| "token table poisoned")?.insert(
            token.clone(),
            Principal {
                subject: subject.to_owned(),
                tenant: tenant.to_owned(),
                actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            },
        );
        Ok(token)
    }
}
