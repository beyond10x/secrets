//! An in-process custody service on a loopback port, as `checks/conformance/src/fixture.rs` stands
//! it up: the shipped router and PostgreSQL store over a disposable database, and a token table in
//! place of the Identity service and Kubernetes TokenReview. No network beyond loopback.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use async_trait::async_trait;
use axum::{Router, http::StatusCode};
use secrets_auth::{AuthError, Authority, Principal};
use secrets_client::Client;
use secrets_core::storage::{Address, SecretValue, Target};
use secrets_crypto::Keyring;
use secrets_http::AppState;
use secrets_postgres::PostgresStore;
use secrets_remote::RemoteBackend;
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, task::JoinHandle};
use uuid::Uuid;

const RING: &[u8] = br#"{"active":"v1","keys":{"v1":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","v2":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}}"#;

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

/// An HTTP client that never routes loopback traffic through a proxy from the environment.
pub fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// Serves a router on `127.0.0.1:0` and returns its origin.
pub async fn serve(router: Router) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{address}/"), server)
}

/// A service that answers every request with this status and body.
pub async fn stub(status: StatusCode, body: &'static str) -> (String, JoinHandle<()>) {
    serve(Router::new().fallback(move || async move { (status, body) })).await
}

/// An origin nothing listens on: the port was bound and released.
pub async fn closed_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}/")
}

pub fn backend_at(origin: &str, token: &str) -> RemoteBackend {
    RemoteBackend::new(Client::with_http(http(), origin, token).unwrap())
}

pub struct Service {
    admin: PgPool,
    name: String,
    pub origin: String,
    server: JoinHandle<()>,
    workloads: Tokens,
    minted: Mutex<u64>,
}

impl Service {
    /// A fresh service, or `None` when `SECRETS_TEST_DATABASE_URL` is unset.
    pub async fn start() -> Option<Self> {
        let admin_url = std::env::var("SECRETS_TEST_DATABASE_URL").ok()?;
        let admin = PgPool::connect(&admin_url).await.unwrap();
        let name = format!("remote_backend_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let (base, _) = admin_url.rsplit_once('/').unwrap();
        let url = format!("{base}/{name}");
        let store = Arc::new(
            PostgresStore::connect(&url, Arc::new(Keyring::from_json(RING).unwrap()))
                .await
                .unwrap(),
        );
        let workloads: Tokens = Arc::default();
        let router = secrets_http::router(AppState {
            store,
            user_authority: Arc::new(TokenAuthority {
                tokens: Arc::default(),
            }),
            workload_authority: Arc::new(TokenAuthority {
                tokens: workloads.clone(),
            }),
        });
        let (origin, server) = serve(router).await;
        Some(Self {
            admin,
            name,
            origin,
            server,
            workloads,
            minted: Mutex::new(0),
        })
    }

    /// A workload token of `tenant` permitted every workload action.
    pub fn token(&self, tenant: &str) -> String {
        let mut minted = self.minted.lock().unwrap();
        *minted += 1;
        let token = format!("remote-token-{minted}");
        self.workloads.lock().unwrap().insert(
            token.clone(),
            Principal {
                subject: format!("workload:{tenant}"),
                tenant: tenant.to_owned(),
                actions: ["*".to_owned()].into(),
            },
        );
        token
    }

    /// The custody client a backend of `tenant` uses, for observing what custody holds.
    pub fn client(&self, tenant: &str) -> Client {
        Client::with_http(http(), &self.origin, self.token(tenant)).unwrap()
    }

    pub fn backend(&self, tenant: &str) -> RemoteBackend {
        RemoteBackend::new(self.client(tenant))
    }

    /// Makes the database refuse every connection, so the store answers unavailable (503).
    pub async fn take_down(&self) {
        sqlx::query(&format!(
            "ALTER DATABASE {} WITH ALLOW_CONNECTIONS false",
            self.name
        ))
        .execute(&self.admin)
        .await
        .unwrap();
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
            .bind(&self.name)
            .execute(&self.admin)
            .await
            .unwrap();
    }

    pub async fn close(self) {
        self.server.abort();
        let _ = self.server.await;
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.name
        ))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

pub fn address(tenant: &str, namespace: &str, user: &str, name: &str) -> Address {
    Address::parse(tenant, namespace, user, name).unwrap()
}

pub fn target(tenant: &str, namespace: &str, user: &str, name: &str) -> Target {
    Target::unbound(address(tenant, namespace, user, name))
}

pub fn value(bytes: &[u8]) -> SecretValue {
    SecretValue::new(bytes.to_vec()).unwrap()
}

/// A tenant name no other test uses.
pub fn tenant() -> String {
    format!("t-{}", Uuid::now_v7().simple())
}
