use reqwest::{Client as HttpClient, StatusCode};
use secrets_core::{Mutation, PutSecret, SecretMetadata, SecretRef, StoredSecret};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct Client {
    http: HttpClient,
    origin: Url,
    token: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("request failed")]
    Transport,
    #[error("not found")]
    NotFound,
    #[error("request refused")]
    Refused,
    #[error("service failed")]
    Service,
}

#[derive(Serialize)]
struct DeleteRequest<'a> {
    reference: &'a SecretRef,
    actor: &'a str,
}
#[derive(Serialize)]
struct PrepareRequest<'a> {
    actor: &'a str,
    mutations: &'a [Mutation],
}
#[derive(Deserialize)]
struct ExistsResponse {
    exists: bool,
}
#[derive(Serialize)]
struct ScopeRequest<'a> {
    tenant: &'a str,
    namespace: &'a str,
}
#[derive(Deserialize)]
struct ListResponse {
    secrets: Vec<SecretMetadata>,
}

impl Client {
    pub fn new(origin: &str, token: impl Into<String>) -> Result<Self, Error> {
        let origin = Url::parse(origin).map_err(|_| Error::Transport)?;
        Ok(Self {
            http: HttpClient::new(),
            origin,
            token: token.into(),
        })
    }
    pub async fn put(&self, input: &PutSecret) -> Result<SecretMetadata, Error> {
        self.json(self.http.put(self.url("v1/workload/secrets")?).json(input))
            .await
    }
    pub async fn get(&self, reference: &SecretRef) -> Result<StoredSecret, Error> {
        self.json(
            self.http
                .post(self.url("v1/workload/secrets:get")?)
                .json(reference),
        )
        .await
    }
    pub async fn exists(&self, reference: &SecretRef) -> Result<bool, Error> {
        Ok(self
            .json::<ExistsResponse>(
                self.http
                    .post(self.url("v1/workload/secrets:exists")?)
                    .json(reference),
            )
            .await?
            .exists)
    }
    pub async fn references(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> Result<Vec<SecretMetadata>, Error> {
        Ok(self
            .json::<ListResponse>(
                self.http
                    .post(self.url("v1/workload/secrets:list")?)
                    .json(&ScopeRequest { tenant, namespace }),
            )
            .await?
            .secrets)
    }
    pub async fn delete(&self, reference: &SecretRef, actor: &str) -> Result<(), Error> {
        self.empty(
            self.http
                .post(self.url("v1/workload/secrets:delete")?)
                .json(&DeleteRequest { reference, actor }),
        )
        .await
    }
    pub async fn prepare(
        &self,
        tenant: &str,
        transaction: Uuid,
        actor: &str,
        mutations: &[Mutation],
    ) -> Result<(), Error> {
        self.empty(
            self.http
                .put(self.url(&format!(
                    "v1/workload/tenants/{tenant}/transactions/{transaction}"
                ))?)
                .json(&PrepareRequest { actor, mutations }),
        )
        .await
    }
    pub async fn commit(&self, tenant: &str, transaction: Uuid) -> Result<(), Error> {
        self.empty(self.http.post(self.url(&format!(
            "v1/workload/tenants/{tenant}/transactions/{transaction}:commit"
        ))?))
        .await
    }
    pub async fn abort(&self, tenant: &str, transaction: Uuid) -> Result<(), Error> {
        self.empty(self.http.post(self.url(&format!(
            "v1/workload/tenants/{tenant}/transactions/{transaction}:abort"
        ))?))
        .await
    }
    async fn json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, Error> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        classify(response.status())?;
        response.json().await.map_err(|_| Error::Service)
    }
    async fn empty(&self, request: reqwest::RequestBuilder) -> Result<(), Error> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        classify(response.status())
    }
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.origin.join(path).map_err(|_| Error::Transport)
    }
}

fn classify(status: StatusCode) -> Result<(), Error> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::NOT_FOUND {
        Err(Error::NotFound)
    } else if status.is_client_error() {
        Err(Error::Refused)
    } else {
        Err(Error::Service)
    }
}
