use async_trait::async_trait;
use reqwest::{Certificate, Client};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
    pub tenant: String,
    pub actions: BTreeSet<String>,
}
impl Principal {
    pub fn permits(&self, action: &str) -> bool {
        self.actions.contains(action) || self.actions.contains("*")
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("authority unavailable")]
    Unavailable,
}

#[async_trait]
pub trait Authority: Send + Sync {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError>;
}

#[derive(Clone)]
pub struct IdentityAuthority {
    client: Client,
    endpoint: String,
    audience: String,
}

impl IdentityAuthority {
    pub fn new(origin: &str, audience: &str) -> Result<Self, AuthError> {
        let endpoint = format!("{}/v1/access/verify", origin.trim_end_matches('/'));
        Ok(Self {
            client: Client::builder()
                .build()
                .map_err(|_| AuthError::Unavailable)?,
            endpoint,
            audience: audience.into(),
        })
    }
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    token: &'a str,
    audience: &'a str,
}
#[derive(Deserialize)]
struct VerifyResponse {
    active: bool,
    subject: String,
    tenant: String,
    #[serde(default)]
    scopes: BTreeSet<String>,
}

#[async_trait]
impl Authority for IdentityAuthority {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let response = self
            .client
            .post(&self.endpoint)
            .json(&VerifyRequest {
                token,
                audience: &self.audience,
            })
            .send()
            .await
            .map_err(|_| AuthError::Unavailable)?;
        if response.status().as_u16() == 401 || response.status().as_u16() == 403 {
            return Err(AuthError::Unauthorized);
        }
        if !response.status().is_success() {
            return Err(AuthError::Unavailable);
        }
        let verified: VerifyResponse = response.json().await.map_err(|_| AuthError::Unavailable)?;
        if !verified.active || verified.subject.is_empty() || verified.tenant.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        Ok(Principal {
            subject: verified.subject,
            tenant: verified.tenant,
            actions: verified.scopes,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkloadGrant {
    pub subject: String,
    pub tenant: String,
    pub actions: BTreeSet<String>,
}

#[derive(Clone)]
pub struct KubernetesAuthority {
    client: Client,
    endpoint: String,
    audience: String,
    grants: Vec<WorkloadGrant>,
}

impl KubernetesAuthority {
    pub fn in_cluster(audience: &str, grants_path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| AuthError::Unavailable)?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS").unwrap_or_else(|_| "443".into());
        let ca = fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
            .map_err(|_| AuthError::Unavailable)?;
        let certificate = Certificate::from_pem(&ca).map_err(|_| AuthError::Unavailable)?;
        let grants: Vec<WorkloadGrant> =
            serde_json::from_slice(&fs::read(grants_path).map_err(|_| AuthError::Unavailable)?)
                .map_err(|_| AuthError::Unavailable)?;
        let client = Client::builder()
            .add_root_certificate(certificate)
            .build()
            .map_err(|_| AuthError::Unavailable)?;
        Ok(Self {
            client,
            endpoint: format!("https://{host}:{port}/apis/authentication.k8s.io/v1/tokenreviews"),
            audience: audience.into(),
            grants,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenReview<'a> {
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec<'a>,
}
#[derive(Serialize)]
struct TokenReviewSpec<'a> {
    token: &'a str,
    audiences: [&'a str; 1],
}
#[derive(Deserialize)]
struct TokenReviewResult {
    status: Option<TokenReviewStatus>,
}
#[derive(Deserialize)]
struct TokenReviewStatus {
    authenticated: Option<bool>,
    user: Option<TokenReviewUser>,
    #[serde(default)]
    audiences: Vec<String>,
}
#[derive(Deserialize)]
struct TokenReviewUser {
    username: String,
}

#[async_trait]
impl Authority for KubernetesAuthority {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let reviewer = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .map_err(|_| AuthError::Unavailable)?;
        let request = TokenReview {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token,
                audiences: [&self.audience],
            },
        };
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(reviewer.trim())
            .json(&request)
            .send()
            .await
            .map_err(|_| AuthError::Unavailable)?;
        if !response.status().is_success() {
            return Err(AuthError::Unavailable);
        }
        let result: TokenReviewResult =
            response.json().await.map_err(|_| AuthError::Unavailable)?;
        let status = result.status.ok_or(AuthError::Unauthorized)?;
        if status.authenticated != Some(true)
            || !status.audiences.iter().any(|a| a == &self.audience)
        {
            return Err(AuthError::Unauthorized);
        }
        let subject = status.user.ok_or(AuthError::Unauthorized)?.username;
        let grant = self
            .grants
            .iter()
            .find(|grant| grant.subject == subject)
            .ok_or(AuthError::Unauthorized)?;
        Ok(Principal {
            subject,
            tenant: grant.tenant.clone(),
            actions: grant.actions.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permissions_are_exact() {
        let p = Principal {
            subject: "s".into(),
            tenant: "t".into(),
            actions: BTreeSet::from(["secret:read".into()]),
        };
        assert!(p.permits("secret:read"));
        assert!(!p.permits("secret:write"));
    }
}
