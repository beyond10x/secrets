//! The authorizer of `secrets.storage`: every command is decided on its scope and its
//! [`Action`] before any backend is reached, as `spec/domains/storage.yaml` declares.
//!
//! Only the local authorizer exists ([`LocalAuthorizer`]). Local mode has one tenant and one user,
//! both `default`; every action is allowed for them in any namespace, and every other scope is
//! refused with [`StorageError::Denied`].
//!
//! # What is checked, per command
//!
//! * The namespace commands (`AddNamespace`, `RemoveNamespace`, `SetMount`) name a
//!   [`NamespaceKey`] and check the tenant only: [`Resource::Namespace`], the spec's `denied`.
//! * The secret commands (`Bind`, `Unbind`, `Write`, `Read`, `Delete`, `Rename`, `ListMetadata`)
//!   name a [`Scope`] and check the tenant, then the user: [`Resource::Scope`], the spec's
//!   `denied` and then `denied-user`.
//!
//! The decision works on the raw tenant and user text, so a caller can ask before it validates a
//! name: the specification decides the authorizer first, and a denied caller learns nothing about
//! a name. A refusal is the closed code [`StorageError::Denied`] and carries no part of the
//! request; [`Denial`] says which check refused, for a caller that has to tell the two outcomes
//! apart.
//!
//! [`Authorized`] puts an authorizer in front of any [`SecretStorage`], so a denied scope never
//! reaches the backend below it.
use std::fmt;

use async_trait::async_trait;

use crate::storage::{
    Action, Address, Capability, NamespaceKey, Revealed, Scope, ScopeName, SecretMetadata,
    SecretName, SecretStorage, SecretValue, StorageError, Target, Written,
};

/// What a command is decided on: the part of its scope the specification's guards read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resource<'a> {
    /// A namespace command: the tenant alone.
    Namespace { tenant: &'a str },
    /// A secret command: the tenant, then the user. The namespace is not consulted.
    Scope { tenant: &'a str, user: &'a str },
}

impl<'a> Resource<'a> {
    /// The resource of a namespace command.
    pub fn namespace(key: &'a NamespaceKey) -> Self {
        Self::Namespace {
            tenant: key.tenant.as_str(),
        }
    }

    /// The resource of a secret command addressed by scope (`ListMetadata`).
    pub fn scope(scope: &'a Scope) -> Self {
        Self::Scope {
            tenant: scope.tenant.as_str(),
            user: scope.user.as_str(),
        }
    }

    /// The resource of a secret command addressed by address.
    pub fn address(address: &'a Address) -> Self {
        Self::scope(&address.scope)
    }
}

/// Which check refused. To a caller of the port every denial is [`StorageError::Denied`]; none
/// carries any part of the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Denial {
    /// The tenant is not admitted: the specification's `denied` outcome.
    Tenant,
    /// The tenant is admitted and the user is not: the specification's `denied-user` outcome.
    User,
}

impl Denial {
    /// The outcome name the specification gives this refusal.
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::Tenant => "denied",
            Self::User => "denied-user",
        }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(StorageError::Denied.code())
    }
}

impl std::error::Error for Denial {}

impl From<Denial> for StorageError {
    fn from(_: Denial) -> Self {
        Self::Denied
    }
}

/// Decides every storage command before any backend call.
pub trait Authorizer: Send + Sync {
    /// Whether `action` is allowed on `resource`, and if not, which check refused.
    ///
    /// # Errors
    /// The [`Denial`] that refused.
    fn decide(&self, resource: Resource<'_>, action: Action) -> Result<(), Denial>;

    /// [`Authorizer::decide`] as the port's refusal.
    ///
    /// # Errors
    /// [`StorageError::Denied`] for every denial.
    fn authorize(&self, resource: Resource<'_>, action: Action) -> Result<(), StorageError> {
        self.decide(resource, action).map_err(StorageError::from)
    }
}

/// Local mode: tenant `default` and user `default` may do every action in any namespace; every
/// other tenant or user is denied. A pure function of the resource and the action: it holds no
/// state, reaches no backend and does no I/O.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LocalAuthorizer;

impl Authorizer for LocalAuthorizer {
    fn decide(&self, resource: Resource<'_>, _action: Action) -> Result<(), Denial> {
        // Every action gets the same answer under the local authorizer (storage.yaml, `Action`).
        let (tenant, user) = match resource {
            Resource::Namespace { tenant } => (tenant, None),
            Resource::Scope { tenant, user } => (tenant, Some(user)),
        };
        if tenant != ScopeName::DEFAULT {
            return Err(Denial::Tenant);
        }
        match user {
            Some(user) if user != ScopeName::DEFAULT => Err(Denial::User),
            _ => Ok(()),
        }
    }
}

/// A [`SecretStorage`] whose every operation is authorized before the storage below is called.
///
/// The action per operation is the specification's: `read` read, `write` write, `delete` delete,
/// `rename` write and then delete, `list` list. A denied operation returns
/// [`StorageError::Denied`] and never calls the storage below.
pub struct Authorized<S, A = LocalAuthorizer> {
    inner: S,
    authorizer: A,
}

impl<S: SecretStorage> Authorized<S> {
    /// `inner` behind the [`LocalAuthorizer`].
    pub fn local(inner: S) -> Self {
        Self::new(inner, LocalAuthorizer)
    }
}

impl<S: SecretStorage, A: Authorizer> Authorized<S, A> {
    pub fn new(inner: S, authorizer: A) -> Self {
        Self { inner, authorizer }
    }

    /// The storage below the authorizer.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn authorizer(&self) -> &A {
        &self.authorizer
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    fn check(&self, target: &Target, action: Action) -> Result<(), StorageError> {
        self.authorizer
            .authorize(Resource::address(&target.address), action)
    }
}

#[async_trait]
impl<S: SecretStorage, A: Authorizer> SecretStorage for Authorized<S, A> {
    fn capabilities(&self) -> &[Capability] {
        self.inner.capabilities()
    }

    fn requires_binding(&self) -> bool {
        self.inner.requires_binding()
    }

    async fn read(&self, target: &Target) -> Result<Revealed, StorageError> {
        self.check(target, Action::Read)?;
        self.inner.read(target).await
    }

    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        self.check(target, Action::Write)?;
        self.inner.write(target, value).await
    }

    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        self.check(target, Action::Delete)?;
        self.inner.delete(target).await
    }

    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        self.check(target, Action::Write)?;
        self.check(target, Action::Delete)?;
        self.inner.rename(target, new_name).await
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        self.authorizer
            .authorize(Resource::scope(scope), Action::List)?;
        self.inner.list(scope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: LocalAuthorizer = LocalAuthorizer;

    fn scope(tenant: &str, namespace: &str, user: &str) -> Result<Scope, StorageError> {
        Ok(Scope {
            tenant: ScopeName::parse(tenant)?,
            namespace: ScopeName::parse(namespace)?,
            user: ScopeName::parse(user)?,
        })
    }

    // Story scenario: "every action is allowed for tenant `default` and user `default` in any
    // namespace".
    #[test]
    fn every_action_is_allowed_for_tenant_and_user_default_in_any_namespace()
    -> Result<(), StorageError> {
        for namespace in ["default", "work", "team.a-1"] {
            let scope = scope("default", namespace, "default")?;
            let key = NamespaceKey::parse("default", namespace)?;
            for action in Action::ALL {
                assert_eq!(LOCAL.decide(Resource::scope(&scope), action), Ok(()));
                assert_eq!(LOCAL.authorize(Resource::scope(&scope), action), Ok(()));
                assert_eq!(LOCAL.decide(Resource::namespace(&key), action), Ok(()));
            }
        }
        Ok(())
    }

    // Story scenario: "a second tenant is denied by name" (spec outcome `denied`, every command).
    #[test]
    fn a_second_tenant_is_denied_for_every_action() -> Result<(), StorageError> {
        for tenant in ["acme", "defaults", "default2", "d"] {
            let scope = scope(tenant, "default", "default")?;
            let key = NamespaceKey::parse(tenant, "default")?;
            for action in Action::ALL {
                assert_eq!(
                    LOCAL.decide(Resource::scope(&scope), action),
                    Err(Denial::Tenant)
                );
                assert_eq!(
                    LOCAL.authorize(Resource::scope(&scope), action),
                    Err(StorageError::Denied)
                );
                assert_eq!(
                    LOCAL.authorize(Resource::namespace(&key), action),
                    Err(StorageError::Denied)
                );
            }
        }
        Ok(())
    }

    // Story scenario: "a second user is denied by name" (spec outcome `denied-user`, secret
    // commands).
    #[test]
    fn a_second_user_in_tenant_default_is_denied_for_every_action() -> Result<(), StorageError> {
        for user in ["alice", "defaults", "root"] {
            let scope = scope("default", "default", user)?;
            for action in Action::ALL {
                assert_eq!(
                    LOCAL.decide(Resource::scope(&scope), action),
                    Err(Denial::User)
                );
                assert_eq!(
                    LOCAL.authorize(Resource::scope(&scope), action),
                    Err(StorageError::Denied)
                );
            }
        }
        Ok(())
    }

    // Spec: the tenant is checked first, so a second tenant with a second user is `denied`, not
    // `denied-user` (their guards are disjoint).
    #[test]
    fn the_tenant_is_decided_before_the_user() -> Result<(), StorageError> {
        let scope = scope("acme", "default", "alice")?;
        assert_eq!(
            LOCAL.decide(Resource::scope(&scope), Action::Read),
            Err(Denial::Tenant)
        );
        assert_eq!(Denial::Tenant.outcome(), "denied");
        assert_eq!(Denial::User.outcome(), "denied-user");
        Ok(())
    }

    // Spec: the namespace commands check the tenant only; the namespace itself is never decided.
    #[test]
    fn a_namespace_command_checks_the_tenant_only() -> Result<(), StorageError> {
        let key = NamespaceKey::parse("default", "other")?;
        assert_eq!(
            LOCAL.decide(Resource::namespace(&key), Action::ManageNamespace),
            Ok(())
        );
        let key = NamespaceKey::parse("acme", "default")?;
        assert_eq!(
            LOCAL.decide(Resource::namespace(&key), Action::ManageNamespace),
            Err(Denial::Tenant)
        );
        Ok(())
    }

    // Spec precedence (DECIDED 2026-09-27): the authorizer decides before any name rule, so it
    // must answer for text that is not a valid scope name.
    #[test]
    fn the_decision_needs_no_valid_name() {
        let long = "a".repeat(65);
        assert_eq!(
            LOCAL.decide(
                Resource::Namespace { tenant: &long },
                Action::ManageNamespace
            ),
            Err(Denial::Tenant)
        );
        assert_eq!(
            LOCAL.decide(
                Resource::Scope {
                    tenant: "default",
                    user: "-bad"
                },
                Action::Write
            ),
            Err(Denial::User)
        );
        assert_eq!(
            LOCAL.decide(
                Resource::Scope {
                    tenant: "Default",
                    user: "default"
                },
                Action::Write
            ),
            Err(Denial::Tenant)
        );
    }

    // Spec: a refusal is the closed code `denied` and nothing else.
    #[test]
    fn a_denial_is_the_closed_code_denied_and_repeats_nothing() -> Result<(), StorageError> {
        let scope = scope("leak-marker", "default", "leak-marker")?;
        let denial = LOCAL
            .decide(Resource::scope(&scope), Action::Read)
            .err()
            .ok_or(StorageError::Conflict)?;
        for denial in [denial, Denial::User] {
            assert_eq!(StorageError::from(denial), StorageError::Denied);
            assert_eq!(denial.to_string(), "denied");
            assert!(!format!("{denial} {denial:?}").contains("leak-marker"));
        }
        Ok(())
    }

    #[cfg(feature = "testing")]
    mod wrapped {
        use super::*;
        use crate::storage::testing::{Call, RecordingBackend};

        fn block<F: std::future::Future>(future: F) -> F::Output {
            // Every future here completes on its first poll: the fake never waits.
            let waker = std::task::Waker::noop();
            let mut context = std::task::Context::from_waker(waker);
            let mut future = std::pin::pin!(future);
            loop {
                if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
                    return output;
                }
            }
        }

        fn target(tenant: &str, user: &str, name: &str) -> Result<Target, StorageError> {
            Ok(Target::unbound(Address::parse(
                tenant, "default", user, name,
            )?))
        }

        /// Every operation of the port against `target`, each answer in order.
        fn every_operation(
            storage: &Authorized<RecordingBackend>,
            target: &Target,
        ) -> Result<Vec<Option<StorageError>>, StorageError> {
            let new_name = SecretName::parse("renamed")?;
            Ok(vec![
                block(storage.write(target, SecretValue::new(b"marker-value".to_vec())?)).err(),
                block(storage.read(target)).err(),
                block(storage.list(&target.address.scope)).err(),
                block(storage.rename(target, &new_name)).err(),
                block(storage.delete(&Target::unbound(Address {
                    scope: target.address.scope.clone(),
                    name: new_name,
                })))
                .err(),
            ])
        }

        // Story scenario: "every action is allowed for tenant `default` and user `default` in
        // any namespace", through the wrapper: each operation reaches the backend.
        #[test]
        fn the_local_scope_reaches_the_backend_for_every_operation() -> Result<(), StorageError> {
            for namespace in ["default", "work"] {
                let storage = Authorized::local(RecordingBackend::read_write());
                let target =
                    Target::unbound(Address::parse("default", namespace, "default", "openai")?);
                let answers = every_operation(&storage, &target)?;
                assert_eq!(answers, vec![None; 5]);
                let calls = storage.inner().calls();
                assert_eq!(calls.len(), 5);
                assert!(matches!(calls[0], Call::Write(_)));
                assert!(matches!(calls[3], Call::Rename(_, _)));
            }
            Ok(())
        }

        // Story scenario: "a second tenant is denied by name before any backend is reached".
        #[test]
        fn a_second_tenant_is_denied_before_any_backend_is_reached() -> Result<(), StorageError> {
            let storage = Authorized::local(RecordingBackend::read_write());
            let answers = every_operation(&storage, &target("acme", "default", "openai")?)?;
            assert_eq!(answers, vec![Some(StorageError::Denied); 5]);
            assert_eq!(storage.inner().calls(), Vec::new());
            Ok(())
        }

        // Story scenario: "a second user is denied by name before any backend is reached".
        #[test]
        fn a_second_user_is_denied_before_any_backend_is_reached() -> Result<(), StorageError> {
            let storage = Authorized::local(RecordingBackend::read_write());
            let answers = every_operation(&storage, &target("default", "alice", "openai")?)?;
            assert_eq!(answers, vec![Some(StorageError::Denied); 5]);
            assert_eq!(storage.inner().calls(), Vec::new());
            Ok(())
        }

        // A denial wins over the backend's own answer: a faulted backend is not even asked.
        #[test]
        fn a_denial_is_decided_before_a_backend_fault() -> Result<(), StorageError> {
            let storage = Authorized::local(RecordingBackend::read_write());
            storage.inner().set_unavailable(true);
            let denied = target("acme", "default", "openai")?;
            assert!(matches!(
                block(storage.read(&denied)),
                Err(StorageError::Denied)
            ));
            assert!(storage.inner().calls().is_empty());
            let local = target("default", "default", "openai")?;
            assert!(matches!(
                block(storage.read(&local)),
                Err(StorageError::Unavailable)
            ));
            assert_eq!(storage.inner().calls().len(), 1);
            Ok(())
        }

        #[test]
        fn the_wrapper_reports_the_backend_s_capabilities() {
            let storage = Authorized::local(RecordingBackend::read_only_bound());
            assert_eq!(storage.capabilities(), &[Capability::Read]);
            assert!(storage.requires_binding());
        }
    }
}
