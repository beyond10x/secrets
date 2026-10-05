//! A recording fake backend for tests of what sits above the port: mount routing, the local
//! authorizer and the CLI. Enabled by the `testing` feature; never part of a build that ships.
//!
//! It records which operation was asked for which address, and never a value. It is either
//! read-write, holding values in memory by address, or read-only, answering only a bound locator
//! from values preloaded with [`RecordingBackend::preload`]. It can be told to answer
//! [`StorageError::Unavailable`] to every call, which it still records.
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;

use super::{
    Address, Capability, Locator, Revealed, Scope, SecretMetadata, SecretName, SecretStorage,
    SecretValue, StorageError, Target, Version, Written,
};

/// What a [`RecordingBackend`] was asked, without the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Read(Address),
    Write(Address),
    Delete(Address),
    Rename(Address, SecretName),
    List(Scope),
}

/// How a [`RecordingBackend`] behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Read, write, delete and list, by address; no binding needed.
    ReadWrite,
    /// Read only, and only through a bound locator.
    ReadOnlyBound,
}

struct Held {
    value: SecretValue,
    version: Version,
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    by_address: BTreeMap<Address, Held>,
    by_locator: BTreeMap<Locator, Held>,
    writes: u64,
}

pub struct RecordingBackend {
    mode: Mode,
    unavailable: AtomicBool,
    state: Mutex<State>,
}

impl RecordingBackend {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            unavailable: AtomicBool::new(false),
            state: Mutex::new(State::default()),
        }
    }

    pub fn read_write() -> Self {
        Self::new(Mode::ReadWrite)
    }

    pub fn read_only_bound() -> Self {
        Self::new(Mode::ReadOnlyBound)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// From now on, answer every call [`StorageError::Unavailable`] (or stop doing so).
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// Holds `value` behind `locator`, as an external store a read-only backend reads would. Not
    /// recorded as a call.
    ///
    /// # Errors
    /// [`StorageError::Unavailable`] if the state lock is poisoned.
    pub fn preload(&self, locator: Locator, value: SecretValue) -> Result<(), StorageError> {
        let mut state = self.lock()?;
        state.writes += 1;
        let version = Version::new(format!("v{}", state.writes));
        state.by_locator.insert(locator, Held { value, version });
        Ok(())
    }

    /// Every call so far, oldest first.
    pub fn calls(&self) -> Vec<Call> {
        self.state
            .lock()
            .map(|state| state.calls.clone())
            .unwrap_or_default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, StorageError> {
        self.state.lock().map_err(|_| StorageError::Unavailable)
    }

    /// Records the call, then refuses it if the backend is down.
    fn enter(&self, call: Call) -> Result<std::sync::MutexGuard<'_, State>, StorageError> {
        let mut state = self.lock()?;
        state.calls.push(call);
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        Ok(state)
    }

    fn writable(&self) -> Result<(), StorageError> {
        match self.mode {
            Mode::ReadWrite => Ok(()),
            Mode::ReadOnlyBound => Err(StorageError::Unsupported),
        }
    }
}

fn copy(value: &SecretValue) -> Result<SecretValue, StorageError> {
    SecretValue::new(value.expose().to_vec())
}

#[async_trait]
impl SecretStorage for RecordingBackend {
    fn capabilities(&self) -> &[Capability] {
        match self.mode {
            Mode::ReadWrite => &Capability::ALL,
            Mode::ReadOnlyBound => &[Capability::Read],
        }
    }

    fn requires_binding(&self) -> bool {
        self.mode == Mode::ReadOnlyBound
    }

    async fn read(&self, target: &Target) -> Result<Revealed, StorageError> {
        let state = self.enter(Call::Read(target.address.clone()))?;
        let held = match self.mode {
            Mode::ReadWrite => state.by_address.get(&target.address),
            Mode::ReadOnlyBound => target
                .locator
                .as_ref()
                .and_then(|locator| state.by_locator.get(locator)),
        }
        .ok_or(StorageError::NotFound)?;
        Ok(Revealed {
            value: copy(&held.value)?,
            version: Some(held.version.clone()),
        })
    }

    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        let mut state = self.enter(Call::Write(target.address.clone()))?;
        self.writable()?;
        state.writes += 1;
        let version = Version::new(format!("v{}", state.writes));
        let replaced = state
            .by_address
            .insert(
                target.address.clone(),
                Held {
                    value,
                    version: version.clone(),
                },
            )
            .is_some();
        Ok(if replaced {
            Written::Replaced(Some(version))
        } else {
            Written::Created(Some(version))
        })
    }

    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        let mut state = self.enter(Call::Delete(target.address.clone()))?;
        self.writable()?;
        state
            .by_address
            .remove(&target.address)
            .map(drop)
            .ok_or(StorageError::NotFound)
    }

    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        let mut state = self.enter(Call::Rename(target.address.clone(), new_name.clone()))?;
        self.writable()?;
        let to = Address {
            scope: target.address.scope.clone(),
            name: new_name.clone(),
        };
        if state.by_address.contains_key(&to) {
            return Err(StorageError::Conflict);
        }
        let held = state
            .by_address
            .remove(&target.address)
            .ok_or(StorageError::NotFound)?;
        state.by_address.insert(to, held);
        Ok(())
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        let state = self.enter(Call::List(scope.clone()))?;
        self.writable()?;
        Ok(state
            .by_address
            .iter()
            .filter(|(address, _)| &address.scope == scope)
            .map(|(address, held)| SecretMetadata {
                address: address.clone(),
                version: Some(held.version.clone()),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(name: &str) -> Result<Address, StorageError> {
        Ok(Address::parse("default", "default", "default", name)?)
    }

    fn value(bytes: &[u8]) -> Result<SecretValue, StorageError> {
        SecretValue::new(bytes.to_vec())
    }

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

    #[test]
    fn read_write_round_trips_and_records_no_value() -> Result<(), StorageError> {
        let backend = RecordingBackend::read_write();
        let target = Target::unbound(address("openai")?);
        let first = block(backend.write(&target, value(b"marker-value")?))?;
        assert!(matches!(first, Written::Created(Some(_))));
        let second = block(backend.write(&target, value(b"marker-value-2")?))?;
        assert!(matches!(second, Written::Replaced(Some(_))));
        assert_ne!(first, second);
        let read = block(backend.read(&target))?;
        assert_eq!(read.value.expose(), b"marker-value-2");
        let listed = block(backend.list(&Scope::local()))?;
        assert_eq!(listed.len(), 1);
        let new_name = SecretName::parse("openai-work")?;
        block(backend.rename(&target, &new_name))?;
        assert!(matches!(
            block(backend.read(&target)),
            Err(StorageError::NotFound)
        ));
        let moved = Target::unbound(address("openai-work")?);
        block(backend.delete(&moved))?;
        assert_eq!(block(backend.delete(&moved)), Err(StorageError::NotFound));
        let calls = backend.calls();
        assert_eq!(calls.len(), 8);
        assert!(!format!("{calls:?}").contains("marker-value"));
        Ok(())
    }

    #[test]
    fn read_only_needs_a_bound_locator_and_refuses_every_write() -> Result<(), StorageError> {
        let backend = RecordingBackend::read_only_bound();
        assert!(backend.requires_binding());
        assert_eq!(backend.capabilities(), &[Capability::Read]);
        let locator = Locator::new("op://vault/item/field");
        backend.preload(locator.clone(), value(b"bound")?)?;
        let unbound = Target::unbound(address("openai")?);
        assert!(matches!(
            block(backend.read(&unbound)),
            Err(StorageError::NotFound)
        ));
        let bound = Target {
            address: address("openai")?,
            locator: Some(locator),
        };
        assert_eq!(block(backend.read(&bound))?.value.expose(), b"bound");
        assert!(matches!(
            block(backend.write(&bound, value(b"x")?)),
            Err(StorageError::Unsupported)
        ));
        assert_eq!(
            block(backend.delete(&bound)),
            Err(StorageError::Unsupported)
        );
        assert!(matches!(
            block(backend.list(&Scope::local())),
            Err(StorageError::Unsupported)
        ));
        assert_eq!(backend.calls().len(), 5);
        Ok(())
    }

    #[test]
    fn a_forced_fault_is_unavailable_and_still_recorded() -> Result<(), StorageError> {
        let backend = RecordingBackend::read_write();
        backend.set_unavailable(true);
        let target = Target::unbound(address("openai")?);
        assert!(matches!(
            block(backend.write(&target, value(b"x")?)),
            Err(StorageError::Unavailable)
        ));
        assert!(matches!(
            block(backend.read(&target)),
            Err(StorageError::Unavailable)
        ));
        assert_eq!(backend.calls().len(), 2);
        backend.set_unavailable(false);
        assert!(matches!(
            block(backend.read(&target)),
            Err(StorageError::NotFound)
        ));
        Ok(())
    }
}
