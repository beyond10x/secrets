//! The shared conformance target. It owns scenario isolation, the forced-outcome control, the
//! consistency token and event attribution, and it dispatches every command and view to the one
//! domain module that answers it — so a later domain is a new module and one entry in [`DOMAINS`],
//! not an edit to a shared function.
//!
//! Only returned production facts are retained. This target never reads the suite, its expected
//! assertions, or a scenario name to determine an answer.
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    error::Error,
};

use ess_conformance::{
    scenario::OutcomeRef,
    target::{
        ConformanceTarget, DeclaredErrorValue, EventObservationRequest, ExternalOutcomeControl,
        ImplementationIdentity, ObservedEvent, RedeliveryRequest, ScenarioContext,
        SemanticCommandRequest, SemanticCommandResult, SemanticViewRequest, SemanticViewResult,
        TargetError, ViewRow,
    },
};
use ess_primitives::{consistency::ConsistencyToken, node::Node};

use crate::fixture::{Admin, Scenario};

/// What a domain module observed of one command: the declared branch the real service took, the
/// declared error it carries, and the events its durable records show it produced.
pub struct Observed {
    pub outcome: Option<String>,
    pub error: Option<&'static str>,
    pub events: Vec<(&'static str, BTreeMap<String, Node>)>,
}

/// What a domain module is handed for one command or read.
pub struct Context<'a> {
    pub runtime: &'a tokio::runtime::Runtime,
    pub admin: &'a Admin,
    pub scenario: &'a mut Scenario,
    /// The outcome the scenario forced for this invocation, when it forced one.
    pub forced: Option<String>,
}

/// A domain's answer to a command: `None` when the domain does not own it.
pub type CommandAnswer =
    fn(&mut Context<'_>, &str, &BTreeMap<String, Node>) -> Option<Result<Observed, TargetError>>;
/// A domain's answer to a read: `None` when the domain does not own the view.
pub type ViewAnswer = fn(&mut Context<'_>, &str) -> Option<Result<Vec<ViewRow>, TargetError>>;

/// One domain's answers.
pub struct Domain {
    pub command: CommandAnswer,
    pub view: ViewAnswer,
}

const DOMAINS: &[Domain] = &[crate::custody::DOMAIN];

pub fn unavailable(operation: &str, error: impl std::fmt::Display) -> TargetError {
    TargetError::unavailable(operation, error.to_string())
}
fn unsupported(what: &str) -> TargetError {
    TargetError::unsupported(what, "no domain module of this target answers it")
}

pub struct SecretsTarget {
    version: String,
    runtime: tokio::runtime::Runtime,
    admin: Admin,
    scenario: RefCell<Option<Scenario>>,
    forced: RefCell<Option<OutcomeRef>>,
    token: RefCell<Option<ConsistencyToken>>,
    sequence: Cell<u64>,
}

impl SecretsTarget {
    pub fn new(version: String, database_url: &str) -> Result<Self, Box<dyn Error>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let admin = runtime.block_on(Admin::connect(database_url))?;
        Ok(Self {
            version,
            runtime,
            admin,
            scenario: RefCell::new(None),
            forced: RefCell::new(None),
            token: RefCell::new(None),
            sequence: Cell::new(0),
        })
    }

    fn close(&self) -> Result<(), TargetError> {
        self.forced.replace(None);
        self.token.replace(None);
        if let Some(scenario) = self.scenario.replace(None) {
            self.runtime
                .block_on(self.admin.close(scenario))
                .map_err(|error| unavailable("dropping the scenario database", error))?;
        }
        Ok(())
    }
}

impl ConformanceTarget for SecretsTarget {
    fn identity(&self) -> Result<ImplementationIdentity, TargetError> {
        Ok(ImplementationIdentity::new(
            "secrets-service",
            &self.version,
        ))
    }
    fn begin_scenario(&self, _: &ScenarioContext) -> Result<(), TargetError> {
        self.close()?;
        let scenario = self
            .runtime
            .block_on(self.admin.open())
            .map_err(|error| unavailable("creating the scenario database", error))?;
        self.scenario.replace(Some(scenario));
        Ok(())
    }
    fn end_scenario(&self, _: &ScenarioContext) -> Result<(), TargetError> {
        self.close()
    }
    fn execute_command(
        &self,
        request: SemanticCommandRequest,
    ) -> Result<SemanticCommandResult, TargetError> {
        let command = request.command.to_string();
        let forced = {
            let mut slot = self.forced.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|force| force.command == request.command)
            {
                slot.take().map(|force| force.outcome.to_string())
            } else {
                None
            }
        };
        let mut scenario = self.scenario.borrow_mut();
        let scenario = scenario
            .as_mut()
            .ok_or_else(|| unavailable("executing a command", "no scenario is open"))?;
        let mut context = Context {
            runtime: &self.runtime,
            admin: &self.admin,
            scenario,
            forced,
        };
        let observed = DOMAINS
            .iter()
            .find_map(|domain| (domain.command)(&mut context, &command, &request.input))
            .ok_or_else(|| unsupported(&command))??;
        let mut result = match observed.outcome {
            Some(outcome) => SemanticCommandResult::took(OutcomeRef::new(
                request.command.clone(),
                outcome
                    .parse()
                    .map_err(|error| unavailable("naming the outcome", error))?,
            )),
            None => SemanticCommandResult::undeclared(),
        };
        if let Some(error) = observed.error {
            result = result.with_error(DeclaredErrorValue::new(
                error
                    .parse()
                    .map_err(|error| unavailable("naming the error", error))?,
            ));
        }
        for (event, payload) in observed.events {
            let mut occurrence = ObservedEvent::new(
                event
                    .parse()
                    .map_err(|error| unavailable("naming the event", error))?,
            )
            .in_activity(request.correlation.clone());
            occurrence.payload = payload;
            result = result.emitting(occurrence);
        }
        let sequence = self
            .sequence
            .get()
            .checked_add(1)
            .ok_or_else(|| unavailable("minting a consistency token", "sequence exhausted"))?;
        self.sequence.set(sequence);
        let token = ConsistencyToken::new(format!("{}:{sequence}", request.correlation))
            .map_err(|error| unavailable("minting a consistency token", error))?;
        self.token.replace(Some(token.clone()));
        Ok(result.with_consistency(token))
    }
    fn query_view(&self, request: SemanticViewRequest) -> Result<SemanticViewResult, TargetError> {
        let view = request.view.to_string();
        if !request.params.is_empty() {
            return Err(unsupported(&view));
        }
        // Every read goes to the service after the write it follows has returned, so the only
        // token this target can be asked to honour is the one it last issued.
        if request
            .consistency
            .token()
            .is_some_and(|token| Some(token) != self.token.borrow().as_ref())
        {
            return Err(unavailable(
                "reading a view",
                "the requested consistency token was not issued in this scenario",
            ));
        }
        let mut scenario = self.scenario.borrow_mut();
        let scenario = scenario
            .as_mut()
            .ok_or_else(|| unavailable("reading a view", "no scenario is open"))?;
        let mut context = Context {
            runtime: &self.runtime,
            admin: &self.admin,
            scenario,
            forced: None,
        };
        let rows = DOMAINS
            .iter()
            .find_map(|domain| (domain.view)(&mut context, &view))
            .ok_or_else(|| unsupported(&view))??;
        Ok(SemanticViewResult::of(rows))
    }
    fn observe_events(
        &self,
        _: EventObservationRequest,
    ) -> Result<Vec<ObservedEvent>, TargetError> {
        Err(TargetError::unsupported(
            "asynchronous events",
            "the service publishes no events; every event is its command's own durable record",
        ))
    }
    fn configure_external_outcome(
        &self,
        control: ExternalOutcomeControl,
    ) -> Result<(), TargetError> {
        self.forced.replace(Some(control.force));
        Ok(())
    }
    fn redeliver_event(&self, _: RedeliveryRequest) -> Result<(), TargetError> {
        Err(TargetError::unsupported(
            "redelivering an event",
            "the service declares no binding",
        ))
    }
}
