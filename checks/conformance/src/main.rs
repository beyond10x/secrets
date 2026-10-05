mod cli;
mod custody;
mod fixture;
mod gate;
mod storage;
mod target;

use ess_conformance::{
    AdmittedSuite, Clock, CountReport, CountRun, CountStatus, Ids, Runner, RunnerConfig,
};
use ess_primitives::time::Timestamp;
use serde::Deserialize;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// Evidence carries the real observation time; elapsed time is monotonic even when the wall clock
/// adjusts.
struct EvidenceClock {
    epoch_ms: u64,
    started: Instant,
}
impl Clock for EvidenceClock {
    fn now(&mut self) -> Timestamp {
        Timestamp::from_epoch_millis(
            self.epoch_ms.saturating_add(
                u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    answered_floor: u64,
    total_floor: u64,
    skipped_ceiling: u64,
    /// How many scenarios may answer `unsupported`: those that need an implementation this
    /// repository does not have yet. Absent is zero.
    #[serde(default)]
    unsupported_ceiling: u64,
}

#[derive(clap::Parser)]
#[command(name = "secrets-conformance")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// Check ESS projection drift and run the suite three times against the baseline.
    Check,
    /// Run one suite against a baseline and write its report.
    Run {
        /// The component the suite was synthesized for.
        #[arg(long, value_enum, default_value = "secrets-service")]
        component: target::Component,
        suite: PathBuf,
        baseline: PathBuf,
        output_dir: PathBuf,
        source_identity: String,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    match <Cli as clap::Parser>::parse().command {
        Cmd::Check => gate::check(),
        Cmd::Run {
            component,
            suite,
            baseline,
            output_dir,
            source_identity,
        } => execute(component, &suite, &baseline, &output_dir, &source_identity),
    }
}

/// The database every scenario gets its own database on. Absent is a refusal, never a skip: a run
/// that returned early would print the same exit status as one that ran.
fn database_url() -> Result<String, Box<dyn Error>> {
    std::env::var("SECRETS_TEST_DATABASE_URL").map_err(|_| {
        "SECRETS_TEST_DATABASE_URL is unset; both suites run against PostgreSQL and are \
         refused rather than skipped"
            .into()
    })
}

fn execute(
    component: target::Component,
    suite_path: &Path,
    baseline_path: &Path,
    output: &Path,
    revision: &str,
) -> Result<(), Box<dyn Error>> {
    let suite = AdmittedSuite::from_json(&fs::read_to_string(suite_path)?)?;
    // Every service scenario gets its own database; a library scenario gets one when it mounts the
    // remote backend, whose custody service runs over it.
    let target = target::SecretsTarget::new(component, revision.to_owned(), &database_url()?)?;
    let clock = EvidenceClock {
        epoch_ms: u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
        started: Instant::now(),
    };
    let run = Runner::new(
        RunnerConfig::default(),
        clock,
        Ids::for_suite(suite.suite()),
    )
    .run_admitted(&suite, &target);
    let report = CountReport::from_run(&run, &suite)?;
    let detail = CountRun::from_run(&run, &suite)?;
    fs::create_dir_all(output)?;
    fs::write(output.join("report.json"), report.to_canonical_json()?)?;
    fs::write(output.join("run.json"), detail.to_canonical_json()?)?;
    // Re-admit the persisted report paired with the exact suite before judging it.
    let report = CountReport::from_json(&fs::read_to_string(output.join("report.json"))?, &suite)?;
    let baseline: Baseline = serde_json::from_str(&fs::read_to_string(baseline_path)?)?;
    let counts = report.counts();
    println!("{}", serde_json::to_string(counts)?);
    let answered = counts.passed + counts.failed;
    if counts.total == 0
        || answered == 0
        || answered < baseline.answered_floor
        || counts.total < baseline.total_floor
        || counts.skipped > baseline.skipped_ceiling
        || counts.unsupported > baseline.unsupported_ceiling
        || counts.error != 0
        || counts.failed != 0
        // ESS calls any unsupported scenario a failed run; the ceiling above is what holds
        // those, so the verdicts are required only of a run with none.
        || (counts.unsupported == 0
            && (report.execution_status() != CountStatus::Passed
                || report.conformance_status() != CountStatus::Passed))
        || !every_authored_scenario_passed(&report)?
    {
        return Err(format!(
            "conformance gate refused; see {}",
            output.join("run.json").display()
        )
        .into());
    }
    Ok(())
}

/// Every authored scenario answers: an authored scenario names a behaviour a story promised, so
/// it is never one of the scenarios a ceiling lets go unsupported.
fn every_authored_scenario_passed(report: &CountReport) -> Result<bool, Box<dyn Error>> {
    let report = serde_json::to_value(report)?;
    let ids = |category: &str| -> Vec<String> {
        report["outcomes"][category]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str().map(ToOwned::to_owned))
            .collect()
    };
    let passed = ids("passed");
    let mut refused = Vec::new();
    for category in ["failed", "error", "unsupported"] {
        refused.extend(
            ids(category)
                .into_iter()
                .filter(|id| id.contains("/authored/") && !passed.contains(id)),
        );
    }
    for id in &refused {
        eprintln!("authored scenario did not pass: {id}");
    }
    Ok(refused.is_empty())
}
