mod custody;
mod fixture;
mod gate;
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
            suite,
            baseline,
            output_dir,
            source_identity,
        } => execute(&suite, &baseline, &output_dir, &source_identity),
    }
}

/// The database every scenario gets its own database on. Absent is a refusal, never a skip: a run
/// that returned early would print the same exit status as one that ran.
fn database_url() -> Result<String, Box<dyn Error>> {
    std::env::var("SECRETS_TEST_DATABASE_URL").map_err(|_| {
        "SECRETS_TEST_DATABASE_URL is unset; the custody suite runs against PostgreSQL and is \
         refused rather than skipped"
            .into()
    })
}

fn execute(
    suite_path: &Path,
    baseline_path: &Path,
    output: &Path,
    revision: &str,
) -> Result<(), Box<dyn Error>> {
    let suite = AdmittedSuite::from_json(&fs::read_to_string(suite_path)?)?;
    let target = target::SecretsTarget::new(revision.to_owned(), &database_url()?)?;
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
        || counts.unsupported != 0
        || counts.error != 0
        || counts.failed != 0
        || report.execution_status() != CountStatus::Passed
        || report.conformance_status() != CountStatus::Passed
    {
        return Err(format!(
            "conformance gate refused; see {}",
            output.join("run.json").display()
        )
        .into());
    }
    Ok(())
}
