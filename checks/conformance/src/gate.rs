use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::target::Component;

/// Every component this runner answers: its suite and the baseline its runs are held to. Each
/// suite holds only its own component's scenarios; the other's are outside it. The CLI suite is
/// the library's generated scenarios with the authored CLI scenarios, run through `secretsctl`.
const SUITES: [(Component, &str, &str); 3] = [
    (
        Component::Service,
        "contracts/suite.json",
        "contracts/baseline.json",
    ),
    (
        Component::Library,
        "contracts/storage-suite.json",
        "contracts/storage-baseline.json",
    ),
    (
        Component::Cli,
        "contracts/cli-suite.json",
        "contracts/cli-baseline.json",
    ),
];

fn ess(args: &[&str]) -> Result<(), Box<dyn Error>> {
    if !Command::new("ess").args(args).status()?.success() {
        return Err("ESS projection refused; see diagnostics above".into());
    }
    Ok(())
}

fn files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error>> {
    fn visit(
        root: &Path,
        path: &Path,
        out: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.is_dir() {
                visit(root, &path, out)?;
            } else {
                out.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

fn identity() -> Result<String, Box<dyn Error>> {
    let mut inputs = BTreeMap::new();
    for root in ["crates", "checks"] {
        for (path, bytes) in files(Path::new(root))? {
            if path
                .extension()
                .is_some_and(|ext| ext == "rs" || ext == "toml" || ext == "sql")
            {
                inputs.insert(Path::new(root).join(path), bytes);
            }
        }
    }
    for file in ["Cargo.toml", "Cargo.lock", "docs/openapi.json"] {
        inputs.insert(PathBuf::from(file), fs::read(file)?);
    }
    let mut hash = Sha256::new();
    for (path, bytes) in inputs {
        hash.update(path.to_str().ok_or("non-UTF8 source path")?.as_bytes());
        hash.update([0]);
        hash.update(u64::try_from(bytes.len())?.to_be_bytes());
        hash.update(bytes);
    }
    let mut identity = String::from("sources-sha256:");
    for byte in hash.finalize() {
        write!(identity, "{byte:02x}")?;
    }
    Ok(identity)
}

/// Every authored scenario on disk must be named in the inputs manifest ESS reads.
///
/// `--scenarios contracts` selects what `contracts/ess-inputs.yaml` lists, not what the tree holds.
/// A scenario file that exists but is unlisted is never selected, and the suite that skipped it
/// still exits 0; this refuses that state instead of leaving it to be noticed.
fn every_authored_scenario_is_declared() -> Result<(), Box<dyn Error>> {
    let manifest = fs::read_to_string("contracts/ess-inputs.yaml")?;
    let declared: BTreeSet<&str> = manifest
        .lines()
        .filter_map(|line| line.strip_prefix("- "))
        .map(str::trim)
        .collect();
    let mut missing = Vec::new();
    for path in files(Path::new("contracts"))?.keys() {
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
            && path
                .components()
                .any(|part| part.as_os_str() == "scenarios")
            && !path.to_str().is_some_and(|name| declared.contains(name))
        {
            missing.push(path.display().to_string());
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "authored scenarios absent from contracts/ess-inputs.yaml: {}",
            missing.join(", ")
        )
        .into());
    }
    Ok(())
}

pub fn check() -> Result<(), Box<dyn Error>> {
    // Require the repository root; never infer success from a suite beside another checkout.
    if fs::canonicalize(".")?
        != fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?
    {
        return Err("run conformance from this build's repository root".into());
    }
    crate::database_url()?;
    every_authored_scenario_is_declared()?;
    // A unique projection directory keeps stale generated files from masking drift.
    let projection = format!("target/conformance/projection-{}", std::process::id());
    // A process id repeats across CI runs, and a restored `target/` cache can hold that run's
    // directory with its ESS ownership state pruned, which ESS refuses to write into.
    match fs::remove_dir_all(&projection) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    fs::create_dir_all(&projection)?;
    for (component, committed, _) in SUITES {
        let suite = format!("{projection}/{}.json", component.name());
        synthesize(component, &suite)?;
        if fs::read(&suite)? != fs::read(committed)? {
            return Err(format!("suite drift: regenerate {committed} with ESS").into());
        }
    }
    let schemas = format!("{projection}/schema");
    ess(&[
        "generate", "--path", "spec", "--kind", "schema", "--out", &schemas,
    ])?;
    // `.ess-output` is ESS's destination-specific ownership ledger, not a projected artifact.
    if files(&Path::new(&schemas).join("schema"))? != files(Path::new("contracts/schema/schema"))? {
        return Err("schema drift: regenerate contracts/schema with ESS".into());
    }
    let identity = identity()?;
    for (component, _, baseline) in SUITES {
        let suite = format!("{projection}/{}.json", component.name());
        let mut previous = None;
        for iteration in 1..=3 {
            let output = PathBuf::from(format!(
                "target/conformance/{}/run-{iteration}",
                component.name()
            ));
            crate::execute(
                component,
                Path::new(&suite),
                Path::new(baseline),
                &output,
                &identity,
            )?;
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(output.join("report.json"))?)?;
            let counts = report["counts"].clone();
            if previous.as_ref().is_some_and(|old| old != &counts) {
                return Err(format!(
                    "{} conformance counts changed across identical consecutive runs",
                    component.name()
                )
                .into());
            }
            previous = Some(counts);
        }
    }
    println!("conformance and deterministic ESS projections passed ({identity})");
    Ok(())
}

/// `component`'s suite, synthesized from the specification and the authored scenarios.
fn synthesize(component: Component, out: &str) -> Result<(), Box<dyn Error>> {
    ess(&[
        "verify",
        "conform",
        "synthesize",
        "--path",
        "spec",
        "--suite-format",
        "5",
        "--target",
        "ir",
        "--component",
        component.specified(),
        "--scenarios",
        component.scenarios(),
        "--out",
        out,
    ])
}
