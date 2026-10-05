//! `secretsctl`: operations helpers for the Secrets service, and the local commands over the
//! named-storage library (story:local-cli).
//!
//! The local commands act on the local scope: tenant `default`, user `default`, namespace
//! `default` unless `--namespace` names another. `--tenant` and `--user` name the scope; any
//! value other than `default` is denied by the local authorizer before the configuration is read
//! or any backend is opened (story:cli-scope-flags). Their configuration is
//! `$XDG_CONFIG_HOME/b10x-secrets/config.toml` (`~/.config` when the variable is unset) and holds
//! no secret.
//!
//! No command writes a secret value to stdout or stderr: there is no command that reads one back,
//! `put` takes its value only from a hidden prompt, a pipe or a protected file, and a command line
//! that clap refuses is reported without repeating what was typed.
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand, error::ContextKind, error::ErrorKind};
use secrets_core::{
    authorize::{Authorizer as _, LocalAuthorizer, Resource},
    storage::Action,
};

mod backends;
mod local;
mod value;

#[derive(Parser)]
#[command(
    version,
    about = "Operations helper for the Secrets service, and local named secrets"
)]
struct Cli {
    /// Print results and refusals as JSON.
    #[arg(long, global = true)]
    json: bool,
    /// The tenant a local command acts in. Local mode serves tenant `default` only; any other is
    /// denied before the configuration or any backend is opened.
    #[arg(
        long,
        global = true,
        default_value = "default",
        allow_hyphen_values = true
    )]
    tenant: String,
    /// The user a local command acts as. Local mode serves user `default` only; any other is
    /// denied before the configuration or any backend is opened.
    #[arg(
        long,
        global = true,
        default_value = "default",
        allow_hyphen_values = true
    )]
    user: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a new service keyring (JSON) for the Secrets service.
    GenerateKeyring {
        #[arg(long, default_value = "v1")]
        key_id: String,
    },
    /// Check that a Secrets service is ready.
    Health { origin: String },
    /// Store a secret under a name. The value comes from a hidden prompt, a pipe on stdin, or
    /// --file; never from the command line.
    Put(PutArgs),
    /// Show one secret's name, scope, backend and version.
    Describe {
        name: String,
        #[command(flatten)]
        namespace: NamespaceArg,
    },
    /// List the names, scope, backend and version of the secrets in a namespace.
    List {
        #[command(flatten)]
        namespace: NamespaceArg,
        /// List every namespace instead of one.
        #[arg(long, conflicts_with = "namespace")]
        all: bool,
    },
    /// Delete a secret. Any binding of its name stays.
    Delete {
        name: String,
        #[command(flatten)]
        namespace: NamespaceArg,
    },
    /// Move a secret to a new name in the same namespace.
    Rename {
        name: String,
        new_name: String,
        #[command(flatten)]
        namespace: NamespaceArg,
    },
    /// Add, list or remove namespaces.
    #[command(subcommand)]
    Namespace(NamespaceCommand),
    /// Point a namespace at a backend.
    #[command(subcommand)]
    Mount(MountCommand),
    /// Bind a name to a locator in its namespace's backend.
    Bind {
        name: String,
        locator: String,
        #[command(flatten)]
        namespace: NamespaceArg,
    },
    /// Remove a name's binding.
    Unbind {
        name: String,
        #[command(flatten)]
        namespace: NamespaceArg,
    },
}

#[derive(Args)]
struct NamespaceArg {
    /// The namespace, in tenant `default`.
    #[arg(long, short = 'n', default_value = "default")]
    namespace: String,
}

#[derive(Args)]
struct PutArgs {
    name: String,
    #[command(flatten)]
    namespace: NamespaceArg,
    /// Read the value from this file, which must be readable by its owner only (mode 0600).
    #[arg(long)]
    file: Option<PathBuf>,
    /// Keep the value's bytes exactly; by default one trailing newline is dropped from a piped or
    /// file value.
    #[arg(long)]
    raw: bool,
    /// Refused: a value on the command line lands in shell history and the process table.
    #[arg(hide = true, allow_hyphen_values = true)]
    value: Option<OsString>,
    /// Refused, as the positional value is.
    #[arg(long = "value", hide = true, allow_hyphen_values = true)]
    value_flag: Option<OsString>,
}

#[derive(Subcommand)]
enum NamespaceCommand {
    /// Add a namespace, on the default keychain mount unless --mount names another.
    Add {
        name: String,
        /// `kind/label`, such as `remote/prod`; a bare kind is label `default`.
        #[arg(long)]
        mount: Option<String>,
    },
    /// List every namespace with its mount.
    List,
    /// Remove a namespace that holds no secret and no binding.
    Remove { name: String },
}

#[derive(Subcommand)]
enum MountCommand {
    /// Mount a namespace on a backend (`kind/label`); refused while it holds secrets.
    Set { namespace: String, mount: String },
}

/// Exit codes: 2 for a command line or an input refused before anything is stored, 3 to 9 for the
/// storage refusals in the specification's order, 1 for anything else.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return refuse_command_line(&error),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("secretsctl: could not start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run(cli))
}

/// A refused command line, reported without the text that was typed: clap would otherwise echo
/// an unexpected argument, which may be the secret someone tried to pass.
fn refuse_command_line(error: &clap::Error) -> ExitCode {
    match error.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let _ = error.print();
            return if error.use_stderr() {
                ExitCode::from(EXIT_USAGE)
            } else {
                ExitCode::SUCCESS
            };
        }
        _ => {}
    }
    let kind = error.kind().as_str().unwrap_or("invalid command line");
    // These kinds name the argument's definition, never the value that was typed.
    let names_definition = matches!(
        error.kind(),
        ErrorKind::InvalidValue
            | ErrorKind::ValueValidation
            | ErrorKind::MissingRequiredArgument
            | ErrorKind::ArgumentConflict
            | ErrorKind::TooManyValues
            | ErrorKind::TooFewValues
            | ErrorKind::WrongNumberOfValues
            | ErrorKind::NoEquals
    );
    let argument = names_definition
        .then(|| error.get(ContextKind::InvalidArg))
        .flatten();
    match argument {
        Some(argument) => eprintln!("secretsctl: {kind}: {argument}; see `secretsctl --help`"),
        None => eprintln!("secretsctl: {kind}; see `secretsctl --help`"),
    }
    ExitCode::from(EXIT_USAGE)
}

async fn run(cli: Cli) -> ExitCode {
    let command = match cli.command {
        Command::GenerateKeyring { key_id } => return generate_keyring(&key_id),
        Command::Health { origin } => return health(&origin).await,
        local => local,
    };
    // The scope is decided first: a denied command reads no configuration and opens no backend.
    let (name, actions) = decision(&command);
    if let Err(denial) = actions.iter().try_for_each(|action| {
        LocalAuthorizer.decide(
            Resource::Scope {
                tenant: &cli.tenant,
                user: &cli.user,
            },
            *action,
        )
    }) {
        return local::Local::unopened(cli.json).finish(name, Err(local::Failure::Denied(denial)));
    }
    // Only an admitted local command reads the configuration and opens the keychain.
    let local = local::Local::open(cli.json);
    let (name, outcome) = match command {
        Command::GenerateKeyring { .. } | Command::Health { .. } => return ExitCode::FAILURE,
        Command::Put(args) => ("put", local.put(args).await),
        Command::Describe { name, namespace } => (
            "describe",
            local.describe(&namespace.namespace, &name).await,
        ),
        Command::List { namespace, all } => ("list", local.list(&namespace.namespace, all).await),
        Command::Delete { name, namespace } => {
            ("delete", local.delete(&namespace.namespace, &name).await)
        }
        Command::Rename {
            name,
            new_name,
            namespace,
        } => (
            "rename",
            local.rename(&namespace.namespace, &name, &new_name).await,
        ),
        Command::Namespace(NamespaceCommand::Add { name, mount }) => (
            "namespace add",
            local.namespace_add(&name, mount.as_deref()).await,
        ),
        Command::Namespace(NamespaceCommand::List) => {
            ("namespace list", local.namespace_list().await)
        }
        Command::Namespace(NamespaceCommand::Remove { name }) => {
            ("namespace remove", local.namespace_remove(&name).await)
        }
        Command::Mount(MountCommand::Set { namespace, mount }) => {
            ("mount set", local.mount_set(&namespace, &mount).await)
        }
        Command::Bind {
            name,
            locator,
            namespace,
        } => (
            "bind",
            local.bind(&namespace.namespace, &name, &locator).await,
        ),
        Command::Unbind { name, namespace } => {
            ("unbind", local.unbind(&namespace.namespace, &name).await)
        }
    };
    local.finish(name, outcome)
}

/// A local command's name in messages, and the actions the authorizer decides for it
/// (`spec/domains/storage.yaml`, `Action`). Every local command is decided on the tenant and the
/// user: the namespace commands' specification reads the tenant only, and the CLI also refuses a
/// user it does not serve rather than act for one silently.
fn decision(command: &Command) -> (&'static str, &'static [Action]) {
    match command {
        Command::GenerateKeyring { .. } => ("generate-keyring", &[]),
        Command::Health { .. } => ("health", &[]),
        Command::Put(_) => ("put", &[Action::Write]),
        Command::Describe { .. } => ("describe", &[Action::List]),
        Command::List { .. } => ("list", &[Action::List]),
        Command::Delete { .. } => ("delete", &[Action::Delete]),
        Command::Rename { .. } => ("rename", &[Action::Write, Action::Delete]),
        Command::Namespace(NamespaceCommand::Add { .. }) => {
            ("namespace add", &[Action::ManageNamespace])
        }
        Command::Namespace(NamespaceCommand::List) => {
            ("namespace list", &[Action::ManageNamespace])
        }
        Command::Namespace(NamespaceCommand::Remove { .. }) => {
            ("namespace remove", &[Action::ManageNamespace])
        }
        Command::Mount(MountCommand::Set { .. }) => ("mount set", &[Action::ManageNamespace]),
        Command::Bind { .. } => ("bind", &[Action::ManageNamespace]),
        Command::Unbind { .. } => ("unbind", &[Action::ManageNamespace]),
    }
}

fn generate_keyring(key_id: &str) -> ExitCode {
    let mut key = [0_u8; 32];
    if getrandom::fill(&mut key).is_err() {
        eprintln!("secretsctl: random generation failed");
        return ExitCode::FAILURE;
    }
    println!(
        "{}",
        serde_json::json!({"active":key_id,"keys":{key_id:STANDARD.encode(key)}})
    );
    ExitCode::SUCCESS
}

async fn health(origin: &str) -> ExitCode {
    let url = format!("{}/health/ready", origin.trim_end_matches('/'));
    match reqwest::get(url).await {
        Ok(response) if response.status().is_success() => {
            println!("ready");
            ExitCode::SUCCESS
        }
        Ok(response) => {
            eprintln!("secretsctl: service returned {}", response.status());
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("secretsctl: {error}");
            ExitCode::FAILURE
        }
    }
}
