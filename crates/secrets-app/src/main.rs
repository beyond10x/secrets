use clap::{Parser, Subcommand};
use secrets_auth::{IdentityAuthority, KubernetesAuthority};
use secrets_crypto::Keyring;
use secrets_http::AppState;
use secrets_postgres::PostgresStore;
use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Encrypted secret custody service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve(Serve),
    Migrate(Database),
    Rewrap(Rewrap),
}

#[derive(clap::Args)]
struct Database {
    #[arg(long, env = "SECRETS_DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "SECRETS_KEYRING_FILE")]
    keyring_file: String,
}

#[derive(clap::Args)]
struct Rewrap {
    #[command(flatten)]
    database: Database,
    #[arg(long, default_value = "secretsctl")]
    actor: String,
}

#[derive(clap::Args)]
struct Serve {
    #[command(flatten)]
    database: Database,
    #[arg(long, env = "SECRETS_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    #[arg(long, env = "SECRETS_IDENTITY_ORIGIN")]
    identity_origin: String,
    #[arg(long, env = "SECRETS_IDENTITY_AUDIENCE")]
    identity_audience: String,
    #[arg(long, env = "SECRETS_WORKLOAD_AUDIENCE")]
    workload_audience: String,
    #[arg(long, env = "SECRETS_WORKLOAD_GRANTS_FILE")]
    workload_grants_file: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await?,
        Command::Migrate(args) => {
            connect(&args).await?;
        }
        Command::Rewrap(args) => {
            let store = connect(&args.database).await?;
            println!(
                "rewrapped {} active secret(s)",
                store.rewrap_all(&args.actor).await?
            );
        }
    }
    Ok(())
}

async fn connect(args: &Database) -> Result<PostgresStore, Box<dyn std::error::Error>> {
    let keyring = Arc::new(Keyring::from_file(&args.keyring_file)?);
    Ok(PostgresStore::connect(&args.database_url, keyring).await?)
}

async fn serve(args: Serve) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(connect(&args.database).await?);
    let users = Arc::new(IdentityAuthority::new(
        &args.identity_origin,
        &args.identity_audience,
    )?);
    let workloads = Arc::new(KubernetesAuthority::in_cluster(
        &args.workload_audience,
        &args.workload_grants_file,
    )?);
    let app = secrets_http::router(AppState {
        store,
        user_authority: users,
        workload_authority: workloads,
    });
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(address=%args.bind, "secrets service listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
