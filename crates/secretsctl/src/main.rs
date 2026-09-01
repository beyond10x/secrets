use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Operations helper for the Secrets service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    GenerateKeyring {
        #[arg(long, default_value = "v1")]
        key_id: String,
    },
    Health {
        origin: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::GenerateKeyring { key_id } => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key)
                .map_err(|error| format!("random generation failed: {error}"))?;
            println!(
                "{}",
                serde_json::json!({"active":key_id,"keys":{key_id:STANDARD.encode(key)}})
            );
        }
        Command::Health { origin } => {
            let url = format!("{}/health/ready", origin.trim_end_matches('/'));
            let status = reqwest::get(url).await?.status();
            if !status.is_success() {
                return Err(format!("service returned {status}").into());
            }
            println!("ready");
        }
    }
    Ok(())
}
