mod agent;
mod channel;
mod client;
mod crypto;
mod packet;
mod protocol;
mod server;
mod swarm;
mod task;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::sync::Mutex;

use crate::crypto::Crypto;
use crate::swarm::SwarmState;

/// Swarm — P2P TCP protocol for AI agent orchestration.
#[derive(Parser)]
#[command(name = "swarm", version, about)]
struct Cli {
    /// Path to the key file (64-char hex AES-256 key)
    #[arg(short, long, default_value = "swarm.key")]
    key_file: PathBuf,

    /// Custom port (default: 6996)
    #[arg(short, long, default_value_t = 6996)]
    port: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start as a swarm server (hub)
    Serve {
        /// Username for this server node
        #[arg(short, long, default_value = "swarm-server")]
        username: String,

        /// Role for this node
        #[arg(short, long)]
        role: Option<String>,

        /// Workspace mode: "git" (default) or "single-host"
        #[arg(long, default_value = "git", value_parser = ["git", "single-host"])]
        workspace_mode: String,
    },
    /// Connect to a swarm server as a client agent
    Connect {
        /// Server IP address
        #[arg(short, long)]
        server: String,

        /// Server port (overrides global --port)
        #[arg(long)]
        server_port: Option<u16>,

        /// Your agent username
        #[arg(short, long)]
        username: String,

        /// Your agent role (developer, researcher, etc.)
        #[arg(short, long)]
        role: Option<String>,

        /// Capabilities (comma-separated)
        #[arg(long, default_value = "general")]
        capabilities: String,

        /// Workspace mode: "git" (default) or "single-host"
        #[arg(long, default_value = "git", value_parser = ["git", "single-host"])]
        workspace_mode: String,

        /// Project root path (required for single-host mode)
        #[arg(long)]
        project_root: Option<String>,
    },
    /// Generate a new random key file
    GenKey {
        /// Output path for the key file
        #[arg(short, long, default_value = "swarm.key")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey { output } => {
            let key = Crypto::generate_key();
            std::fs::write(&output, &key)?;
            println!("Key written to {}", output.display());
            println!("Share this key with all swarm members.");
        }
        Commands::Serve { username, role, workspace_mode } => {
            // Load or create key
            let crypto = load_or_create_key(&cli.key_file)?;
            let crypto = Arc::new(crypto);

            let bind_addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
            let state = Arc::new(Mutex::new(SwarmState::new()));

            // Register the server itself as an agent
            {
                let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
                let mut s = state.lock().await;
                s.add_agent(
                    crate::agent::Agent::new(
                        username.clone(),
                        role.clone(),
                        vec!["server".into(), "orchestrator".into()],
                        Some(workspace_mode.clone()),
                        None,
                    ),
                    crate::swarm::ConnectionHandle { tx },
                );
            }

            println!("=== Swarm Server ===");
            println!("Key file: {}", cli.key_file.display());
            println!("Port:     {}", cli.port);
            println!("Username: {}", username);
            println!("Role:     {:?}", role);

            let server = server::Server::new(state, crypto, bind_addr);
            server.run().await?;
        }
        Commands::Connect {
            server,
            server_port,
            username,
            role,
            capabilities,
            workspace_mode,
            project_root,
        } => {
            let crypto = Crypto::from_key_file(&cli.key_file)?;
            let crypto = Arc::new(crypto);

            let port = server_port.unwrap_or(cli.port);
            let addr = format!("{}:{}", server, port);
            let server_addr: SocketAddr = addr.parse()?;

            let caps: Vec<String> =
                capabilities.split(',').map(|s| s.trim().to_string()).collect();

            println!("=== Swarm Client ===");
            println!("Server: {}", server_addr);
            println!("Key:    {}", cli.key_file.display());
            println!("Agent:  {} (role: {:?})", username, role);

            client::run_client(
                server_addr,
                crypto,
                username,
                role,
                caps,
                workspace_mode,
                project_root,
            )
            .await?;
        }
    }
    Ok(())
}

fn load_or_create_key(path: &PathBuf) -> anyhow::Result<Crypto> {
    if path.exists() {
        Crypto::from_key_file(path)
    } else {
        let key = Crypto::generate_key();
        std::fs::write(path, &key)?;
        println!("[NOTE] Generated new key file: {}", path.display());
        Crypto::from_key_file(path)
    }
}
