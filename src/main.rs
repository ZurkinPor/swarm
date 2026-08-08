mod agent;
mod binary_tool;
mod channel;
mod client;
mod crypto;
mod packet;
mod protocol;
mod server;
mod swarm;
mod task;
mod tools;

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
    /// 64-char hex key directly (alternative to --key-file)
    #[arg(short = 'K', long)]
    key: Option<String>,

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

        /// Run as orchestrator — can assign tasks to other agents
        #[arg(long)]
        orchestrator: bool,
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

        /// Pipe mode: JSON commands on stdin, JSON events on stdout (for AI harnesses)
        #[arg(long)]
        pipe: bool,

        /// Run as orchestrator — can assign tasks to other agents
        #[arg(long)]
        orchestrator: bool,
    },
    /// Generate a new random key file
    GenKey {
        /// Output path for the key file
        #[arg(short, long, default_value = "swarm.key")]
        output: PathBuf,

        /// Save this specific hex key instead of generating a new one
        #[arg(short = 'k', long)]
        key: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey { output, key } => {
            let key = match key {
                Some(hex) => hex,
                None => Crypto::generate_key(),
            };
            std::fs::write(&output, &key)?;
            println!("Key written to {}", output.display());
            println!("Share this key with all swarm members.");
        }
        Commands::Serve { username, role, workspace_mode, orchestrator } => {
            let crypto = load_key(&cli.key, &cli.key_file)?;
            let crypto = Arc::new(crypto);

            let bind_addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
            let state = Arc::new(Mutex::new(SwarmState::new()));

            // Register the server itself as an agent
            {
                let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
                let mut s = state.lock().await;
                let mut caps = vec!["server".into()];
                if orchestrator { caps.push("orchestrator".into()); }
                s.add_agent(
                    crate::agent::Agent::new(
                        username.clone(),
                        role.clone(),
                        caps,
                        Some(workspace_mode.clone()),
                        None,
                        orchestrator,
                    ),
                    crate::swarm::ConnectionHandle { tx },
                );
            }

            println!("=== Swarm Server ===");
            println!("Key file:     {}", cli.key_file.display());
            println!("Port:         {}", cli.port);
            println!("Username:     {}", username);
            println!("Role:         {:?}", role);
            println!("Orchestrator: {}", if orchestrator { "YES" } else { "no" });

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
            pipe,
            orchestrator,
        } => {
            let crypto = load_key(&cli.key, &cli.key_file)?;
            let crypto = Arc::new(crypto);

            let port = server_port.unwrap_or(cli.port);
            let addr = format!("{}:{}", server, port);
            let server_addr: SocketAddr = addr.parse()?;

            let caps: Vec<String> =
                capabilities.split(',').map(|s| s.trim().to_string()).collect();

            println!("=== Swarm Client ===");
            println!("Server:       {}", server_addr);
            println!("Key:          {}", cli.key_file.display());
            println!("Agent:        {} (role: {:?})", username, role);
            println!("Orchestrator: {}", if orchestrator { "YES" } else { "no" });

            client::run_client(
                server_addr,
                crypto,
                username,
                role,
                caps,
                workspace_mode,
                project_root,
                pipe,
                orchestrator,
            )
            .await?;
        }
    }
    Ok(())
}

fn load_key(key_opt: &Option<String>, path: &PathBuf) -> anyhow::Result<Crypto> {
    if let Some(hex) = key_opt {
        return Crypto::from_hex(hex);
    }
    if path.exists() {
        Crypto::from_key_file(path)
    } else {
        let key = Crypto::generate_key();
        std::fs::write(path, &key)?;
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Generated new key — clients MUST use the      ║");
        eprintln!("║  SAME key or they will fail with decryption errors.     ║");
        eprintln!("║  Key file: {}{}║", path.display(), " ".repeat(53_usize.saturating_sub(path.display().to_string().len())));
        eprintln!("║  Share via: swarm.exe gen-key -K <hex> -o swarm.key    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        Crypto::from_key_file(path)
    }
}
