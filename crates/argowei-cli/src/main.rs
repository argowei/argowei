use clap::{Parser, Subcommand};
use std::error::Error;

mod interfaces;
mod scan;

#[derive(Debug, Parser)]
#[command(name = "argowei")]
#[command(about = "Network intelligence tooling for private infrastructure")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print build and project information.
    About,
    /// List local network interfaces.
    Interfaces,
    /// ARP-scan a network interface's local subnet for live hosts.
    ///
    /// Requires permission to open a raw socket (run as root, or grant
    /// CAP_NET_RAW to the binary).
    Scan {
        /// Interface to scan on, e.g. eth0 (see `argowei interfaces`).
        interface: String,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::About => {
            println!(
                "{} {}",
                argowei_core::PROJECT_NAME,
                env!("CARGO_PKG_VERSION")
            );
        }
        Command::Interfaces => {
            interfaces::run()?;
        }
        Command::Scan { interface } => {
            scan::run(&interface)?;
        }
    }

    Ok(())
}
