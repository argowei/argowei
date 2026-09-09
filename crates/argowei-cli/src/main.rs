use clap::{Parser, Subcommand};
use std::error::Error;

mod interfaces;

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
    }

    Ok(())
}
