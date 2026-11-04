use clap::{Parser, Subcommand};
use std::error::Error;

mod interfaces;
mod resolve;
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
    /// Ask each name source (mDNS, NetBIOS, reverse DNS, optionally a DHCP
    /// lease file) what the given devices call themselves.
    ///
    /// Sends a few small UDP packets to each address; only addresses on the
    /// local network are accepted. Useful to see which sources your devices
    /// actually answer.
    Resolve {
        /// IPv4 addresses of devices on the local network.
        #[arg(required = true)]
        addresses: Vec<std::net::Ipv4Addr>,
        /// DNS server for reverse lookups (default: the local servers in /etc/resolv.conf).
        #[arg(long)]
        dns_server: Option<std::net::Ipv4Addr>,
        /// dnsmasq lease file to read names from.
        #[arg(long)]
        leases: Option<std::path::PathBuf>,
        /// How long to wait for each answer, in milliseconds.
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
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
        Command::Resolve {
            addresses,
            dns_server,
            leases,
            timeout_ms,
        } => {
            resolve::run(resolve::Options {
                addresses,
                dns_server,
                leases,
                timeout: std::time::Duration::from_millis(timeout_ms),
            })?;
        }
    }

    Ok(())
}
