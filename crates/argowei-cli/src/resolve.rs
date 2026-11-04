use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use argowei_collector::names::{
    resolve_all, DhcpLeaseResolver, HostnameResolver, MdnsResolver, NameSource, NetbiosResolver,
    RdnsResolver, Target,
};

pub struct Options {
    pub addresses: Vec<Ipv4Addr>,
    pub dns_server: Option<Ipv4Addr>,
    pub leases: Option<PathBuf>,
    pub timeout: Duration,
}

/// Asks each source separately about each address and prints what every one
/// answered, so disagreements and silent sources are visible.
pub fn run(options: Options) -> Result<(), Box<dyn Error>> {
    let rdns = match options.dns_server {
        Some(ip) => RdnsResolver::new(vec![SocketAddr::new(ip.into(), 53)]),
        None => RdnsResolver::from_system(),
    };
    println!(
        "Reverse DNS via: {}",
        if rdns.servers().is_empty() {
            "(no local DNS server found; use --dns-server)".to_owned()
        } else {
            rdns.servers()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    );

    let mut resolvers: Vec<Arc<dyn HostnameResolver>> = Vec::new();
    if let Some(path) = &options.leases {
        resolvers.push(Arc::new(DhcpLeaseResolver::new(path)));
    }
    resolvers.push(Arc::new(MdnsResolver::default()));
    resolvers.push(Arc::new(NetbiosResolver::default()));
    resolvers.push(Arc::new(rdns));

    // Without a scan there is no MAC address; the lease file then matches by IP.
    let targets: Vec<Target> = options
        .addresses
        .iter()
        .map(|ip| Target {
            ip: *ip,
            mac: "00:00:00:00:00:00".to_owned(),
        })
        .collect();

    println!("{:<16} {:<8} NAME", "ADDRESS", "SOURCE");
    for result in resolve_all(&resolvers, &targets, options.timeout, 8) {
        for source in NameSource::ALL {
            let answer = result.names.iter().find(|n| n.source == source);
            let failure = result.errors.iter().find(|(s, _)| *s == source);
            let enabled = resolvers_has(&resolvers, source);
            let text = match (answer, failure, enabled) {
                (Some(name), _, _) => name.name.clone(),
                (None, Some((_, error)), _) => format!("(failed: {error})"),
                (None, None, true) => "(no answer)".to_owned(),
                (None, None, false) => continue,
            };
            println!("{:<16} {:<8} {text}", result.target.ip, source.as_str());
        }
    }
    Ok(())
}

fn resolvers_has(resolvers: &[Arc<dyn HostnameResolver>], source: NameSource) -> bool {
    resolvers.iter().any(|r| r.source() == source)
}
