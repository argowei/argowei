//! Reading nmap's XML output (`-oX -`) into plain structs.
//!
//! Only parsing lives here; running nmap is the API's job (it needs
//! timeouts, cancellation and a database). The XML comes from a local nmap
//! process, but it describes what *devices* answered (service banners,
//! versions), so it is still treated as untrusted: DTDs are tolerated only
//! because nmap writes one, entity expansion is bounded by roxmltree, the
//! node count is capped, and missing or odd attributes become `None` or an
//! error, never a panic.
//!
//! Results may be incomplete: a firewall that drops packets makes ports look
//! `filtered`, rate limiting can hide open ones, and nmap only lists the
//! ports it was asked about.

use std::fmt;

use argowei_core::scan_diff::PortCoverage;
use roxmltree::{Document, Node, ParsingOptions};

/// Upper bound on XML nodes; a full scan of one host stays far below it.
const MAX_NODES: u32 = 1_000_000;

/// One nmap run.
#[derive(Debug, Clone, PartialEq)]
pub struct NmapRun {
    /// nmap's version, e.g. `7.993`.
    pub version: Option<String>,
    /// The command line nmap reports.
    pub args: Option<String>,
    /// Seconds the run took, from `runstats`.
    pub elapsed_secs: Option<f64>,
    /// `false` when nmap reported an error exit in `runstats`.
    pub succeeded: bool,
    /// nmap's own error message, if it gave one.
    pub error: Option<String>,
    /// The ports nmap probed (from `scaninfo`); empty if it did not say,
    /// which makes every port count as not compared.
    pub coverage: PortCoverage,
    pub hosts: Vec<NmapHost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapHost {
    /// `up`, `down` or `unknown` (with `-Pn` nmap reports `up` regardless).
    pub state: String,
    pub addresses: Vec<String>,
    /// Ports nmap listed individually; ports summarized in `extraports`
    /// (typically the many closed or filtered ones) are not included.
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapPort {
    /// `tcp` or `udp`.
    pub protocol: String,
    pub port: u16,
    /// `open`, `closed`, `filtered`, `unfiltered`, `open|filtered`, ...
    pub state: String,
    /// Why nmap decided the state, e.g. `syn-ack` or `conn-refused`.
    pub reason: Option<String>,
    pub service: Option<NmapService>,
}

impl NmapPort {
    pub fn is_open(&self) -> bool {
        self.state == "open"
    }
}

/// What nmap thinks runs on a port. Without `-sV`, `name` is only a guess
/// from the port number (`method="table"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapService {
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    /// `true` when nmap actually probed the service (`method="probed"`).
    pub probed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmapError {
    /// Not well-formed XML (a truncated run, or not nmap output at all).
    Malformed(String),
    /// Well-formed, but not an `nmaprun` document.
    NotNmap,
    /// A required attribute is missing or invalid.
    Invalid(&'static str),
}

impl fmt::Display for NmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "nmap output is not valid XML: {reason}"),
            Self::NotNmap => write!(f, "not nmap XML output"),
            Self::Invalid(what) => write!(f, "nmap output has an invalid {what}"),
        }
    }
}

impl std::error::Error for NmapError {}

/// Parses the XML nmap writes with `-oX`.
pub fn parse_xml(xml: &str) -> Result<NmapRun, NmapError> {
    let options = ParsingOptions {
        allow_dtd: true,
        nodes_limit: MAX_NODES,
    };
    let document = Document::parse_with_options(xml, options)
        .map_err(|e| NmapError::Malformed(e.to_string()))?;
    let root = document.root_element();
    if !root.has_tag_name("nmaprun") {
        return Err(NmapError::NotNmap);
    }

    let finished = child(root, "runstats").and_then(|stats| child(stats, "finished"));
    let hosts = root
        .children()
        .filter(|n| n.has_tag_name("host"))
        .map(parse_host)
        .collect::<Result<Vec<_>, _>>()?;

    // A malformed list only loses that protocol's coverage: ports outside
    // the known coverage are reported as not comparable, never as changes.
    let mut coverage = PortCoverage::default();
    for info in root.children().filter(|n| n.has_tag_name("scaninfo")) {
        if let (Some(protocol), Some(services)) =
            (info.attribute("protocol"), info.attribute("services"))
        {
            let mut one = PortCoverage::default();
            if one.add_services(protocol, services).is_some() {
                coverage.add_services(protocol, services);
            }
        }
    }

    Ok(NmapRun {
        version: attr(root, "version"),
        coverage,
        args: attr(root, "args"),
        elapsed_secs: finished
            .and_then(|f| f.attribute("elapsed"))
            .and_then(|e| e.parse().ok()),
        succeeded: finished.and_then(|f| f.attribute("exit")) != Some("error"),
        error: finished.and_then(|f| attr(f, "errormsg")),
        hosts,
    })
}

fn parse_host(host: Node) -> Result<NmapHost, NmapError> {
    let ports = match child(host, "ports") {
        Some(ports) => ports
            .children()
            .filter(|n| n.has_tag_name("port"))
            .map(parse_port)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    Ok(NmapHost {
        state: child(host, "status")
            .and_then(|s| attr(s, "state"))
            .unwrap_or_else(|| "unknown".to_owned()),
        addresses: host
            .children()
            .filter(|n| n.has_tag_name("address"))
            .filter_map(|a| attr(a, "addr"))
            .collect(),
        ports,
    })
}

fn parse_port(port: Node) -> Result<NmapPort, NmapError> {
    let state = child(port, "state").ok_or(NmapError::Invalid("port state"))?;
    Ok(NmapPort {
        protocol: attr(port, "protocol").ok_or(NmapError::Invalid("port protocol"))?,
        port: port
            .attribute("portid")
            .and_then(|p| p.parse().ok())
            .ok_or(NmapError::Invalid("port number"))?,
        state: attr(state, "state").ok_or(NmapError::Invalid("port state"))?,
        reason: attr(state, "reason"),
        service: child(port, "service").map(|service| NmapService {
            name: attr(service, "name"),
            product: attr(service, "product"),
            version: attr(service, "version"),
            extra_info: attr(service, "extrainfo"),
            probed: service.attribute("method") == Some("probed"),
        }),
    })
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|n| n.has_tag_name(name))
}

/// An attribute's value, with empty values treated as missing.
fn attr(node: Node, name: &str) -> Option<String> {
    node.attribute(name)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests;
