//! Convert independently recorded reference events to conservative study labels.
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "presence_reference/mod.rs"]
mod presence_reference;

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("presence_reference: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h")) {
        return writeln!(io::stdout().lock(), "Usage: presence_reference <reference.json|->\n\nOffline conversion of independent reference events with explicit clock bounds.\nCopy artifact ground_truth into the matching study trace; keep the full artifact.\nContract and limitations: docs/PRESENCE-REFERENCE.md")
            .map_err(|e| e.to_string());
    }
    if args.len() != 1 {
        return Err("expected one JSON path or - for stdin; use --help".into());
    }
    let input = if args[0] == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        bytes
    } else {
        let path = PathBuf::from(&args[0]);
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?
    };
    let artifact = presence_reference::convert_json(&input)?;
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &artifact).map_err(|e| e.to_string())?;
    writeln!(output).map_err(|e| e.to_string())
}
