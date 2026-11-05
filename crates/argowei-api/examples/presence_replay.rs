//! Replay timestamped observations against independently recorded presence labels.
//! See docs/PRESENCE-REPLAY.md for the input contract and metric definitions.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;
use sha2::{Digest, Sha256};

#[path = "presence_replay/mod.rs"]
mod presence_replay;

const HELP: &str = "Usage: presence_replay <trace.json|->

Compare the production presence policy and three baselines on one dataset.
Use - to read JSON from stdin. The deterministic JSON report goes to stdout;
input errors go to stderr and exit with status 1. No database or network needed.

Example:
  cargo run --locked -q -p argowei-api --example presence_replay -- \
    docs/evidence/presence-replay.synthetic.json

Input format and metric definitions: docs/PRESENCE-REPLAY.md";

#[derive(Serialize)]
struct Artifact {
    artifact_version: u8,
    /// Hash of the exact input bytes, including whitespace, for reproducibility.
    input_sha256: String,
    report: presence_replay::Report,
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("presence_replay: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h")) {
        return writeln!(io::stdout().lock(), "{HELP}").map_err(|error| error.to_string());
    }
    if args.len() != 1 {
        return Err("expected one JSON path or - for stdin; use --help for usage".into());
    }

    let input = if args[0] == "-" {
        let mut input = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut input)
            .map_err(|error| format!("cannot read stdin: {error}"))?;
        input
    } else {
        let path = PathBuf::from(&args[0]);
        std::fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?
    };

    let report = presence_replay::replay_json(&input)?;
    let artifact = Artifact {
        artifact_version: 1,
        input_sha256: format!("{:x}", Sha256::digest(&input)),
        report,
    };
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &artifact)
        .map_err(|error| format!("cannot write report: {error}"))?;
    writeln!(output).map_err(|error| format!("cannot write report: {error}"))
}
