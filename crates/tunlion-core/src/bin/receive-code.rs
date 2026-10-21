//! Process adapter for one `Core::receive_code` call.
//!
//! This is deliberately tiny: the real receive path is the library's
//! `recv::dispatch::drive`, reached through `Core` with its reduced
//! `CoreHost`, identity store, ports and transfer gate. The binary exists so a
//! shell gate can run that engine as a separate process, feed it a code minted
//! by `tunlion send --code`, and capture what it prints. It adds no receive
//! behavior of its own.
//!
//! It never prints the code. The one stdout line is the summary JSON that the
//! gate asserts on, so any future logging that leaks the claim fails the gate.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;
use tunlion_core::{Core, ReceiveSummary};

struct Args {
    config_dir: PathBuf,
    dir: PathBuf,
    code: String,
    yes: bool,
    timeout: Option<u64>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("receive-code: {message}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> &'static str {
    "usage: receive-code --config-dir DIR --dir DIR --code CODE [--yes] [--timeout SECS]"
}

fn parse_args() -> Result<Args, String> {
    let mut config_dir = None;
    let mut dir = None;
    let mut code = None;
    let mut yes = false;
    let mut timeout = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .ok_or_else(|| format!("{name} needs a value; {}", usage()))
        };
        match arg.as_str() {
            "--config-dir" => config_dir = Some(PathBuf::from(value("--config-dir")?)),
            "--dir" => dir = Some(PathBuf::from(value("--dir")?)),
            "--code" => code = Some(value("--code")?),
            "--yes" | "-y" => yes = true,
            "--timeout" => {
                let raw = value("--timeout")?;
                let secs = raw
                    .parse::<u64>()
                    .map_err(|_| format!("--timeout must be seconds; {}", usage()))?;
                timeout = Some(secs);
            }
            "-h" | "--help" => return Err(usage().to_string()),
            other => return Err(format!("unknown argument {other:?}; {}", usage())),
        }
    }

    Ok(Args {
        config_dir: config_dir.ok_or_else(|| format!("missing --config-dir; {}", usage()))?,
        dir: dir.ok_or_else(|| format!("missing --dir; {}", usage()))?,
        code: code.ok_or_else(|| format!("missing --code; {}", usage()))?,
        yes,
        timeout,
    })
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let core = Core::open(&args.config_dir).map_err(|error| error.to_string())?;
    let summary = core
        .receive_code(args.code, args.dir, args.yes, args.timeout)
        .map_err(|error| error.to_string())?;
    println!("{}", summary_json(&summary));
    Ok(())
}

fn summary_json(summary: &ReceiveSummary) -> serde_json::Value {
    json!({
        "stored": summary.stored.iter().map(|file| json!({
            "name": file.name,
            "stored_name": file.stored_name,
            "bytes": file.bytes,
            "sha256": file.sha256,
        })).collect::<Vec<_>>(),
        "refused": summary.refused.iter().map(|file| json!({
            "name": file.name,
            "reason": file.reason,
            "message": file.message,
        })).collect::<Vec<_>>(),
        "bytes": summary.bytes,
    })
}
