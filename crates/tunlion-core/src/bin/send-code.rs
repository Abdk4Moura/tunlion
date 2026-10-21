//! Process adapter for one `Core::create_code` + `wait_send` call.
//!
//! This is the sender side of the cross-engine E2E gate: the receiver is the
//! normal CLI, the sender is the library engine in this process. It contains no
//! send logic. It writes the allocated code to `--code-out` (so a shell can hand
//! it to the receiver) and prints the final summary JSON.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;
use tunlion_core::Core;

struct Args {
    config_dir: PathBuf,
    code_out: PathBuf,
    timeout: Option<u64>,
    files: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("send-code: {message}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> &'static str {
    "usage: send-code --config-dir DIR --code-out FILE [--timeout SECS] FILE..."
}

fn parse_args() -> Result<Args, String> {
    let mut config_dir = None;
    let mut code_out = None;
    let mut timeout = None;
    let mut files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .ok_or_else(|| format!("{name} needs a value; {}", usage()))
        };
        match arg.as_str() {
            "--config-dir" => config_dir = Some(PathBuf::from(value("--config-dir")?)),
            "--code-out" => code_out = Some(PathBuf::from(value("--code-out")?)),
            "--timeout" => {
                let raw = value("--timeout")?;
                timeout = Some(
                    raw.parse::<u64>()
                        .map_err(|_| format!("--timeout must be seconds; {}", usage()))?,
                );
            }
            "-h" | "--help" => return Err(usage().to_string()),
            other if other.starts_with('-') => {
                return Err(format!("unknown argument {other:?}; {}", usage()))
            }
            other => files.push(other.to_string()),
        }
    }
    if files.is_empty() {
        return Err(format!("no files; {}", usage()));
    }
    Ok(Args {
        config_dir: config_dir.ok_or_else(|| format!("missing --config-dir; {}", usage()))?,
        code_out: code_out.ok_or_else(|| format!("missing --code-out; {}", usage()))?,
        timeout,
        files,
    })
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let core = Core::open(&args.config_dir).map_err(|error| error.to_string())?;
    let created = core
        .create_code(args.files, args.timeout)
        .map_err(|error| error.to_string())?;
    std::fs::write(&args.code_out, format!("{}\n", created.code))
        .map_err(|error| format!("writing {}: {error}", args.code_out.display()))?;
    let result = core.wait_send().map_err(|error| error.to_string())?;
    println!(
        "{}",
        json!({
            "code": result.code,
            "expires_in_secs": result.expires_in_secs,
            "bytes": result.bytes,
            "files": result.files.iter().map(|file| json!({
                "name": file.name,
                "stored_name": file.stored_name,
                "bytes": file.bytes,
                "sha256": file.sha256,
                "delivered": file.delivered,
            })).collect::<Vec<_>>(),
        })
    );
    Ok(())
}
