//! Process adapter for one `Core::join_invitation` or preview call.
//!
//! Tiny on purpose: the join ceremony and persistence are the library's
//! `recv::join::drive` and `recv::enrollment::persist_join_ack`, reached
//! through `Core`. This binary exists so a shell gate can run the real Core
//! joiner against a real CLI owner and assert on the JSON facts.
//!
//! It never prints the invitation token or any seed. A preview prints the
//! requested signed authority only; a join prints the stored result.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;
use tunlion_core::Core;

struct Args {
    config_dir: PathBuf,
    invite_file: PathBuf,
    name: String,
    timeout: Option<u64>,
    preview: bool,
}

fn usage() -> &'static str {
    "usage: join-invitation --config-dir DIR --invite-file FILE [--name NAME] [--timeout SECS] [--preview]"
}

fn parse_args() -> Result<Args, String> {
    let mut config_dir = None;
    let mut invite_file = None;
    let mut name = "device".to_string();
    let mut timeout = None;
    let mut preview = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |field: &str| {
            args.next()
                .ok_or_else(|| format!("{field} needs a value; {}", usage()))
        };
        match arg.as_str() {
            "--config-dir" => config_dir = Some(PathBuf::from(value("--config-dir")?)),
            "--invite-file" => invite_file = Some(PathBuf::from(value("--invite-file")?)),
            "--name" => name = value("--name")?,
            "--timeout" => {
                let raw = value("--timeout")?;
                timeout = Some(
                    raw.parse::<u64>()
                        .map_err(|_| format!("--timeout must be seconds; {}", usage()))?,
                );
            }
            "--preview" => preview = true,
            "-h" | "--help" => return Err(usage().to_string()),
            other => return Err(format!("unknown argument {other:?}; {}", usage())),
        }
    }
    Ok(Args {
        config_dir: config_dir.ok_or_else(|| format!("missing --config-dir; {}", usage()))?,
        invite_file: invite_file.ok_or_else(|| format!("missing --invite-file; {}", usage()))?,
        name,
        timeout,
        preview,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("join-invitation: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let bytes = std::fs::read(&args.invite_file)
        .map_err(|e| format!("read invitation file {}: {e}", args.invite_file.display()))?;
    let core = Core::open(&args.config_dir).map_err(|e| e.to_string())?;
    if args.preview {
        let preview = core.preview_invitation(bytes).map_err(|e| e.to_string())?;
        println!(
            "{}",
            json!({
                "owner_name": preview.owner_name,
                "relationship": format!("{:?}", preview.relationship),
                "requested_capabilities": preview.requested_capabilities,
                "expires": preview.expires,
                "max_offline": preview.max_offline,
                "max_uses": preview.max_uses,
                "reusable": preview.reusable,
                "ephemeral": preview.ephemeral,
                "expired": preview.expired,
            })
        );
        return Ok(());
    }
    let joined = core
        .join_invitation(bytes, args.name, args.timeout)
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({
            "name": joined.name,
            "owner_name": joined.owner_name,
            "device_pub": joined.device_pub,
            "ceiling": joined.ceiling,
            "expires": joined.expires,
            "ephemeral": joined.ephemeral,
        })
    );
    Ok(())
}
