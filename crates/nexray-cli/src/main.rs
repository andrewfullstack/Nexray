//! `nexray-cli` — Phase 1 deliverable.
//!
//! `nexray-cli classify <URL_OR_PATH> [--json]` fetches or reads a
//! subscription, classifies each entry, and prints either a human-readable
//! table or a `--json` ClassifyResult document.
//!
//! HTTPS-only on the wire (DEVELOPMENT.md §12 rule 1). 10s connect+read
//! timeout. ≤3 redirects. No cookies. Pinned User-Agent that identifies us.

use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use nexray_core::{
    classify_subscription, errors::CoreError, summarize_skipped, ClassifyResult, Profile,
};
use thiserror::Error;

const USER_AGENT: &str = concat!("Nexray/", env!("CARGO_PKG_VERSION"));

#[derive(Parser, Debug)]
#[command(
    name = "nexray-cli",
    version,
    about = "Classify a 机场 subscription into VLESS profiles"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fetch (HTTPS) or read a subscription, then classify each entry.
    Classify {
        /// Subscription URL (https://) or local file path (use `-` for stdin).
        source: String,
        /// Emit JSON to stdout instead of a human-readable table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error(transparent)]
    Core(#[from] CoreError),

    #[error("could not read file: {0}")]
    Io(#[from] io::Error),

    #[error("could not fetch subscription: {0}")]
    Http(#[from] reqwest::Error),

    #[error("could not encode JSON: {0}")]
    Json(#[from] serde_json::Error),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nexray-cli: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Classify { source, json } => classify(&source, json),
    }
}

fn classify(source: &str, as_json: bool) -> Result<(), CliError> {
    let body = if is_url(source) {
        nexray_core::subscription::require_https(source)?;
        fetch_https(source)?
    } else if source == "-" {
        read_stdin()?
    } else {
        fs::read_to_string(source)?
    };

    let result = classify_subscription(&body);

    if as_json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        print_table(&result);
    }
    Ok(())
}

fn is_url(s: &str) -> bool {
    let lower = s.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn read_stdin() -> Result<String, io::Error> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

fn fetch_https(url: &str) -> Result<String, reqwest::Error> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(3))
        .https_only(true)
        .build()?;
    client.get(url).send()?.error_for_status()?.text()
}

fn print_table(r: &ClassifyResult) {
    if r.accepted.is_empty() && r.skipped.is_empty() {
        println!("0 servers found.");
        return;
    }

    if !r.accepted.is_empty() {
        println!("{} servers accepted:", r.accepted.len());
        println!(
            "  {:<10}  {:<28}  {:<24}  {:<28}  fingerprint",
            "kind", "name", "address:port", "sni / dest"
        );
        for p in &r.accepted {
            let row = profile_row(p);
            println!(
                "  {:<10}  {:<28}  {:<24}  {:<28}  {}",
                row.kind, row.name, row.endpoint, row.sni, row.fingerprint
            );
        }
    }

    if !r.skipped.is_empty() {
        if !r.accepted.is_empty() {
            println!();
        }
        println!("{}", summarize_skipped(&r.skipped));
    }
}

struct Row {
    kind: &'static str,
    name: String,
    endpoint: String,
    sni: String,
    fingerprint: &'static str,
}

fn profile_row(profile: &Profile) -> Row {
    match profile {
        Profile::CdnWs(p) => Row {
            kind: "cdn-ws",
            name: truncate(&p.name, 26),
            endpoint: format!("{}:{}", p.address, p.port),
            sni: p.sni.clone(),
            fingerprint: fingerprint_str(p.fingerprint),
        },
        Profile::Reality(p) => Row {
            kind: "reality",
            name: truncate(&p.name, 26),
            endpoint: format!("{}:{}", p.address, p.port),
            sni: p.sni.clone(),
            fingerprint: fingerprint_str(p.fingerprint),
        },
        Profile::Trojan(p) => Row {
            kind: "trojan",
            name: truncate(&p.name, 26),
            endpoint: format!("{}:{}", p.address, p.port),
            sni: p.sni.clone(),
            fingerprint: fingerprint_str(p.fingerprint),
        },
    }
}

fn fingerprint_str(fp: nexray_core::Fingerprint) -> &'static str {
    nexray_core::FINGERPRINTS
        .iter()
        .find(|(f, _)| *f == fp)
        .map(|(_, n)| *n)
        .unwrap_or("?")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
