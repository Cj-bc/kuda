// リリースビルドではタスク起動のたびにコンソール窓が出ないよう GUI サブシステムにする
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
// 実装途中の間だけ。全サブコマンドが繋がったら外す
#![allow(dead_code)]

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

mod baseline;
mod collector;
mod config;
mod logging;
mod paths;
mod probe;
mod process;
mod store;
mod trigger;

#[derive(Parser)]
#[command(
    name = "kuda",
    version,
    about = "PC monitoring harness with LLM-driven investigation"
)]
struct Cli {
    /// Log at debug level and mirror the log to stderr
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one monitoring cycle (this is what the scheduler invokes)
    Check {
        /// Probe every watch even if its interval has not elapsed
        #[arg(long)]
        force: bool,
    },
    /// Take snapshots and store them as last_known_good
    Snapshot {
        /// Ignore snapshot_interval
        #[arg(long)]
        force: bool,
        /// Limit to one watch
        #[arg(long)]
        watch: Option<String>,
    },
    /// Build an incident directory and investigate it with an LLM
    Diagnose {
        #[arg(long)]
        watch: String,
        /// Only build the incident directory; do not call an LLM
        #[arg(long)]
        dry_run: bool,
        /// Use this backend instead of the one in the config
        #[arg(long)]
        backend: Option<String>,
        /// Investigate an existing incident directory
        #[arg(long)]
        incident: Option<std::path::PathBuf>,
    },
    /// Show samples, baselines, snapshots and cooldowns for each watch
    Status,
    /// Validate the config file and everything it refers to
    CheckConfig,
    /// Show whether each LLM backend is available
    CheckBackends,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { .. }
        | Command::Snapshot { .. }
        | Command::Diagnose { .. }
        | Command::Status
        | Command::CheckConfig
        | Command::CheckBackends => bail!("not implemented yet"),
    }
}
