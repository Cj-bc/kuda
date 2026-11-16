//! Kuda の本体。`kuda` と `kudaw` の 2 つのバイナリから呼ばれる。

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;
use paths::Paths;
use std::process::ExitCode;

mod baseline;
mod collector;
mod commands;
mod config;
mod detach;
mod diagnosis;
mod incident;
mod known_set;
mod lock;
mod logging;
mod notify;
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
    /// Take snapshots and store each successful collector as last_known_good
    Snapshot {
        /// Ignore snapshot_interval and the retry interval
        #[arg(long)]
        force: bool,
        /// Limit to one watch
        #[arg(long)]
        watch: Option<String>,
    },
    /// Build an incident directory and investigate it with an LLM
    Diagnose {
        /// Name of the watch to investigate (the `name` of a [[watch]] in the config;
        /// it must have a [watch.diagnose] table)
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
        /// Show desktop notifications when the investigation starts and ends
        #[arg(long)]
        notify: bool,
    },
    /// Show samples, baselines, snapshots and cooldowns for each watch
    Status,
    /// Validate the config file and everything it refers to
    CheckConfig,
    /// Show whether each LLM backend is available
    CheckBackends,
}

fn run(cli: Cli) -> Result<()> {
    let paths = Paths::from_env()?;
    paths.ensure_dirs()?;
    logging::init(&paths.logs_dir, cli.verbose)?;

    let config_path = paths.config_file();
    commands::log_paths(&paths, &config_path);
    let config = Config::load(&config_path)?;
    logging::set_level(config.general.log_level, cli.verbose);

    match cli.command {
        Command::Check { force } => commands::check(&config, &paths, force),
        Command::Snapshot { force, watch } => {
            commands::snapshot(&config, &paths, force, watch.as_deref())
        }
        Command::Diagnose {
            watch,
            dry_run,
            backend,
            incident,
            notify,
        } => commands::diagnose(
            &config,
            &paths,
            commands::DiagnoseOptions {
                watch,
                dry_run,
                backend,
                incident,
                notify,
            },
        ),
        Command::Status => commands::status(&config, &paths),
        Command::CheckConfig => commands::check_config(&config, &paths),
        Command::CheckBackends => commands::check_backends(&config),
    }
}

pub fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // ログ初期化前の失敗もあるので、標準エラーにも必ず出す
            log::error!("{error:#}");
            if log::max_level() == log::LevelFilter::Off {
                eprintln!("error: {error:#}");
            }
            ExitCode::FAILURE
        }
    }
}
