use censorlab::censor::args::SubCmd;
use censorlab::censor::{Censor, CensorInitError};
use censorlab::config::Config;
use censorlab::ipc::IPC_DEFAULT_PORT;
use censorlab::model::{onnx, start_model_thread};
use clap::Parser;
use onnxruntime::environment::Environment;
use onnxruntime::error::OrtError;
use onnxruntime::LoggingLevel;
use std::io;
use std::path::PathBuf;
use thiserror::Error;
use tracing::subscriber::SetGlobalDefaultError;
use tracing::{error, Level};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Verbosity of the logger
    #[clap(short, long, default_value_t = Level::INFO)]
    verbosity: Level,
    /// Port to listen on for IPC commands
    #[clap(long, default_value_t = IPC_DEFAULT_PORT)]
    pub ipc_port: u16,
    /// Path to the config file
    #[clap(short, long)]
    pub config_path: Option<PathBuf>,
    /// Path to log TCP decisions to
    pub tcp_decision_log_path: Option<PathBuf>,
    /// Subcommand indicating which mode to run in
    #[clap(subcommand)]
    sub_cmd: SubCmd,
}

#[tokio::main]
async fn main() -> Result<(), CensorlabError> {
    // Parse CLI arguments
    let args = Args::parse();
    // Build our log filtr
    let env_filter = EnvFilter::new(format!("{}={}", clap::crate_name!(), args.verbosity));
    // Build our log subscriber
    let subscriber = FmtSubscriber::builder()
        // Use verbosity
        //.with_max_level(args.verbosity)
        .with_env_filter(env_filter)
        // completes the builder.
        .finish();
    // Set the global subscriber
    tracing::subscriber::set_global_default(subscriber)?;
    // Load our config
    let config = args
        .config_path
        .map(Config::load)
        .unwrap_or_else(|| Ok(Config::default()))
        .map_err(CensorlabError::Config)?;
    // Start the model thread
    let (model_sender, model_thread) = start_model_thread(&config.models)?;
    // Initialize our censor using the common args
    let censor = Censor::new(
        args.ipc_port,
        config,
        args.tcp_decision_log_path,
        model_sender,
    )?;
    // Run the censor in the specified mode using the common arguments
    if let Err(err) = censor.run(args.sub_cmd).await {
        error!(error = tracing::field::display(err), "Error running censor");
    }
    // Join the handle
    Ok(())
}
#[derive(Debug, Error)]
enum CensorlabError {
    #[error("Failed to set global logger: {0}")]
    SetGlobalLogger(#[from] SetGlobalDefaultError),
    #[error("Failed to load config: {0}")]
    Config(io::Error),
    #[error("Failed to do something with ONNX: {0}")]
    EnvironmentBuild(#[from] OrtError),
    #[error("Failed to initialize censor: {0}")]
    CensorInit(#[from] CensorInitError),
}
