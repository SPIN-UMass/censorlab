use censorlab::censor::args::SubCmd;
use censorlab::censor::{Censor, CensorError, CensorInitError};
use censorlab::config::{Config, ConfigLoadError};
use censorlab::ipc::IPC_DEFAULT_PORT;
use censorlab::model::{ModelLoadError, Models};
use censorlab::program::analysis::ProgramAnalysis;
use censorlab::program::check::ModelSignatures;
use clap::Parser;
use ort::Error as OrtError;
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
    // /// Path to log TCP decisions to
    //pub tcp_decision_log_path: Option<PathBuf>,
    /// Path to a program (overrides the one in config.toml)
    #[clap(short, long)]
    pub program: Option<PathBuf>,
    /// Subcommand indicating which mode to run in
    #[clap(subcommand)]
    sub_cmd: SubCmd,
}

#[tokio::main]
async fn main() -> Result<(), CensorlabError> {
    // Initialize the tract backend for ort (pure Rust ONNX inference)
    ort::set_api(ort_tract::api());
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
    // Static analysis needs no models or censor.  The config is optional:
    // with -c the program is checked against its [execution.censorlang]
    // settings and [models]; otherwise against the defaults (model names are
    // then not checked).
    if let SubCmd::Analyze { program, json } = &args.sub_cmd {
        let source = std::fs::read_to_string(program)
            .map_err(|e| CensorlabError::Analyze(format!("{}: {e}", program.display())))?;
        let config = args.config_path.as_ref().map(Config::load).transpose()?;
        let models: Option<ModelSignatures> = config
            .as_ref()
            .map(|c| c.models.keys().map(|name| (name.clone(), None)).collect());
        let censorlang = config.map(|c| c.execution.censorlang).unwrap_or_default();
        let analysis = ProgramAnalysis::from_source(&source, &censorlang, models.as_ref())
            .map_err(|e| CensorlabError::Analyze(format!("{}: {e}", program.display())))?;
        if *json {
            println!("{}", serde_json::to_string_pretty(&analysis).map_err(|e| CensorlabError::Analyze(e.to_string()))?);
        } else {
            print!("{}", analysis.report());
        }
        return Ok(());
    }
    // Load our config
    let mut config = args
        .config_path
        .map(Config::load)
        .unwrap_or_else(|| Ok(Config::default()))?;
    // Override with program path if provided
    if let Some(program) = args.program {
        config.execution.script = Some(program);
    }
    // Load (and validate) the models
    let models = Models::load(&config.models)?;
    // Initialize our censor using the common args
    let censor = Censor::new(
        args.ipc_port,
        config,
        //args.tcp_decision_log_path,
        //removed tcp decision log path for now
        None,
        models.clone(),
    )?;
    // Run the censor in the specified mode using the common arguments
    let run_result = censor.run(args.sub_cmd).await;
    if let Err(err) = &run_result {
        error!(error = tracing::field::display(err), "Error running censor");
    }
    // Report the censor's own failure first; it is the most specific error.
    run_result?;
    if models.panicked() {
        return Err(CensorlabError::ModelPanicked);
    }
    Ok(())
}
#[derive(Debug, Error)]
enum CensorlabError {
    #[error("Failed to set global logger: {0}")]
    SetGlobalLogger(#[from] SetGlobalDefaultError),
    #[error("Failed to load config: {0}")]
    Config(#[from] ConfigLoadError),
    #[error("Failed to do something with ONNX: {0}")]
    EnvironmentBuild(#[from] OrtError),
    #[error("Failed to load models: {0}")]
    ModelLoad(#[from] ModelLoadError),
    #[error("Failed to initialize censor: {0}")]
    CensorInit(#[from] CensorInitError),
    #[error("Failed to analyse program: {0}")]
    Analyze(String),
    #[error("Failed to run censor: {0}")]
    Run(#[from] CensorError),
    #[error("Model inference panicked")]
    ModelPanicked,
}
