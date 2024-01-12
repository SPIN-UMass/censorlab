use censorlab::ipc::{IpcOpcode, ModelScope, IPC_DEFAULT_PORT, IPC_FAILURE, IPC_SUCCESS};
use clap::Parser;
use std::io;
use std::net::Ipv4Addr;
use std::num::TryFromIntError;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::subscriber::SetGlobalDefaultError;
use tracing::{trace, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Verbosity of the logger
    #[clap(short, long, default_value_t = Level::INFO)]
    verbosity: Level,
    /// What port the IPC is running on
    #[clap(short, long, default_value_t = IPC_DEFAULT_PORT)]
    port: u16,
    /// Subcommand
    #[clap(subcommand)]
    subcommand: SubCmd,
}
#[derive(Debug, Parser)]
enum SubCmd {
    /// Send a decision tree to the censor
    SendModel {
        /// What the model is for: either "tcp" or "udp"
        #[arg(value_enum)]
        scope: ModelScope,
        /// Path to the model file (onnx)
        model_path: PathBuf,
        /// Path to the model metadata (in json)
        metadata_path: PathBuf,
    },
    /// Shutdown
    Shutdown,
}

#[tokio::main]
async fn main() -> Result<(), IpcClientError> {
    // Parse arguments
    let args = Args::parse();
    // Build our log subscriber
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(args.verbosity)
        // completes the builder.
        .finish();
    // Set the global subscriber
    tracing::subscriber::set_global_default(subscriber)?;
    // Import the error for ease
    use IpcClientError::*;
    // Connect to the socket
    let mut connection = TcpStream::connect((Ipv4Addr::LOCALHOST, args.port))
        .await
        .map_err(Connect)?;
    match args.subcommand {
        SubCmd::SendModel {
            scope,
            model_path,
            metadata_path,
        } => {
            // Open the model file
            let mut model_file = File::open(model_path).await.map_err(OpenModelFile)?;
            // Get size as u32
            let model_size: u32 = model_file
                .metadata()
                .await
                .map_err(OpenModelFile)?
                .len()
                .try_into()
                .map_err(ConvertLength)?;
            let model_size = model_size.to_le_bytes();
            // Open the metadata file
            let mut metadata_file = File::open(metadata_path).await.map_err(OpenMetadataFile)?;
            // Get size as u32
            let metadata_size: u32 = metadata_file
                .metadata()
                .await
                .map_err(OpenMetadataFile)?
                .len()
                .try_into()
                .map_err(ConvertLength)?;
            let metadata_size = metadata_size.to_le_bytes();
            // Send the opcode
            let opcode: u8 = IpcOpcode::UpdateModel.into();
            trace!("Sending opcode");
            connection.write_all(&[opcode]).await.map_err(SendOpcode)?;
            // Send the scope
            let scope: u8 = scope.into();
            trace!("Sending scope");
            connection.write_all(&[scope]).await.map_err(SendScope)?;
            // Send the model data
            trace!("Sending model length");
            connection
                .write_all(&model_size)
                .await
                .map_err(SendModelLength)?;
            trace!("Sending model");
            tokio::io::copy(&mut model_file, &mut connection)
                .await
                .map_err(SendModelData)?;
            // Send the metadata
            trace!("Sending metadata length");
            connection
                .write_all(&metadata_size)
                .await
                .map_err(SendMetadataLength)?;
            trace!("Sending metadata");
            tokio::io::copy(&mut metadata_file, &mut connection)
                .await
                .map_err(SendMetadata)?;
        }
        SubCmd::Shutdown => {
            let opcode: u8 = IpcOpcode::Shutdown.into();
            trace!("Sending opcode");
            connection.write_all(&[opcode]).await.map_err(SendOpcode)?;
        }
    }
    // Wait for ack
    trace!("Waiting for ack");
    let mut resp = [0; 2];
    connection
        .read_exact(&mut resp)
        .await
        .map_err(RecvResponse)?;
    match resp {
        IPC_SUCCESS => println!("Success"),
        IPC_FAILURE => println!("Failure"),
        other_resp => println!("Received unknown response: {:?}", other_resp),
    }
    Ok(())
}

#[derive(Error, Debug)]
enum IpcClientError {
    #[error("Error configuring logger")]
    Logger(#[from] SetGlobalDefaultError),
    #[error("Failed to open model file: {0}")]
    OpenModelFile(io::Error),
    #[error("Failed to open metadata file: {0}")]
    OpenMetadataFile(io::Error),
    #[error("failed to convert length")]
    ConvertLength(#[from] TryFromIntError),
    #[error("Failed to connect: {0}")]
    Connect(io::Error),
    #[error("Failed to send opcode: {0}")]
    SendOpcode(io::Error),
    #[error("Failed to send scope : {0}")]
    SendScope(io::Error),
    #[error("Failed to send model length: {0}")]
    SendModelLength(io::Error),
    #[error("Failed to send model data: {0}")]
    SendModelData(io::Error),
    #[error("Failed to send metadata length: {0}")]
    SendMetadataLength(io::Error),
    #[error("Failed to send metadata data: {0}")]
    SendMetadata(io::Error),
    #[error("Failed to receive response: {0}")]
    RecvResponse(io::Error),
}
