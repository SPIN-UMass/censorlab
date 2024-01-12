use crate::model::onnx::ModelMetadata;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::num::TryFromIntError;
use std::str::FromStr;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::UnboundedSender;
use tokio_byteorder::{AsyncReadBytesExt, LittleEndian};
use tracing::{debug, error};

/// Default port IPC server runs on
pub const IPC_DEFAULT_PORT: u16 = 25716;
/// IPC success message
pub const IPC_SUCCESS: [u8; 2] = *b"OK";
/// IPC failure message
pub const IPC_FAILURE: [u8; 2] = *b"NO";

/// This represents a message type for the ipc socket
pub enum IpcOpcode {
    UpdateModel,
    Shutdown,
}
impl IpcOpcode {
    const UPDATE_MODEL: u8 = 0;
    const SHUTDOWN: u8 = 1;
}
impl From<IpcOpcode> for u8 {
    fn from(msg: IpcOpcode) -> Self {
        match msg {
            IpcOpcode::UpdateModel => IpcOpcode::UPDATE_MODEL,
            IpcOpcode::Shutdown => IpcOpcode::SHUTDOWN,
        }
    }
}
#[derive(Debug, Error)]
#[error("Invalid message type: {0}")]
pub struct InvalidIpcOpcodeError(u8);

impl TryFrom<u8> for IpcOpcode {
    type Error = InvalidIpcOpcodeError;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            IpcOpcode::UPDATE_MODEL => Ok(Self::UpdateModel),
            IpcOpcode::SHUTDOWN => Ok(Self::Shutdown),
            other => Err(InvalidIpcOpcodeError(other)),
        }
    }
}

/// This represents a scope to update the model in
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ModelScope {
    Tcp,
    Udp,
}
impl ModelScope {
    const TCP: u8 = 0;
    const UDP: u8 = 1;
}
impl From<ModelScope> for u8 {
    fn from(msg: ModelScope) -> Self {
        match msg {
            ModelScope::Tcp => ModelScope::TCP,
            ModelScope::Udp => ModelScope::UDP,
        }
    }
}
#[derive(Debug, Error)]
#[error("Invalid message type: {0}")]
pub struct InvalidModelScopeError(u8);

impl TryFrom<u8> for ModelScope {
    type Error = InvalidModelScopeError;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            ModelScope::TCP => Ok(ModelScope::Tcp),
            ModelScope::UDP => Ok(ModelScope::Udp),
            other => Err(InvalidModelScopeError(other)),
        }
    }
}
impl FromStr for ModelScope {
    type Err = InvalidModelScopeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "tcp" => Ok(ModelScope::Tcp),
            "udp" => Ok(ModelScope::Udp),
            _ => Err(InvalidModelScopeError(0)),
        }
    }
}
impl fmt::Display for ModelScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            ModelScope::Tcp => "tcp",
            ModelScope::Udp => "udp",
        })
    }
}

/// Message sent to the main censor thread
#[derive(Debug)]
pub enum Message {
    UpdateModel {
        scope: ModelScope,
        onnx_data: Vec<u8>,
        metadata: ModelMetadata,
    },
    Shutdown,
}

pub async fn ipc_thread(
    port: u16,
    sender: UnboundedSender<Message>,
) -> Result<(), ModelThreadError> {
    use ModelThreadError::*;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(Bind)?;
    loop {
        let (stream, _socket_addr) = listener.accept().await.map_err(Accept)?;
        match handle_client_wrapped(stream, sender.clone()).await {
            Ok(true) => break,
            Ok(false) => {}
            Err(err) => error!(
                err = tracing::field::display(err),
                "Error handling connection with client"
            ),
        }
    }
    Ok(())
}
async fn handle_client_wrapped(
    mut stream: TcpStream,
    sender: UnboundedSender<Message>,
    //model: Arc<RwLock<Option<DecisionTree<C, L>>>>,
) -> Result<bool, HandleClientError> {
    let result = handle_client(&mut stream, sender).await;
    let (terminate, response) = match result {
        Ok(terminate) => {
            debug!("Successfully handled IPC request");
            (terminate, &IPC_SUCCESS)
        }
        Err(ref err) => {
            error!(
                err = tracing::field::display(&err),
                "Error handling IPC request"
            );
            (false, &IPC_FAILURE)
        }
    };
    stream
        .write_all(response)
        .await
        .map_err(HandleClientError::SendResponse)?;
    stream
        .flush()
        .await
        .map_err(HandleClientError::SendResponse)?;
    Ok(terminate)
}
async fn handle_client(
    stream: &mut TcpStream,
    sender: UnboundedSender<Message>,
    //model: Arc<RwLock<Option<DecisionTree<C, L>>>>,
) -> Result<bool, HandleClientError> {
    use HandleClientError::*;
    // First, read in the ipc opcode
    let mut opcode = [0; 1];
    stream.read_exact(&mut opcode).await.map_err(RecvOpcode)?;
    match opcode[0].try_into()? {
        IpcOpcode::UpdateModel => {
            // First, read in where this model is getting sent
            let mut model_scope = [0; 1];
            stream
                .read_exact(&mut model_scope)
                .await
                .map_err(RecvScope)?;
            let model_scope: ModelScope = model_scope[0].try_into()?;
            // The first part of this transmission is the onnx model file
            let onnx_size = AsyncReadBytesExt::read_u32::<LittleEndian>(stream)
                .await
                .map_err(RecvOnnxLength)?
                .try_into()?;
            // Read in the data
            let mut onnx_data = vec![0; onnx_size];
            stream
                .read_exact(&mut onnx_data)
                .await
                .map_err(RecvOnnxData)?;
            // The second part of this transmission is the model metadata
            // First we read in a size. Technically not needed if the client terminates here but I
            // think theoretically we could later have streams of messages
            let metadata_size: usize = AsyncReadBytesExt::read_u32::<LittleEndian>(stream)
                .await
                .map_err(RecvMetadataLength)?
                .try_into()
                .unwrap();
            // This is a Read object limited in its number of bytes
            // Read in metadata
            let mut stream_metadata = vec![0; metadata_size];
            stream
                .read_exact(&mut stream_metadata)
                .await
                .map_err(RecvMetadata)?;
            // Use serde to parse the rest of the data
            let metadata: ModelMetadata = serde_json::from_slice(&stream_metadata)?;
            sender.send(Message::UpdateModel {
                scope: model_scope,
                onnx_data,
                metadata,
            })?;
            Ok(false)
        }
        IpcOpcode::Shutdown => {
            sender.send(Message::Shutdown)?;
            Ok(true)
        }
    }
}

#[derive(Debug, Error)]
pub enum ModelThreadError {
    #[error("failed to bind to port")]
    Bind(io::Error),
    #[error("failed to accept connection")]
    Accept(io::Error),
    #[error("failure while handling client")]
    HandleClient(#[from] HandleClientError),
}

#[derive(Debug, Error)]
pub enum HandleClientError {
    #[error("failed to read opcode")]
    RecvOpcode(io::Error),
    #[error("failed to read scope")]
    RecvScope(io::Error),
    #[error("received invalid opcode")]
    InvalidOpcode(#[from] InvalidIpcOpcodeError),
    #[error("Invalid model scope")]
    InvalidModelScope(#[from] InvalidModelScopeError),
    #[error("failed to read onnx model length")]
    RecvOnnxLength(io::Error),
    #[error("failed to convert length into system length")]
    ConvertLength(#[from] TryFromIntError),
    #[error("failed to read onnx model data")]
    RecvOnnxData(io::Error),
    #[error("failed to read metadata length")]
    RecvMetadataLength(io::Error),
    #[error("failed to read metadata: {0}")]
    RecvMetadata(io::Error),
    #[error("failed to parse metadata: {0}")]
    ParseMetadata(#[from] serde_json::Error),
    #[error("failed to send model data over the channel")]
    ChannelSend(#[from] SendError<Message>),
    #[error("failed to send response back to client")]
    SendResponse(io::Error),
}
