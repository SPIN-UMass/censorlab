pub mod onnx;

use crate::config::model::Model as ModelConfig;
use ndarray::{
    Array, ShapeError,
};
use onnx::Model;
use ort::inputs;
use ort::Error as OrtError;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::tensor::TensorElementType;
use ort::value::{TensorRef, ValueType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use tracing::error;

pub trait Classify {
    type Features;
    type Label;
    fn classify(&self, features: &Self::Features) -> Self::Label;
}

/// Name of the model input tensor (skl2onnx convention)
const INPUT_NAME: &str = "float_input";
/// Name of the model output tensor holding class probabilities
const OUTPUT_NAME: &str = "probabilities";

/// A configured model that could not be loaded or does not have the
/// interface CensorLab expects (`float_input: f32[1, N]` -> `probabilities: f32[..]`)
#[derive(Debug, thiserror::Error)]
pub enum ModelLoadError {
    #[error("model {name} ({}): failed to load: {err}", path.display())]
    Ort { name: String, path: PathBuf, err: OrtError },
    #[error("model {name} ({}): {problem}", path.display())]
    Interface { name: String, path: PathBuf, problem: String },
    #[error("model thread exited while loading models")]
    ThreadDied,
}

/// Load one model and check its input/output interface
fn load_model(name: &str, config: &ModelConfig) -> Result<Model, ModelLoadError> {
    let ort_err = |err| ModelLoadError::Ort { name: name.to_owned(), path: config.path.clone(), err };
    let bad = |problem: String| ModelLoadError::Interface {
        name: name.to_owned(),
        path: config.path.clone(),
        problem,
    };
    // Load the model data from a file
    let session = Session::builder()
        .map_err(ort_err)?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(ort_err)?
        .commit_from_file(&config.path)
        .map_err(ort_err)?;
    // The input must be an f32 tensor of shape [batch, features] where the batch
    // dimension is 1 or dynamic (-1, which we always feed as 1)
    let input = session
        .inputs()
        .iter()
        .find(|input| input.name() == INPUT_NAME)
        .ok_or_else(|| bad(format!("no input named {INPUT_NAME}")))?;
    let input_dims = match input.dtype() {
        ValueType::Tensor { ty: TensorElementType::Float32, shape, .. } => match **shape {
            [batch, features] if (batch == 1 || batch == -1) && (features > 0 || features == -1) => {
                vec![batch, features]
            }
            ref dims => {
                return Err(bad(format!(
                    "{INPUT_NAME} must have shape [1, N] (1 or N may be dynamic), got {dims:?}"
                )))
            }
        },
        other => return Err(bad(format!("{INPUT_NAME} must be an f32 tensor, got {other:?}"))),
    };
    // The output must be an f32 tensor
    let (prob_index, output) = session
        .outputs()
        .iter()
        .enumerate()
        .find(|(_, output)| output.name() == OUTPUT_NAME)
        .ok_or_else(|| bad(format!("no output named {OUTPUT_NAME}")))?;
    if !matches!(output.dtype(), ValueType::Tensor { ty: TensorElementType::Float32, .. }) {
        return Err(bad(format!(
            "{OUTPUT_NAME} must be an f32 tensor, got {:?}",
            output.dtype()
        )));
    }
    Ok(Model {
        session,
        input_dims,
        prob_index,
    })
}

/// Run one inference request; never panics
fn run_model(model: &mut Model, data: Vec<f32>) -> Result<Vec<f64>, ModelThreadError> {
    let shape = onnx::input_shape(&model.input_dims, data.len())
        .ok_or_else(|| ModelThreadError::UnsupportedInputShape(model.input_dims.clone()))?;
    let input = Array::from_shape_vec(shape, data).map_err(ModelThreadError::ModelShapeError)?;
    let tensor =
        TensorRef::from_array_view(input.view()).map_err(ModelThreadError::ModelRunError)?;
    let outputs = model
        .session
        .run(inputs![INPUT_NAME => tensor])
        .map_err(ModelThreadError::ModelRunError)?;
    let (_, probs) = outputs[model.prob_index]
        .try_extract_tensor::<f32>()
        .map_err(ModelThreadError::ModelRunError)?;
    Ok(probs.iter().copied().map(f64::from).collect())
}

/// Load every configured model and start the thread that serves inference
/// requests. All models are loaded and validated before this returns, so a
/// missing or malformed model fails startup instead of the first request.
pub fn start_model_thread(
    model_config: &HashMap<String, ModelConfig>,
) -> Result<(mpsc::SyncSender<ModelThreadMessage>, JoinHandle<()>), ModelLoadError> {
    // Create a 2-way channel
    let (sender, receiver): (
        mpsc::SyncSender<ModelThreadMessage>,
        mpsc::Receiver<ModelThreadMessage>,
    ) = mpsc::sync_channel(256);
    // The thread reports whether loading succeeded before serving requests
    let (loaded_tx, loaded_rx) = mpsc::sync_channel::<Result<(), ModelLoadError>>(1);
    let model_config = model_config.clone();
    // Spawn the processing thread (ONNX sessions are created and used on it)
    let handle = thread::spawn(move || {
        // Initialize the ONNX environment
        ort::init()
            .with_name(onnx::ENV_NAME)
            .commit();
        // For each model in the config, load it
        let loaded: Result<HashMap<String, Model>, ModelLoadError> = model_config
            .iter()
            .map(|(name, config)| Ok((name.clone(), load_model(name, config)?)))
            .collect();
        let mut models = match loaded {
            Ok(models) => {
                let _ = loaded_tx.send(Ok(()));
                models
            }
            Err(err) => {
                let _ = loaded_tx.send(Err(err));
                return;
            }
        };
        while let Ok(message) = receiver.recv() {
            match message {
                ModelThreadMessage::Shutdown => break,
                ModelThreadMessage::Request {
                    name,
                    data,
                    response_channel,
                } => {
                    let result = match models.get_mut(&name) {
                        Some(model) => run_model(model, data),
                        None => Err(ModelThreadError::ModelNotFound),
                    };
                    if let Err(err) = response_channel.send(result) {
                        error!("Error sending response from model thread: {err}");
                    }
                }
            }
        }
    });
    match loaded_rx.recv() {
        Ok(Ok(())) => Ok((sender, handle)),
        Ok(Err(err)) => {
            let _ = handle.join();
            Err(err)
        }
        Err(_) => Err(ModelLoadError::ThreadDied),
    }
}

pub enum ModelThreadMessage {
    Shutdown,
    Request {
        name: String,
        data: Vec<f32>,
        response_channel: mpsc::SyncSender<Result<Vec<f64>, ModelThreadError>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn models(entries: &[(&str, PathBuf)]) -> HashMap<String, ModelConfig> {
        ort::set_api(ort_tract::api());
        entries
            .iter()
            .map(|(name, path)| (name.to_string(), ModelConfig { path: path.clone() }))
            .collect()
    }

    fn workspace(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    fn request(
        sender: &mpsc::SyncSender<ModelThreadMessage>,
        name: &str,
        data: Vec<f32>,
    ) -> Result<Vec<f64>, ModelThreadError> {
        let (tx, rx) = mpsc::sync_channel(1);
        sender
            .send(ModelThreadMessage::Request { name: name.to_owned(), data, response_channel: tx })
            .expect("model thread alive");
        rx.recv().expect("model thread replied")
    }

    #[test]
    fn load_failure_is_reported_to_caller() {
        let config = models(&[("missing", workspace("does/not/exist.onnx"))]);
        assert!(start_model_thread(&config).is_err());
    }

    #[test]
    fn demo_model_evaluates_and_survives_bad_requests() {
        let config = models(&[("classifier", workspace("experiments/05_ml_classification/model.onnx"))]);
        let (sender, handle) = start_model_thread(&config).expect("model loads");
        // Wrong number of features: an error reply, not a dead thread
        assert!(matches!(
            request(&sender, "classifier", vec![0.0; 3]),
            Err(ModelThreadError::ModelShapeError(_))
        ));
        assert!(matches!(
            request(&sender, "nope", vec![0.0; 20]),
            Err(ModelThreadError::ModelNotFound)
        ));
        // 10 lengths + 10 directions
        let probs = request(&sender, "classifier", vec![0.0; 20]).expect("model runs");
        assert!(!probs.is_empty());
        sender.send(ModelThreadMessage::Shutdown).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn all_shipped_models_load() {
        let config = models(&[
            ("a", workspace("demos/model/model.onnx")),
            ("b", workspace("demos/shadowsocks_poisoned/model/poisoned.onnx.ml")),
            ("c", workspace("experiments/05_ml_classification/model.onnx")),
        ]);
        let (sender, handle) = start_model_thread(&config).expect("models load");
        sender.send(ModelThreadMessage::Shutdown).unwrap();
        handle.join().unwrap();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ModelThreadError {
    #[error("Failed to find model with given name")]
    ModelNotFound,
    #[error("Failed to run the model: {0}")]
    ModelRunError(OrtError),
    #[error("Error with data shape: {0}")]
    ModelShapeError(ShapeError),
    #[error("Unsupported model input shape {0:?}, expected 2D")]
    UnsupportedInputShape(Vec<i64>),
}
