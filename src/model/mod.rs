pub mod onnx;

use crate::config::model::Model as ModelConfig;
use ndarray::{
    Array, ShapeError,
};
use onnx::Model;
use ort::inputs;
use ort::environment::Environment;
use ort::Error as OrtError;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::TensorElementType;
use ort::value::{TensorRef, ValueType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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
    #[error("failed to initialize ONNX environment: {0}")]
    Environment(String),
}

/// The process-wide ONNX environment. ort allows building only one per
/// process (ever), so it is created on first use and shared by all
/// models.
fn onnx_environment() -> Result<Environment, ModelLoadError> {
    static ENVIRONMENT: OnceLock<Result<Environment, String>> = OnceLock::new();
    ENVIRONMENT
        .get_or_init(|| {
            ort::init()
                .with_name(onnx::ENV_NAME)
                .build()
                .map_err(|err| err.to_string())
        })
        .clone()
        .map_err(ModelLoadError::Environment)
}

/// Load one model and check its input/output interface
fn load_model(
    environment: &Environment,
    name: &str,
    config: &ModelConfig,
) -> Result<Model, ModelLoadError> {
    let ort_err = |err| ModelLoadError::Ort { name: name.to_owned(), path: config.path.clone(), err };
    let bad = |problem: String| ModelLoadError::Interface {
        name: name.to_owned(),
        path: config.path.clone(),
        problem,
    };
    // Load the model data from a file
    let session = Session::builder(environment)
        .map_err(ort_err)?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|err| ort_err(err.into()))?
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

/// Run one inference request
fn run_model(model: &mut Model, data: Vec<f32>) -> Result<Vec<f64>, ModelError> {
    let shape = onnx::input_shape(&model.input_dims, data.len())
        .ok_or_else(|| ModelError::UnsupportedInputShape(model.input_dims.clone()))?;
    let input = Array::from_shape_vec(shape, data).map_err(ModelError::ModelShapeError)?;
    let tensor =
        TensorRef::from_array_view(input.view()).map_err(ModelError::ModelRunError)?;
    let outputs = model
        .session
        .run(inputs![INPUT_NAME => tensor])
        .map_err(ModelError::ModelRunError)?;
    let (_, probs) = outputs[model.prob_index]
        .try_extract_tensor::<f32>()
        .map_err(ModelError::ModelRunError)?;
    Ok(probs.iter().copied().map(f64::from).collect())
}

/// The configured models, loaded and validated at startup.
///
/// Inference runs on the thread that asks for it (the packet-processing
/// thread), so a request is a function call rather than a round trip to a
/// separate model thread; the packet waits for the result either way. Clones
/// share the models.
#[derive(Clone, Default)]
pub struct Models {
    models: Arc<HashMap<String, Mutex<Model>>>,
    /// Set once inference has panicked; every later request then fails
    panicked: Arc<AtomicBool>,
}

impl std::fmt::Debug for Models {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Models")
            .field("names", &self.models.keys().collect::<Vec<_>>())
            .field("panicked", &self.panicked())
            .finish()
    }
}

impl Models {
    /// Load every configured model. All models are loaded and validated
    /// before this returns, so a missing or malformed model fails startup
    /// instead of the first request.
    pub fn load(model_config: &HashMap<String, ModelConfig>) -> Result<Self, ModelLoadError> {
        let models = if model_config.is_empty() {
            HashMap::new()
        } else {
            let environment = onnx_environment()?;
            model_config
                .iter()
                .map(|(name, config)| {
                    Ok((name.clone(), Mutex::new(load_model(&environment, name, config)?)))
                })
                .collect::<Result<_, ModelLoadError>>()?
        };
        Ok(Self {
            models: Arc::new(models),
            panicked: Arc::default(),
        })
    }

    /// Run model `name` on one sample of features and return its class
    /// probabilities. Never panics: a panic inside the inference engine is
    /// reported as [`ModelError::Panicked`], for this and every later request.
    pub fn evaluate(&self, name: &str, data: Vec<f32>) -> Result<Vec<f64>, ModelError> {
        if self.panicked() {
            return Err(ModelError::Panicked);
        }
        let model = self.models.get(name).ok_or(ModelError::ModelNotFound)?;
        let mut model = model.lock().map_err(|_| ModelError::Panicked)?;
        match panic::catch_unwind(AssertUnwindSafe(|| run_model(&mut model, data))) {
            Ok(result) => result,
            Err(_) => {
                self.panicked.store(true, Ordering::Relaxed);
                Err(ModelError::Panicked)
            }
        }
    }

    /// Whether inference has panicked (models are disabled from then on)
    pub fn panicked(&self) -> bool {
        self.panicked.load(Ordering::Relaxed)
    }
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

    #[test]
    fn load_failure_is_reported_to_caller() {
        let config = models(&[("missing", workspace("does/not/exist.onnx"))]);
        assert!(Models::load(&config).is_err());
    }

    #[test]
    fn demo_model_evaluates_and_survives_bad_requests() {
        let config = models(&[("classifier", workspace("experiments/05_ml_classification/model.onnx"))]);
        let models = Models::load(&config).expect("model loads");
        // Wrong number of features: an error, and the model keeps working
        assert!(matches!(
            models.evaluate("classifier", vec![0.0; 3]),
            Err(ModelError::ModelShapeError(_))
        ));
        assert!(matches!(
            models.evaluate("nope", vec![0.0; 20]),
            Err(ModelError::ModelNotFound)
        ));
        // 10 lengths + 10 directions
        let probs = models.evaluate("classifier", vec![0.0; 20]).expect("model runs");
        assert!(!probs.is_empty());
        // Clones share the models
        assert_eq!(models.clone().evaluate("classifier", vec![0.0; 20]).unwrap(), probs);
    }

    #[test]
    fn requests_fail_once_inference_has_panicked() {
        let config = models(&[("classifier", workspace("experiments/05_ml_classification/model.onnx"))]);
        let models = Models::load(&config).expect("model loads");
        models.panicked.store(true, Ordering::Relaxed);
        assert!(models.panicked());
        assert!(matches!(
            models.evaluate("classifier", vec![0.0; 20]),
            Err(ModelError::Panicked)
        ));
    }

    #[test]
    fn all_shipped_models_load() {
        let config = models(&[
            ("a", workspace("demos/model/model.onnx")),
            ("b", workspace("demos/shadowsocks_poisoned/model/poisoned.onnx.ml")),
            ("c", workspace("experiments/05_ml_classification/model.onnx")),
        ]);
        Models::load(&config).expect("models load");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("Failed to find model with given name")]
    ModelNotFound,
    #[error("Failed to run the model: {0}")]
    ModelRunError(OrtError),
    #[error("Error with data shape: {0}")]
    ModelShapeError(ShapeError),
    #[error("Unsupported model input shape {0:?}, expected 2D")]
    UnsupportedInputShape(Vec<i64>),
    #[error("Model inference panicked earlier; models are disabled")]
    Panicked,
}
