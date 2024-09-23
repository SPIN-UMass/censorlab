pub mod onnx;
use crate::config::model::Model as ModelConfig;
use onnx::Model;
use onnxruntime::environment::Environment;
use onnxruntime::error::OrtError;
use onnxruntime::ndarray::{
    arr2, rcarr2, Array, ArrayBase, Dim, IntoDimension, OwnedArcRepr, OwnedRepr, ShapeError,
};
use onnxruntime::tensor::OrtOwnedTensor;
use onnxruntime::GraphOptimizationLevel;
use onnxruntime::LoggingLevel;
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use tracing::error;

pub trait Classify {
    type Features;
    type Label;
    fn classify(&self, features: &Self::Features) -> Self::Label;
}

pub fn start_model_thread(
    model_config: &HashMap<String, ModelConfig>,
) -> Result<(mpsc::SyncSender<ModelThreadMessage>, JoinHandle<()>), OrtError> {
    // Create a 2-way channel
    let (sender, receiver): (
        mpsc::SyncSender<ModelThreadMessage>,
        mpsc::Receiver<ModelThreadMessage>,
    ) = mpsc::sync_channel(256);
    let model_config = model_config.clone();
    // Spawn the processing thread
    let handle = thread::spawn(move || {
        // Initialize the ONNX environment
        let onnx_env = Environment::builder()
            .with_name(onnx::ENV_NAME)
            //TODO: parameterize
            .with_log_level(LoggingLevel::Info)
            .build()
            .expect("Failed to build ONNX context");
        // For each model in the config, load it
        let mut models: HashMap<String, Model> = Default::default();
        for (name, config) in model_config {
            // Load the model data from a file
            let session = onnx_env
                .new_session_builder()
                .expect("Failed to start session")
                .with_optimization_level(GraphOptimizationLevel::All)
                .expect("Failed to start with optimization")
                .with_number_threads(1)
                .expect("Failed to set thread")
                .with_model_from_file(config.path)
                .expect("Failed to set model");
            // print some stuff
            let input = session
                .inputs
                .iter()
                .find(|input| input.name == "float_input")
                .expect("Could not find float_input");
            let dims = input.dimensions.clone();
            let (prob_index, _) = session
                .outputs
                .iter()
                .enumerate()
                .find(|(_, output)| output.name == "probabilities")
                .expect("Could not find probabilities");
            let model = Model {
                session,
                input_dims: dims.into_iter().map(|dim| dim.unwrap() as usize).collect(),
                prob_index,
            };
            models.insert(name.clone(), model);
        }
        while let Ok(message) = receiver.recv() {
            match message {
                ModelThreadMessage::Shutdown => break,
                ModelThreadMessage::Request {
                    name,
                    data,
                    response_channel,
                } => {
                    // Check if we have a model by the given name
                    let result = if let Some(ref mut model) = models.get_mut(&name) {
                        match ArrayBase::from_shape_vec(
                            (model.input_dims[0], model.input_dims[1]),
                            data,
                        ) {
                            Ok(input) => {
                                let inputs = vec![input];
                                match model.session.run(inputs) {
                                    Ok(outputs) => {
                                        let outputs: Vec<OrtOwnedTensor<f64, _>> = outputs;
                                        let prob = &outputs[model.prob_index];
                                        Ok(prob.to_slice().unwrap().to_vec())
                                    }
                                    Err(err) => Err(ModelThreadError::ModelRunError(err)),
                                }
                            }

                            Err(err) => Err(ModelThreadError::ModelShapeError(err)),
                        }
                    } else {
                        Err(ModelThreadError::ModelNotFound)
                    };
                    if let Err(err) = response_channel.send(result) {
                        error!("Error sending response from model thread: {err}");
                    }
                }
            }
        }
    });
    Ok((sender.clone(), handle))
}

pub enum ModelThreadMessage {
    Shutdown,
    Request {
        name: String,
        data: Vec<f32>,
        response_channel: mpsc::SyncSender<Result<Vec<f64>, ModelThreadError>>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ModelThreadError {
    #[error("Failed to find model with given name")]
    ModelNotFound,
    #[error("Failed to run the model: {0}")]
    ModelRunError(OrtError),
    #[error("Error with data shape: {0}")]
    ModelShapeError(ShapeError),
}
