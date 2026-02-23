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
use ort::value::TensorRef;
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
        ort::init()
            .with_name(onnx::ENV_NAME)
            .commit();
        // For each model in the config, load it
        let mut models: HashMap<String, Model> = Default::default();
        for (name, config) in model_config {
            // Load the model data from a file
            let session = Session::builder()
                .expect("Failed to start session")
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .expect("Failed to start with optimization")
                .commit_from_file(config.path)
                .expect("Failed to set model");
            // Extract input dimensions and output index before moving session
            let input = session
                .inputs()
                .iter()
                .find(|input| input.name() == "float_input")
                .expect("Could not find float_input");
            let input_dims = if let ort::value::ValueType::Tensor { ref shape, .. } = *input.dtype() {
                Some(shape.iter().map(|dim| *dim as usize).collect::<Vec<_>>())
            } else {
                None
            };
            let prob_index = session
                .outputs()
                .iter()
                .enumerate()
                .find(|(_, output)| output.name() == "probabilities")
                .map(|(idx, _)| idx)
                .expect("Could not find probabilities");
            if let Some(input_dims) = input_dims {
                let model = Model {
                    session,
                    input_dims,
                    prob_index,
                };
                models.insert(name.clone(), model);
            }
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
                    let result: Result<Vec<f32>, _> =
                        if let Some(ref mut model) = models.get_mut(&name) {
                            match Array::from_shape_vec(
                                (model.input_dims[0], model.input_dims[1]),
                                data,
                            ) {
                                Ok(input) => {
                                    let tensor = TensorRef::from_array_view(input.view())
                                        .expect("Failed to create tensor from array view");
                                    let inputs = inputs!["float_input" => tensor];
                                    match model.session.run(inputs) {
                                        Ok(outputs) => {
                                            let prob = &outputs[model.prob_index];
                                            let (_, data) = prob
                                                .try_extract_tensor::<f32>()
                                                .unwrap();
                                            Ok(data.to_vec())
                                        }
                                        Err(err) => Err(ModelThreadError::ModelRunError(err)),
                                    }
                                }

                                Err(err) => Err(ModelThreadError::ModelShapeError(err)),
                            }
                        } else {
                            Err(ModelThreadError::ModelNotFound)
                        };
                    let result = result.map(|v| v.into_iter().map(f64::from).collect());
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
