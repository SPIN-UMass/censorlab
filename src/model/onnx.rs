use crate::censor::Action;
use ort::Session;
use serde::{Deserialize, Deserializer};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

/// Environment name used for initializing ONNX
pub const ENV_NAME: &str = "censorlab";

/// Represents a classification model, generally for performing censorship actions
#[derive(Debug)]
pub struct Model {
    pub session: Session,
    pub input_dims: Vec<usize>,
    pub prob_index: usize,
}

/// Represents the metadata of the model.
///
/// Features represents each feature that will be input in the model
/// Labels represents the label of each of the output classes, and what action should be taken
#[derive(Debug, Deserialize)]
pub struct ModelMetadata {
    pub features: Vec<FeatureMetadata>,
    pub labels: Vec<LabelMetadata>,
}

/// Represents a type of output
///
/// For example ("obfs4", "reset")
#[derive(Debug, Deserialize)]
pub struct LabelMetadata {
    pub name: String,
    #[serde(default)]
    pub action: Action,
}

/// Represents an input feature
///
/// For example, "w0_p25_Size", mean=512, std=793, eps=1e-10
#[derive(Debug, Deserialize)]
pub struct FeatureMetadata {
    pub name: Feature,
    #[serde(flatten)]
    pub norm_params: NormParameters,
}

/// Parameters to the normalization function
///
/// For example,  mean=512, std=793, eps=1e-10
#[derive(Debug, Deserialize)]
pub struct NormParameters {
    mean: f32,
    std: f32,
    eps: f32,
}
impl NormParameters {
    /// Normalize the value using these normalization parameters
    pub fn normalize(&self, value: f32) -> f32 {
        (value - self.mean) / (self.std + self.eps)
    }
}

/// Represents a parsed feature
///
/// For example, w0_p21_Size is window=0, packet=0, feature=packet size
#[derive(Debug)]
pub struct Feature {
    pub window_num: usize,
    pub packet_num: usize,
    pub feature: PacketFeature,
}

/// Represents which feature to use for the packet
#[derive(Debug)]
pub enum PacketFeature {
    /// The packet's direction: from or to the client
    Direction,
    /// The packet's payload length
    Length,
    /// The packet's shannon entropy
    Entropy,
    /// The packet's signed length
    ///
    /// For example: a packet coming from the server of size 588 could be -588
    ///
    /// TODO: make this consistent with the signness we use
    DirSignSize,
    /// How deep this packet is into a burst
    ///
    /// For example, packets
    ///
    /// in, in, in, out, in, out, out, out, in
    ///
    /// would have burst depth
    ///
    /// 0,  1,  2,  0,   0,  0,   1,   2,   0
    BurstDepth,
}
#[derive(Debug, Error)]
pub enum FeatureParseError {
    #[error("Missing window index")]
    MissingWindowIndex,
    #[error("Invalid window index: {0}")]
    InvalidWindowIndex(std::num::ParseIntError),
    #[error("Missing packet index")]
    MissingPacketIndex,
    #[error("Invalid packet index: {0}")]
    InvalidPacketIndex(std::num::ParseIntError),
    #[error("Missing feature name")]
    MissingFeatureName,
    #[error("Invalid feature name")]
    InvalidFeatureName,
}
impl FromStr for Feature {
    type Err = FeatureParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // import our errors because otherwise this gets really verbose
        use FeatureParseError::*;
        // Split our condition on <= (standard in sklearn decision tree)
        let mut toks = s.split('_');
        // Get the window index
        let window_num: usize = toks
            .next()
            .ok_or(MissingWindowIndex)?
            .trim_start_matches('w')
            .parse::<usize>()
            .map_err(InvalidWindowIndex)?;
        // Get the packet index
        let packet_num: usize = toks
            .next()
            .ok_or(MissingPacketIndex)?
            .trim_start_matches('p')
            .parse::<usize>()
            .map_err(InvalidPacketIndex)?;
        // Get the actual feature name
        let name = toks.next().ok_or(MissingFeatureName)?;
        // Determine our feature based on name
        let feature = match name.to_lowercase().as_str() {
            "entropy" => Ok(PacketFeature::Entropy),
            "size" => Ok(PacketFeature::Length),
            "direction" => Ok(PacketFeature::Direction),
            "dirsignsize" => Ok(PacketFeature::DirSignSize),
            "burstdepth" => Ok(PacketFeature::BurstDepth),
            _ => Err(InvalidFeatureName),
        }?;
        Ok(Feature {
            window_num,
            packet_num,
            feature,
        })
    }
}
impl<'de> Deserialize<'de> for Feature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Loads ONNX data and model metadata
pub fn load_model<P: AsRef<Path>, PP: AsRef<Path>>(
    model_path: P,
    metadata_path: PP,
) -> Result<(Vec<u8>, ModelMetadata), ModelLoadError> {
    let model_data = fs::read(model_path).map_err(ModelLoadError::LoadOnnx)?;
    let metadata_file = File::open(metadata_path).map_err(ModelLoadError::OpenMetadata)?;
    let metadata = serde_json::from_reader(metadata_file)?;
    Ok((model_data, metadata))
}

#[derive(Debug, Error)]
pub enum ModelLoadError {
    #[error("Failed to load ONNX data: {0}")]
    LoadOnnx(io::Error),
    #[error("Failed to open metadata: {0}")]
    OpenMetadata(io::Error),
    #[error("Failed to parse metadata: {0}")]
    ParseMetadata(#[from] serde_json::Error),
}

/// Loads ONNX data for a watermarking model
pub fn load_watermarking_model<P: AsRef<Path>>(
    model_path: P,
) -> Result<Vec<u8>, WatermarkModelLoadError> {
    let model_data = fs::read(model_path).map_err(WatermarkModelLoadError::LoadOnnx)?;
    Ok(model_data)
}

#[derive(Debug, Error)]
pub enum WatermarkModelLoadError {
    #[error("Failed to load ONNX data: {0}")]
    LoadOnnx(io::Error),
}
