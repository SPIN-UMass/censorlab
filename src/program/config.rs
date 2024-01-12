use crate::program::program::{Action, Operator};
use serde::Deserialize;

use std::io;

/// Configuration for Program
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    /// Configuration of the execution environment
    #[serde(default)]
    pub env: EnvConfig,
    /// Configuration of the program
    pub program: ProgramConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error("Failed to read config: {0}")]
    Read(#[from] io::Error),
    #[error("Failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Configuration of the execution environment
#[derive(Clone, Debug, Deserialize)]
pub struct EnvConfig {
    pub relax_register_types: bool,
    pub field_default_on_error: bool,
}
impl Default for EnvConfig {
    fn default() -> Self {
        EnvConfig {
            relax_register_types: false,
            field_default_on_error: true,
        }
    }
}
/// Configuration of the program
#[derive(Clone, Debug, Deserialize)]
pub struct ProgramConfig {
    /// Max number of lines
    pub num_lines: usize,
    /// Max number of registers per bank
    pub num_registers: u16,
    /// Available operators
    #[serde(default = "Operator::all")]
    pub operators: Vec<Operator>,
    /// Available actions
    #[serde(default = "Action::all")]
    pub actions: Vec<Action>,
}
impl Default for ProgramConfig {
    fn default() -> Self {
        ProgramConfig {
            num_lines: 16,
            num_registers: 16,
            operators: Operator::all(),
            actions: Action::all(),
        }
    }
}
