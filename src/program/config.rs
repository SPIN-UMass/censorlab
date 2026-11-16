use crate::program::program::{Action, Operator};
use serde::Deserialize;

use std::io;

/// Configuration for CensorLang programs
///
/// Read from the `[execution.censorlang]` table of censor.toml, which is flat:
///
/// ```toml
/// [execution.censorlang]
/// relax_register_types = false
/// field_default_on_error = true
/// num_registers = 16
/// num_lines = 256
/// operators = ["<", "==", "&&"]      # optional, default: all
/// actions = ["allow", "terminate"]   # optional, default: all
/// ```
///
/// Unknown keys are rejected.  The limits are enforced when the program is
/// loaded (see [`crate::program::check`]), not per packet.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(from = "FlatConfig")]
pub struct Config {
    /// Configuration of the execution environment
    pub env: EnvConfig,
    /// Configuration of the program
    pub program: ProgramConfig,
}

/// On-disk (flat) form of [`Config`]
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FlatConfig {
    relax_register_types: bool,
    field_default_on_error: bool,
    num_lines: usize,
    num_registers: u16,
    operators: Vec<Operator>,
    actions: Vec<Action>,
}
impl Default for FlatConfig {
    fn default() -> Self {
        let Config { env, program } = Config::default();
        FlatConfig {
            relax_register_types: env.relax_register_types,
            field_default_on_error: env.field_default_on_error,
            num_lines: program.num_lines,
            num_registers: program.num_registers,
            operators: program.operators,
            actions: program.actions,
        }
    }
}
impl From<FlatConfig> for Config {
    fn from(flat: FlatConfig) -> Self {
        Config {
            env: EnvConfig {
                relax_register_types: flat.relax_register_types,
                field_default_on_error: flat.field_default_on_error,
            },
            program: ProgramConfig {
                num_lines: flat.num_lines,
                num_registers: flat.num_registers,
                operators: flat.operators,
                actions: flat.actions,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error("Failed to read config: {0}")]
    Read(#[from] io::Error),
    #[error("Failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Configuration of the execution environment
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct ProgramConfig {
    /// Max number of lines (as written, excluding comments, blank lines and
    /// regex directives)
    pub num_lines: usize,
    /// Number of registers per bank (indices 0..num_registers)
    pub num_registers: u16,
    /// Available condition operators
    pub operators: Vec<Operator>,
    /// Available actions
    pub actions: Vec<Action>,
}
impl Default for ProgramConfig {
    fn default() -> Self {
        ProgramConfig {
            num_lines: 256,
            num_registers: 16,
            operators: Operator::all(),
            actions: Action::all(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::program::{ComparisonOperator, Operator};

    #[test]
    fn empty_table_gives_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert!(!c.env.relax_register_types);
        assert!(c.env.field_default_on_error);
        assert_eq!(c.program.num_registers, 16);
        assert_eq!(c.program.num_lines, 256);
        assert_eq!(c.program.operators, Operator::all());
        assert_eq!(c.program.actions, Action::all());
    }

    #[test]
    fn flat_keys_are_read() {
        let c: Config = toml::from_str(
            r#"
relax_register_types = true
field_default_on_error = false
num_registers = 4
num_lines = 8
operators = ["<", "=="]
actions = ["allow", "terminate"]
"#,
        )
        .unwrap();
        assert!(c.env.relax_register_types);
        assert!(!c.env.field_default_on_error);
        assert_eq!(c.program.num_registers, 4);
        assert_eq!(c.program.num_lines, 8);
        assert_eq!(
            c.program.operators,
            vec![
                Operator::Comparison(ComparisonOperator::Less),
                Operator::Comparison(ComparisonOperator::Equal)
            ]
        );
        assert_eq!(c.program.actions, vec![Action::Allow, Action::TerminateAll]);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(toml::from_str::<Config>("num_regs = 4").is_err());
    }
}
