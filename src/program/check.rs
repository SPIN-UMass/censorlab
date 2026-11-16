//! Load-time checking of CensorLang programs.
//!
//! CensorLang is loop-free and every operand has a static type, so everything
//! that could otherwise fail on a packet because of the program text itself is
//! decided here, once, when the program is loaded:
//!
//! * the program fits the configured number of lines;
//! * every register index (`reg:` and `hreg:`) is inside the configured banks;
//! * every operation writes a value of the destination register's type
//!   (unless `relax_register_types` is set, in which case writes are routed to
//!   the bank of the value's type and cannot fail);
//! * every `REGEX <n>` names a declared `regex` directive;
//! * every condition operator and `RETURN` action is in the configured
//!   allow-lists;
//! * every model referenced is configured, and model input indices are within
//!   the model's declared input length (or [`MAX_MODEL_INPUTS`] if unknown),
//!   which bounds the per-connection model input buffer.
//!
//! A program that fails any check is rejected with all of its errors; it never
//! reaches the packet path.  What remains possible at run time is only what
//! depends on the traffic: reading a field the packet does not have (when
//! `field_default_on_error` is off) and model inference failures.

use crate::program::config::Config;
use crate::program::program::{Input, Line, Operation, Program, Register, RegisterType};
use std::collections::BTreeMap;
use std::fmt;

/// Upper bound on a model input index when the model's input length is not
/// known at load time.  Model inputs are buffered per connection, so this
/// caps that buffer at `MAX_MODEL_INPUTS` floats per model.
pub const MAX_MODEL_INPUTS: usize = 4096;

/// Models available to a program: name -> declared input length, if known
pub type ModelSignatures = BTreeMap<String, Option<usize>>;

/// A single problem found in a program
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum CheckErrorKind {
    #[error("program has {lines} lines, more than the configured maximum of {max} (num_lines)")]
    TooManyLines { lines: usize, max: usize },
    #[error("register {register} is out of range: only indices 0..{num_registers} exist (num_registers)")]
    RegisterIndex {
        register: String,
        num_registers: usize,
    },
    #[error("writes a {value} value to {register}, a {register_ty} register (set relax_register_types to allow this)")]
    RegisterType {
        register: String,
        register_ty: &'static str,
        value: &'static str,
    },
    #[error("REGEX {index} refers to an undeclared regex (the program declares {declared})")]
    RegexIndex { index: usize, declared: usize },
    #[error("operator {0} is not enabled (operators)")]
    OperatorNotAllowed(String),
    #[error("action {0} is not enabled (actions)")]
    ActionNotAllowed(String),
    #[error("model {0:?} is not configured")]
    UnknownModel(String),
    #[error("model {name:?} input index {index} is out of range: the model takes {len} inputs")]
    ModelInputIndex { name: String, index: usize, len: usize },
}

/// A problem, with the source line it was found on
#[derive(Clone, Debug, PartialEq)]
pub struct CheckError {
    /// 1-based source line number, if known
    pub line_number: Option<usize>,
    /// The offending line, as displayed
    pub line: Option<String>,
    pub kind: CheckErrorKind,
}
impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (&self.line_number, &self.line) {
            (Some(n), Some(line)) => write!(f, "line {n} ({line}): {}", self.kind),
            (None, Some(line)) => write!(f, "{line}: {}", self.kind),
            _ => self.kind.fmt(f),
        }
    }
}

/// Every problem found in a program
#[derive(Clone, Debug, PartialEq)]
pub struct CheckErrors(pub Vec<CheckError>);
impl fmt::Display for CheckErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, err) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            err.fmt(f)?;
        }
        Ok(())
    }
}
impl std::error::Error for CheckErrors {}

fn type_name(ty: &RegisterType) -> &'static str {
    match ty {
        RegisterType::Float => "float",
        RegisterType::Int => "int",
        RegisterType::Bool => "bool",
    }
}

/// Static type of an input
pub fn input_type(input: &Input) -> RegisterType {
    match input {
        Input::Field(field) => field.ty(),
        Input::Register(reg) => reg.ty.clone(),
        Input::ModelOutput(_) | Input::Float(_) => RegisterType::Float,
        Input::Int(_) => RegisterType::Int,
        Input::Bool(_) => RegisterType::Bool,
    }
}

/// Static type of the value an operation writes, with its destination
pub fn output_type(operation: &Operation) -> Option<(RegisterType, &Register)> {
    use Operation::*;
    match operation {
        Copy { from, to } => Some((input_type(from), to)),
        // Mirrors MathOperator::call: any float operand makes the result a
        // float, otherwise (int/bool operands) it is an int
        Add { lhs, rhs, out }
        | Sub { lhs, rhs, out }
        | Mul { lhs, rhs, out }
        | Div { lhs, rhs, out }
        | Mod { lhs, rhs, out } => {
            let ty = if input_type(lhs) == RegisterType::Float
                || input_type(rhs) == RegisterType::Float
            {
                RegisterType::Float
            } else {
                RegisterType::Int
            };
            Some((ty, out))
        }
        And { out, .. }
        | Or { out, .. }
        | Xor { out, .. }
        | Regex { out, .. }
        | RegexSni { out, .. }
        | SubnetIn { out, .. } => {
            Some((RegisterType::Bool, out))
        }
        Return(_) | Noop | Model { .. } | CopyToModel { .. } => None,
    }
}

fn line_inputs(line: &Line) -> Vec<&Input> {
    let mut inputs = Vec::new();
    if let Some(cond) = &line.condition {
        inputs.push(&cond.lhs);
        inputs.push(&cond.rhs);
    }
    use Operation::*;
    match &line.operation {
        Copy { from, .. } | CopyToModel { from, .. } => inputs.push(from),
        Add { lhs, rhs, .. }
        | Sub { lhs, rhs, .. }
        | Mul { lhs, rhs, .. }
        | Div { lhs, rhs, .. }
        | Mod { lhs, rhs, .. }
        | And { lhs, rhs, .. }
        | Or { lhs, rhs, .. }
        | Xor { lhs, rhs, .. } => {
            inputs.push(lhs);
            inputs.push(rhs);
        }
        Regex { .. } | RegexSni { .. } | SubnetIn { .. } | Return(_) | Noop | Model { .. } => {}
    }
    inputs
}

fn check_line(
    line: &Line,
    regexes: usize,
    config: &Config,
    models: Option<&ModelSignatures>,
) -> Vec<CheckErrorKind> {
    let mut errors = Vec::new();
    let num_registers = usize::from(config.program.num_registers);
    let check_register = |reg: &Register, errors: &mut Vec<CheckErrorKind>| {
        if reg.index >= num_registers {
            errors.push(CheckErrorKind::RegisterIndex {
                register: reg.to_string(),
                num_registers,
            });
        }
    };
    let check_model = |name: &str, errors: &mut Vec<CheckErrorKind>| -> Option<usize> {
        match models {
            Some(models) => match models.get(name) {
                Some(len) => Some(len.unwrap_or(MAX_MODEL_INPUTS)),
                None => {
                    errors.push(CheckErrorKind::UnknownModel(name.to_string()));
                    None
                }
            },
            None => Some(MAX_MODEL_INPUTS),
        }
    };
    // Condition operator
    if let Some(cond) = &line.condition {
        if !config.program.operators.contains(&cond.operator) {
            errors.push(CheckErrorKind::OperatorNotAllowed(cond.operator.to_string()));
        }
    }
    // Inputs
    for input in line_inputs(line) {
        match input {
            Input::Register(reg) => check_register(reg, &mut errors),
            Input::ModelOutput(slot) => {
                check_model(&slot.name, &mut errors);
            }
            _ => {}
        }
    }
    // Output register: bounds and type
    if let Some((ty, out)) = output_type(&line.operation) {
        check_register(out, &mut errors);
        if !config.env.relax_register_types && ty != out.ty {
            errors.push(CheckErrorKind::RegisterType {
                register: out.to_string(),
                register_ty: type_name(&out.ty),
                value: type_name(&ty),
            });
        }
    }
    use Operation::*;
    match &line.operation {
        Regex { index, .. } | RegexSni { index, .. } if *index >= regexes => {
            errors.push(CheckErrorKind::RegexIndex {
                index: *index,
                declared: regexes,
            });
        }
        Return(action) if !config.program.actions.contains(action) => {
            errors.push(CheckErrorKind::ActionNotAllowed(action.to_string()));
        }
        Model { name } => {
            check_model(name, &mut errors);
        }
        CopyToModel { name, index, .. } => {
            if let Some(len) = check_model(name, &mut errors) {
                if *index >= len {
                    errors.push(CheckErrorKind::ModelInputIndex {
                        name: name.clone(),
                        index: *index,
                        len,
                    });
                }
            }
        }
        _ => {}
    }
    errors
}

/// Check a program against a configuration.
///
/// `line_numbers[i]` is the 1-based source line of `program.lines[i]`, if
/// known.  `models` lists the configured models; `None` skips the model-name
/// check (input indices are then capped at [`MAX_MODEL_INPUTS`]).
pub fn check(
    program: &Program,
    line_numbers: Option<&[usize]>,
    config: &Config,
    models: Option<&ModelSignatures>,
) -> Result<(), CheckErrors> {
    let mut errors = Vec::new();
    if program.lines.len() > config.program.num_lines {
        errors.push(CheckError {
            line_number: None,
            line: None,
            kind: CheckErrorKind::TooManyLines {
                lines: program.lines.len(),
                max: config.program.num_lines,
            },
        });
    }
    for (i, line) in program.lines.iter().enumerate() {
        for kind in check_line(line, program.regexes.len(), config, models) {
            errors.push(CheckError {
                line_number: line_numbers.and_then(|n| n.get(i).copied()),
                line: Some(line.to_string()),
                kind,
            });
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CheckErrors(errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str, config: &Config, models: Option<&ModelSignatures>) -> Result<(), CheckErrors> {
        let (program, numbers) = Program::parse_numbered(src).unwrap();
        check(&program, Some(&numbers), config, models)
    }

    fn kinds(src: &str, config: &Config) -> Vec<CheckErrorKind> {
        run(src, config, None).err().map(|e| e.0.into_iter().map(|e| e.kind).collect()).unwrap_or_default()
    }

    #[test]
    fn well_typed_program_passes() {
        let src = "COPY field:tcp.payload.len -> reg:i.0\n\
                   DIV reg:i.0, 2 -> reg:i.1\n\
                   DIV field:tcp.payload.len, 2.0 -> reg:f.0\n\
                   ADD True, True -> reg:i.2\n\
                   AND reg:i.0, field:tcp.flag.syn -> reg:b.0\n\
                   COPY field:tcp.flag.syn -> reg:b.1\n\
                   if reg:f.0 > 1: RETURN terminate";
        assert_eq!(run(src, &Config::default(), None), Ok(()));
    }

    #[test]
    fn integer_division_into_float_register_is_rejected() {
        let k = kinds("DIV field:tcp.payload.len, 2 -> reg:f.0", &Config::default());
        assert!(matches!(&k[..], [CheckErrorKind::RegisterType { value: "int", register_ty: "float", .. }]), "{k:?}");
    }

    #[test]
    fn relaxed_register_types_accept_mismatch() {
        let mut config = Config::default();
        config.env.relax_register_types = true;
        assert_eq!(kinds("DIV field:tcp.payload.len, 2 -> reg:f.0", &config), vec![]);
    }

    #[test]
    fn bool_field_into_int_register_is_rejected() {
        let k = kinds("COPY field:tcp.flag.syn -> reg:i.0", &Config::default());
        assert!(matches!(&k[..], [CheckErrorKind::RegisterType { .. }]), "{k:?}");
    }

    #[test]
    fn register_out_of_range_is_rejected() {
        let k = kinds("if reg:i.99 > 0: COPY 1 -> hreg:i.16", &Config::default());
        assert_eq!(k.len(), 2, "{k:?}");
        assert!(k.iter().all(|k| matches!(k, CheckErrorKind::RegisterIndex { num_registers: 16, .. })));
        let mut config = Config::default();
        config.program.num_registers = 100;
        assert_eq!(kinds("if reg:i.99 > 0: COPY 1 -> hreg:i.16", &config), vec![]);
    }

    #[test]
    fn regex_index_is_checked() {
        let k = kinds("regex \"a\"\nREGEX 0 -> reg:b.0\nREGEX 1 -> reg:b.0", &Config::default());
        assert_eq!(k, vec![CheckErrorKind::RegexIndex { index: 1, declared: 1 }]);
    }

    #[test]
    fn num_lines_is_enforced() {
        let mut config = Config::default();
        config.program.num_lines = 2;
        let k = kinds("# comment\nregex \"a\"\nNOOP\nNOOP\nNOOP", &config);
        assert_eq!(k, vec![CheckErrorKind::TooManyLines { lines: 3, max: 2 }]);
    }

    #[test]
    fn operators_and_actions_are_enforced() {
        let mut config = Config::default();
        config.program.operators = vec!["<".parse().unwrap()];
        config.program.actions = vec!["allow".parse().unwrap()];
        let k = kinds("if field:tcp.dst < 1: RETURN allow\nif field:tcp.dst == 1: RETURN terminate", &config);
        assert_eq!(
            k,
            vec![
                CheckErrorKind::OperatorNotAllowed("==".into()),
                CheckErrorKind::ActionNotAllowed("terminate".into())
            ]
        );
    }

    #[test]
    fn models_are_checked() {
        let models: ModelSignatures = [("m".to_string(), Some(4)), ("u".to_string(), None)].into_iter().collect();
        let config = Config::default();
        assert_eq!(run("COPY 1 -> model:m:in:3\nMODEL m\nCOPY model:m:out:0 -> reg:f.0", &config, Some(&models)), Ok(()));
        let err = run("COPY 1 -> model:m:in:4", &config, Some(&models)).unwrap_err();
        assert_eq!(err.0[0].kind, CheckErrorKind::ModelInputIndex { name: "m".into(), index: 4, len: 4 });
        let err = run("MODEL nope\nCOPY model:nope:out:0 -> reg:f.0", &config, Some(&models)).unwrap_err();
        assert_eq!(err.0.len(), 2);
        // Unknown input length: the cap applies, with or without a model list
        let huge = format!("COPY 1 -> model:u:in:{MAX_MODEL_INPUTS}");
        assert!(run(&huge, &config, Some(&models)).is_err());
        assert!(run("COPY 1 -> model:x:in:1000000000000", &config, None).is_err());
    }

    #[test]
    fn errors_carry_source_line_numbers() {
        let err = run("# header\n\nCOPY 1 -> reg:i.0\nCOPY 1 -> reg:f.0", &Config::default(), None).unwrap_err();
        assert_eq!(err.0.len(), 1);
        assert_eq!(err.0[0].line_number, Some(4));
        assert!(err.to_string().starts_with("line 4 (COPY 1 -> reg:f.0): "), "{err}");
    }
}
