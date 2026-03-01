use crate::program::env::{EnvFields, RegisterBanks, RegisterWriteError};
use crate::program::packet::Packet;
use crate::program::packet::{IpVersionMetadata, TcpFlags, TransportMetadataExtra};
use fnv::FnvHashSet;
use lalrpop_util::lalrpop_mod;
use num::Zero;
use regex::bytes::Regex as BytesRegex;
use serde::Deserialize;
use serde_with::DeserializeFromStr;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::num::TryFromIntError;
use std::path::PathBuf;
use std::str::FromStr;
use thiserror::Error;

/// Storage for model input/output values during CensorLang execution
#[derive(Debug, Default)]
pub struct ModelIO {
    pub inputs: HashMap<String, Vec<f64>>,
    pub outputs: HashMap<String, Vec<f64>>,
}
impl ModelIO {
    pub fn set_input(&mut self, name: &str, index: usize, value: f64) {
        let vec = self.inputs.entry(name.to_string()).or_default();
        if index >= vec.len() {
            vec.resize(index + 1, 0.0);
        }
        vec[index] = value;
    }
    pub fn get_output(&self, name: &str, index: usize) -> Option<f64> {
        self.outputs.get(name).and_then(|v| v.get(index)).copied()
    }
}

/// Generates an `all()` method that returns a `Vec` of all listed variants.
macro_rules! enum_all {
    ($($variant:expr),+ $(,)?) => {
        pub fn all() -> Vec<Self> {
            vec![$($variant),+]
        }
    };
}

#[derive(Debug, Error)]
pub enum ProgramLoadError {
    #[error("Failed to read program file: {0}")]
    Read(#[from] std::io::Error),
    #[error("Failed to parse program: {0}")]
    Parse(String),
}

// Load in the parsing module
lalrpop_mod!(
    #[allow(dead_code, clippy::all)]
    pub program_parse,
    "/program/program_parse.rs"
); // synthesized by LALRPOP

/// Agprogram
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct Program {
    pub lines: Vec<Line>,
    #[serde(skip)]
    pub regexes: Vec<BytesRegex>,
}
impl Program {
    /// Loads a program
    pub fn load(program_path: PathBuf) -> Result<Self, ProgramLoadError> {
        // Load the program
        let program = fs::read_to_string(program_path)?;
        let program = program.parse().map_err(ProgramLoadError::Parse)?;
        Ok(program)
    }
}
impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for re in &self.regexes {
            writeln!(f, "regex \"{}\"", re.as_str())?;
        }
        for line in &self.lines {
            writeln!(f, "{}", line)?;
        }
        Ok(())
    }
}
impl Program {
    pub fn new(lines: Vec<Line>) -> Self {
        Self::new_with_regexes(lines, vec![])
    }
    pub fn new_with_regexes(lines: Vec<Line>, regexes: Vec<BytesRegex>) -> Self {
        let mut program = Program { lines, regexes };
        program.optimise();
        program
    }
    pub fn non_return_points(&self) -> impl Iterator<Item = (usize, &Line)> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| !matches!(line.operation, Operation::Model { .. } | Operation::Return(_)))
    }
    pub fn return_points(&self) -> impl Iterator<Item = (usize, &Line)> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| matches!(line.operation, Operation::Model { .. } | Operation::Return(_)))
    }
    pub fn read_register_indices_also_fix(
        &mut self,
        written: &FnvHashSet<usize>,
    ) -> (FnvHashSet<usize>, bool) {
        let mut regs: FnvHashSet<usize> = Default::default();
        let mut changed = false;
        for line in &mut self.lines {
            if let Some(ref mut condition) = line.condition {
                if let Input::Register(ref reg) = condition.lhs {
                    if reg.host {
                        // Host registers are always considered "live" -- skip optimization
                    } else if written.contains(&reg.index) {
                        regs.insert(reg.index);
                    } else {
                        condition.lhs = reg.as_uninitialized_value().into();
                        changed = true;
                    }
                }
                if let Input::Register(ref reg) = condition.rhs {
                    if reg.host {
                        // Host registers are always considered "live" -- skip optimization
                    } else if written.contains(&reg.index) {
                        regs.insert(reg.index);
                    } else {
                        condition.rhs = reg.as_uninitialized_value().into();
                        changed = true;
                    }
                }
            }
            use Operation::*;
            match line.operation {
                Copy { ref mut from, .. } | CopyToModel { ref mut from, .. } => {
                    if let Input::Register(ref reg) = from {
                        if reg.host {
                            // Host registers are always considered "live" -- skip optimization
                        } else if written.contains(&reg.index) {
                            regs.insert(reg.index);
                        } else {
                            *from = reg.as_uninitialized_value().into();
                            changed = true;
                        }
                    }
                }
                Add {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | Sub {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | Mul {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | Div {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | Mod {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | And {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | Or {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                }
                | Xor {
                    ref mut lhs,
                    ref mut rhs,
                    ..
                } => {
                    if let Input::Register(ref reg) = lhs {
                        if reg.host {
                            // Host registers are always considered "live" -- skip optimization
                        } else if written.contains(&reg.index) {
                            regs.insert(reg.index);
                        } else {
                            *lhs = reg.as_uninitialized_value().into();
                            changed = true;
                        }
                    }
                    if let Input::Register(ref reg) = rhs {
                        if reg.host {
                            // Host registers are always considered "live" -- skip optimization
                        } else if written.contains(&reg.index) {
                            regs.insert(reg.index);
                        } else {
                            *rhs = reg.as_uninitialized_value().into();
                            changed = true;
                        }
                    }
                }
                _ => {}
            }
        }
        (regs, changed)
    }
    pub fn write_register_indices(&self) -> Vec<Option<usize>> {
        let mut regs = Vec::new();
        for line in &self.lines {
            use Operation::*;
            match line.operation {
                Copy { ref to, .. } => {
                    regs.push(if to.host { None } else { Some(to.index) });
                }
                Add { ref out, .. }
                | Sub { ref out, .. }
                | Mul { ref out, .. }
                | Div { ref out, .. }
                | Mod { ref out, .. }
                | And { ref out, .. }
                | Or { ref out, .. }
                | Xor { ref out, .. }
                | Regex { ref out, .. } => {
                    regs.push(if out.host { None } else { Some(out.index) });
                }
                _ => {
                    regs.push(None);
                }
            }
        }
        regs
    }
    pub fn optimise(&mut self) {
        let mut changed = true;
        // Loop until no change
        while changed {
            // Do register analysis
            changed = false;
            // Strip out any noops
            changed |= self.strip_noops();
            // Remove always-true conditions
            // Remove lines with always-false conditions
            self.lines.iter_mut().for_each(|line| {
                if let Some(ref mut condition) = line.condition {
                    match condition.proven_value() {
                        Some(true) => {
                            line.condition = None;
                            changed = true;
                        }
                        // Setting it to noop means it gets purged later
                        Some(false) => {
                            line.operation = Operation::Noop;

                            changed = true;
                        }
                        None => {}
                    };
                }
                if let Some((value, to)) = line.operation.has_constant_math_value() {
                    line.operation = Operation::Copy {
                        from: value.into(),
                        to,
                    };
                    changed = true;
                }
            });
            // Strip out noops again
            changed |= self.strip_noops();
            // Get list of written registers
            let written_registers = self.write_register_indices();
            // Convert it to a set
            let written_reg_set: FnvHashSet<usize> =
                written_registers.iter().flatten().cloned().collect();
            let (read_registers, change_uninit) =
                self.read_register_indices_also_fix(&written_reg_set);
            changed |= change_uninit;
            // If a line writes a register that is never written, delete it
            for (i, written) in written_registers.iter().enumerate() {
                if let Some(written) = written {
                    if !read_registers.contains(written) {
                        self.lines[i].operation = Operation::Noop;
                        changed = true;
                    }
                }
            }
            // Strip noops once again
            changed |= self.strip_noops();
            // If we find an unconditional return, any line after that will have no effect
            if let Some((idx, _)) = self.lines.iter().enumerate().find(|(_, line)| {
                line.condition.is_none() && matches!(line.operation, Operation::Return(_))
            }) {
                self.lines.truncate(idx + 1);
            }
        }
        // Just a nice readability change
        for line in &mut self.lines {
            if let Some(ref mut cond) = line.condition {
                cond.enhance_readability();
            }
        }
    }
    fn strip_noops(&mut self) -> bool {
        let orig_len = self.lines.len();
        // Strip out noops
        self.lines
            .retain(|line| !matches!(line.operation, Operation::Noop));
        self.lines.len() != orig_len
    }
    pub fn run(
        &self,
        packet: &Packet,
        registers: &mut RegisterBanks,
        fields: &EnvFields,
        field_default_on_error: bool,
        model_io: &mut ModelIO,
        model_sender: Option<&std::sync::mpsc::SyncSender<crate::model::ModelThreadMessage>>,
    ) -> Result<Action, LineExecutionError> {
        let mut action = Action::default();
        for line in &self.lines {
            action = line.run(packet, registers, fields, field_default_on_error, &self.regexes, model_io, model_sender)?;
            if action != Action::default() {
                break;
            }
        }
        Ok(action)
    }
}
impl FromStr for Program {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = Vec::new();
        let mut regexes = Vec::new();
        for line in s.lines() {
            let trimmed = line.trim();
            // Skip blank lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Parse regex directives: regex "pattern"
            if let Some(rest) = trimmed.strip_prefix("regex ") {
                let rest = rest.trim();
                if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
                    let pattern = &rest[1..rest.len() - 1];
                    let re = BytesRegex::new(pattern)
                        .map_err(|e| format!("Invalid regex pattern \"{pattern}\": {e}"))?;
                    regexes.push(re);
                } else {
                    return Err(format!(
                        "Invalid regex directive, expected regex \"pattern\", got: {trimmed}"
                    ));
                }
                continue;
            }
            let line = program_parse::LineParser::new()
                .parse(trimmed)
                .map_err(|e| e.to_string())?;
            lines.push(line);
        }
        Ok(Program { lines, regexes })
    }
}

#[derive(Clone, Debug, DeserializeFromStr)]
pub struct Line {
    pub condition: Option<Condition>,
    pub operation: Operation,
}
impl Line {
    pub fn input_registers(&self) -> Vec<Register> {
        let mut registers = Vec::new();
        if let Some(ref cond) = self.condition {
            if let Input::Register(ref reg) = cond.lhs {
                registers.push(reg.clone());
            }
            if let Input::Register(ref reg) = cond.rhs {
                registers.push(reg.clone());
            }
        }
        use Operation::*;
        match self.operation {
            Copy {
                from: Input::Register(ref reg),
                ..
            }
            | CopyToModel {
                from: Input::Register(ref reg),
                ..
            } => {
                registers.push(reg.clone());
            }
            Add {
                ref lhs, ref rhs, ..
            }
            | Sub {
                ref lhs, ref rhs, ..
            }
            | Mul {
                ref lhs, ref rhs, ..
            }
            | Div {
                ref lhs, ref rhs, ..
            }
            | Mod {
                ref lhs, ref rhs, ..
            }
            | And {
                ref lhs, ref rhs, ..
            }
            | Or {
                ref lhs, ref rhs, ..
            }
            | Xor {
                ref lhs, ref rhs, ..
            } => {
                if let Input::Register(ref reg) = lhs {
                    registers.push(reg.clone());
                }
                if let Input::Register(ref reg) = rhs {
                    registers.push(reg.clone());
                }
            }
            _ => {}
        }
        registers
    }
    pub fn output_register(&self) -> Option<Register> {
        use Operation::*;
        match self.operation {
            Copy { ref to, .. } => Some(to.clone()),
            Add { ref out, .. }
            | Sub { ref out, .. }
            | Mul { ref out, .. }
            | Div { ref out, .. }
            | Mod { ref out, .. }
            | And { ref out, .. }
            | Or { ref out, .. }
            | Xor { ref out, .. }
            | Regex { ref out, .. } => Some(out.clone()),
            _ => None,
        }
    }
    pub fn run(
        &self,
        packet: &Packet,
        registers: &mut RegisterBanks,
        fields: &EnvFields,
        field_default_on_error: bool,
        regexes: &[BytesRegex],
        model_io: &mut ModelIO,
        model_sender: Option<&std::sync::mpsc::SyncSender<crate::model::ModelThreadMessage>>,
    ) -> Result<Action, LineExecutionError> {
        // Only execute the line if the condition evaluates to true
        if self
            .condition
            .as_ref()
            .map(|cond| cond.eval(packet, registers, fields, field_default_on_error, model_io))
            .transpose()?
            .unwrap_or(true)
        {
            use Operation::*;
            match &self.operation {
                Copy { from, to } => {
                    let val = from.eval(packet, registers, fields, field_default_on_error, model_io)?;
                    registers.set(to, &val)?;
                }
                Add { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Numeric(MathOperatorNumeric::Add),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Sub { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Numeric(MathOperatorNumeric::Sub),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Mul { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Numeric(MathOperatorNumeric::Mul),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Div { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Numeric(MathOperatorNumeric::Div),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Mod { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Numeric(MathOperatorNumeric::Mod),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                And { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Logic(LogicOperator::And),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Or { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Logic(LogicOperator::Or),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Xor { lhs, rhs, out } => {
                    Self::run_math_operator(
                        packet,
                        registers,
                        fields,
                        MathOperator::Logic(LogicOperator::Xor),
                        lhs,
                        rhs,
                        out,
                        field_default_on_error,
                        model_io,
                    )?;
                }
                Regex { index, out } => {
                    let re = regexes
                        .get(*index)
                        .ok_or(LineExecutionError::RegexIndex(*index))?;
                    let matched = re.is_match(&packet.payload);
                    registers.set(out, &Value::Bool(matched))?;
                }
                Return(action) => {
                    return Ok(*action);
                }
                Noop => {}
                Model { ref name } => {
                    if let Some(sender) = model_sender {
                        let inputs = model_io.inputs.remove(name).unwrap_or_default();
                        let (resp_tx, resp_rx) = std::sync::mpsc::sync_channel(1);
                        sender
                            .send(crate::model::ModelThreadMessage::Request {
                                name: name.clone(),
                                data: inputs.into_iter().map(|v| v as f32).collect(),
                                response_channel: resp_tx,
                            })
                            .map_err(|_| LineExecutionError::ModelSendError)?;
                        match resp_rx.recv() {
                            Ok(Ok(outputs)) => {
                                model_io.outputs.insert(name.clone(), outputs);
                            }
                            Ok(Err(err)) => return Err(LineExecutionError::ModelError(err)),
                            Err(_) => return Err(LineExecutionError::ModelRecvError),
                        }
                    }
                }
                CopyToModel { from, name, index } => {
                    let val = from.eval(packet, registers, fields, field_default_on_error, model_io)?;
                    let f = match val {
                        Value::Float(f) => f,
                        Value::Int(i) => i as f64,
                        Value::Bool(b) => {
                            if b {
                                1.0
                            } else {
                                0.0
                            }
                        }
                    };
                    model_io.set_input(name, *index, f);
                }
            };
            Ok(Action::default())
        } else {
            Ok(Action::default())
        }
    }
    fn run_math_operator(
        packet: &Packet,
        registers: &mut RegisterBanks,
        fields: &EnvFields,
        math_operator: MathOperator,
        lhs: &Input,
        rhs: &Input,
        out: &Register,
        field_default_on_error: bool,
        model_io: &ModelIO,
    ) -> Result<(), LineExecutionError> {
        let lhs = lhs.eval(packet, registers, fields, field_default_on_error, model_io)?;
        let rhs = rhs.eval(packet, registers, fields, field_default_on_error, model_io)?;
        let val = math_operator.call(&lhs, &rhs);
        registers.set(out, &val)?;
        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
pub enum LineExecutionError {
    #[error("Error executing condition: {0}")]
    Condition(#[from] ConditionError),
    #[error("Error getting value: {0}")]
    Input(#[from] InputError),
    #[error("Error writing value to register: {0}")]
    RegisterWrite(#[from] RegisterWriteError),
    #[error("Regex index {0} out of bounds")]
    RegexIndex(usize),
    #[error("Failed to send request to model thread")]
    ModelSendError,
    #[error("Failed to receive response from model thread")]
    ModelRecvError,
    #[error("Model inference error: {0}")]
    ModelError(crate::model::ModelThreadError),
}
impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref cond) = self.condition {
            writeln!(f, "if {cond}:")?;
            write!(f, "    {}", self.operation)
        } else {
            self.operation.fmt(f)
        }
    }
}
impl FromStr for Line {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        program_parse::LineParser::new()
            .parse(s)
            .map_err(|e| e.to_string())
    }
}
#[derive(Clone, Debug)]
pub struct Condition {
    pub lhs: Input,
    pub operator: Operator,
    pub rhs: Input,
}
impl Condition {
    /// Evaluate the value of the condition
    pub fn eval(
        &self,
        packet: &Packet,
        registers: &RegisterBanks,
        fields: &EnvFields,
        field_default_on_error: bool,
        model_io: &ModelIO,
    ) -> Result<bool, ConditionError> {
        // Evaluate the value of the LHS
        let lhs = self
            .lhs
            .eval(packet, registers, fields, field_default_on_error, model_io)
            .map_err(ConditionError::Lhs)?;
        // Evaluate the value of the RHS
        let rhs = self
            .rhs
            .eval(packet, registers, fields, field_default_on_error, model_io)
            .map_err(ConditionError::Rhs)?;
        // Compare lhs and rhs
        Ok(self.operator.call(&lhs, &rhs))
    }
    /// Proven value for this condition (if one exists)
    pub fn proven_value(&self) -> Option<bool> {
        if let Some(lhs) = self.lhs.const_value() {
            self.rhs
                .const_value()
                .map(|rhs| self.operator.call(&lhs, &rhs))
        } else {
            None
        }
    }
    /// Make the condition less painful to read
    pub fn enhance_readability(&mut self) {
        match self.lhs {
            Input::Float(_) | Input::Int(_) | Input::Bool(_) => match self.rhs {
                Input::Field(_) | Input::Register(_) | Input::ModelOutput(_) => {
                    let tmp = self.lhs.clone();
                    self.lhs = self.rhs.clone();
                    self.rhs = tmp;
                    self.operator = self.operator.invert();
                }
                _ => {}
            },
            _ => {}
        }
    }
}
impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {}", self.lhs, self.operator, self.rhs)
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ConditionError {
    #[error("Failed to get LHS: {0}")]
    Lhs(InputError),
    #[error("Failed to get RHS: {0}")]
    Rhs(InputError),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Input {
    Field(field::Field),
    Register(Register),
    ModelOutput(ModelSlot),
    Float(f64),
    Int(i64),
    Bool(bool),
}
#[derive(Clone, Copy, Debug)]
pub enum Value {
    Float(f64),
    Int(i64),
    Bool(bool),
}
impl Value {
    pub fn as_bool(&self) -> bool {
        match self {
            Value::Float(f) => *f != 0.0,
            Value::Int(i) => *i != 0,
            Value::Bool(b) => *b,
        }
    }
}
impl Input {
    pub fn const_value(&self) -> Option<Value> {
        match self {
            Input::Float(flt) => Some(Value::Float(*flt)),
            Input::Int(i) => Some(Value::Int(*i)),
            Input::Bool(b) => Some(Value::Bool(*b)),
            Input::Field(_) | Input::Register(_) | Input::ModelOutput(_) => None,
        }
    }
    pub fn eval(
        &self,
        packet: &Packet,
        registers: &RegisterBanks,
        fields: &EnvFields,
        field_default_on_error: bool,
        model_io: &ModelIO,
    ) -> Result<Value, InputError> {
        match self {
            Input::Field(field) => field
                .eval(packet, fields, field_default_on_error)
                .map_err(|e| e.into()),
            Input::Register(reg) => registers
                .get(reg)
                .ok_or(InputError::RegisterIndex(reg.index)),
            Input::ModelOutput(slot) => Ok(Value::Float(
                model_io.get_output(&slot.name, slot.index).unwrap_or(0.0),
            )),
            Input::Float(flt) => Ok(Value::Float(*flt)),
            Input::Int(i) => Ok(Value::Int(*i)),
            Input::Bool(b) => Ok(Value::Bool(*b)),
        }
    }
}
impl From<Value> for Input {
    fn from(v: Value) -> Self {
        match v {
            Value::Float(f) => Input::Float(f),
            Value::Int(f) => Input::Int(f),
            Value::Bool(f) => Input::Bool(f),
        }
    }
}
impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Input::*;
        match self {
            Field(field) => write!(f, "field:{field:?}"),
            Register(reg) => reg.fmt(f),
            ModelOutput(slot) => write!(f, "model:{}:out:{}", slot.name, slot.index),
            Float(flt) => flt.fmt(f),
            Int(i) => i.fmt(f),
            Bool(b) => b.fmt(f),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Error getting value of field: {0}")]
    FieldError(#[from] field::FieldError),
    #[error("Register index {0} out of bounds")]
    RegisterIndex(usize),
}

pub mod field {
    use super::{
        program_parse, DeserializeFromStr, EnvFields, FromStr, IpVersionMetadata, Packet, TcpFlags,
        TransportMetadataExtra, TryFromIntError, Value,
    };
    #[derive(Clone, Debug, DeserializeFromStr, Eq, Hash, PartialEq)]
    pub enum Field {
        /// Fields from the program environment: generally some sort of smart-state
        Env(env::Field),
        /// The packet's timestamp
        Timestamp,
        /// A field based on the IP metadata of a packet
        Ip(ip::Field),
        /// A field based on the TCP metadata of a packet
        Tcp(tcp::Field),
        /// A field based on the UDP metadata of a packet
        Udp(udp::Field),
        /// Entropy of the transport-layer payload
        PayloadEntropy,
        /// Average popcount (bits per byte) of the transport-layer payload
        PayloadAveragePopcount,
    }
    impl Field {
        pub fn eval(
            &self,
            packet: &Packet,
            fields: &EnvFields,
            default_on_error: bool,
        ) -> Result<Value, FieldError> {
            match self {
                Field::Env(field) => Ok(field.eval(fields)),
                Field::Timestamp => {
                    if default_on_error {
                        Ok(Value::Float(packet.timestamp.unwrap_or(0.0)))
                    } else {
                        packet
                            .timestamp
                            .map(Value::Float)
                            .ok_or(FieldError::Timestamp)
                    }
                }
                Field::Ip(field) => field.eval(packet, default_on_error).map_err(FieldError::Ip),
                Field::Tcp(field) => field
                    .eval(packet, default_on_error)
                    .map_err(FieldError::Tcp),
                Field::Udp(field) => field
                    .eval(packet, default_on_error)
                    .map_err(FieldError::Udp),
                Field::PayloadEntropy => Ok(Value::Float(packet.payload_entropy())),
                Field::PayloadAveragePopcount => Ok(Value::Float(packet.payload_average_popcount())),
            }
        }
        pub fn all() -> Vec<Field> {
            let mut fields = vec![Field::Timestamp];
            for field in ip::Field::all() {
                fields.push(Field::Ip(field))
            }
            for field in tcp::Field::all() {
                fields.push(Field::Tcp(field));
            }
            for field in udp::Field::all() {
                fields.push(Field::Udp(field));
            }
            fields.push(Field::PayloadEntropy);
            fields.push(Field::PayloadAveragePopcount);
            fields
        }
    }
    impl FromStr for Field {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            program_parse::FieldParser::new()
                .parse(s)
                .map_err(|e| e.to_string())
        }
    }
    #[derive(Debug, thiserror::Error)]
    pub enum FieldError {
        #[error("Packet is missing a timestamp")]
        Timestamp,
        #[error("Error getting an IP field: {0}")]
        Ip(ip::FieldError),
        #[error("Error getting a TCP field: {0}")]
        Tcp(tcp::FieldError),
        #[error("Error getting a UDP field: {0}")]
        Udp(udp::FieldError),
    }
    pub mod env {
        use super::{EnvFields, Value};
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum Field {
            NumPackets,
            HostNumConnections,
            HostNumPackets,
            DstHostNumConnections,
            DstHostNumPackets,
        }

        impl Field {
            pub fn eval(&self, fields: &EnvFields) -> Value {
                use Field::*;
                match self {
                    NumPackets => Value::Int(fields.num_packets.into()),
                    HostNumConnections => Value::Int(fields.host_num_connections.into()),
                    HostNumPackets => Value::Int(fields.host_num_packets.into()),
                    DstHostNumConnections => Value::Int(fields.dst_host_num_connections.into()),
                    DstHostNumPackets => Value::Int(fields.dst_host_num_packets.into()),
                }
            }
        }
    }
    pub mod ip {
        use super::{IpVersionMetadata, Packet, TryFromIntError, Value};
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum Field {
            HeaderLen,
            TotalLen,
            HopLimit,
            V4(V4Field),
            V6(V6Field),
        }
        impl Field {
            pub fn all() -> Vec<Self> {
                use Field::*;
                let mut fields = vec![HeaderLen, TotalLen, HopLimit];
                for v4_field in V4Field::all() {
                    fields.push(V4(v4_field));
                }
                for v6_field in V6Field::all() {
                    fields.push(V6(v6_field));
                }
                fields
            }
            pub fn eval(
                &self,
                packet: &Packet,
                default_on_error: bool,
            ) -> Result<Value, FieldError> {
                use Field::*;
                let result = match self {
                    HeaderLen => packet
                        .ip
                        .header_len
                        .try_into()
                        .map(Value::Int)
                        .map_err(FieldError::IntConvert),
                    TotalLen => packet
                        .ip
                        .total_len
                        .try_into()
                        .map(Value::Int)
                        .map_err(FieldError::IntConvert),
                    HopLimit => Ok(Value::Int(packet.ip.hop_limit.into())),
                    V4(v4_field) => {
                        if let IpVersionMetadata::V4 {
                            dscp,
                            ecn,
                            ident,
                            dont_frag,
                            more_frags,
                            frag_offset,
                            checksum,
                            ..
                        } = packet.ip.version
                        {
                            use V4Field::*;
                            Ok(match v4_field {
                                Dscp => Value::Int(dscp.into()),
                                Ecn => Value::Int(ecn.into()),
                                Ident => Value::Int(ident.into()),
                                DontFrag => Value::Bool(dont_frag),
                                MoreFrags => Value::Bool(more_frags),
                                FragOffset => Value::Int(frag_offset.into()),
                                Checksum => Value::Int(checksum.into()),
                            })
                        } else {
                            Err(FieldError::WrongIpVersion)
                        }
                    }
                    V6(v6_field) => {
                        if let IpVersionMetadata::V6 {
                            traffic_class,
                            flow_label,
                            payload_len,
                            ..
                        } = packet.ip.version
                        {
                            use V6Field::*;
                            Ok(match v6_field {
                                TrafficClass => Value::Int(traffic_class.into()),
                                FlowLabel => Value::Int(flow_label.into()),
                                PayloadLen => Value::Int(payload_len.into()),
                            })
                        } else {
                            Err(FieldError::WrongIpVersion)
                        }
                    }
                };
                if default_on_error {
                    Ok(result.unwrap_or(Value::Int(0)))
                } else {
                    result
                }
            }
        }
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum V4Field {
            Dscp,
            Ecn,
            Ident,
            DontFrag,
            MoreFrags,
            FragOffset,
            Checksum,
        }
        impl V4Field {
            enum_all! {
                V4Field::Dscp, V4Field::Ecn, V4Field::Ident,
                V4Field::DontFrag, V4Field::MoreFrags, V4Field::FragOffset,
                V4Field::Checksum,
            }
        }
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum V6Field {
            TrafficClass,
            FlowLabel,
            PayloadLen,
        }
        impl V6Field {
            enum_all! { V6Field::TrafficClass, V6Field::FlowLabel, V6Field::PayloadLen }
        }
        #[derive(Debug, thiserror::Error)]
        pub enum FieldError {
            #[error("Error converting integers: {0}")]
            IntConvert(#[from] TryFromIntError),
            #[error("Tried to extract a special field from traffic with the wrong IP version")]
            WrongIpVersion,
        }
    }
    pub mod tcp {
        use super::{Packet, TcpFlags, TransportMetadataExtra, TryFromIntError, Value};

        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum Field {
            SrcPort,
            DstPort,
            Seq,
            Ack,
            Flag(Flag),
            Length,
            HeaderLength,
            PayloadLength,
            UrgentAt,
            WindowLength,
            // TCP options field evaluation not yet supported
        }
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum Flag {
            Fin,
            Syn,
            Rst,
            Psh,
            Ack,
            Urg,
            Ece,
            Cwr,
            Ns,
        }
        impl Field {
            pub fn eval(
                &self,
                packet: &Packet,
                default_on_error: bool,
            ) -> Result<Value, FieldError> {
                use Field::*;
                let result =
                    if let TransportMetadataExtra::Tcp(ref tcp_metadata) = packet.transport.extra {
                        match self {
                            SrcPort => Ok(Value::Int(packet.transport.src.into())),
                            DstPort => Ok(Value::Int(packet.transport.dst.into())),
                            Seq => Ok(Value::Int(tcp_metadata.seq.0.into())),
                            Ack => Ok(Value::Int(tcp_metadata.ack.0.into())),
                            Flag(flag) => Ok(flag.eval(&tcp_metadata.flags)),
                            Length => {
                                let total_len: u32 = (usize::from(tcp_metadata.header_len)
                                    + packet.payload.len())
                                .try_into()?;
                                Ok(Value::Int(total_len.into()))
                            }
                            HeaderLength => Ok(Value::Int(tcp_metadata.header_len.into())),
                            PayloadLength => {
                                let payload_len: u32 = packet.payload.len().try_into()?;
                                Ok(Value::Int(payload_len.into()))
                            }
                            UrgentAt => Ok(Value::Int(tcp_metadata.urgent_at.into())),
                            WindowLength => Ok(Value::Int(tcp_metadata.window_len.into())),
                        }
                    } else {
                        Err(FieldError::WrongProtocol)
                    };
                if default_on_error {
                    Ok(result.unwrap_or(Value::Int(0)))
                } else {
                    result
                }
            }
            pub fn all() -> Vec<Field> {
                vec![
                    Field::SrcPort,
                    Field::DstPort,
                    Field::Seq,
                    Field::Ack,
                    Field::Flag(Flag::Fin),
                    Field::Flag(Flag::Syn),
                    Field::Flag(Flag::Rst),
                    Field::Flag(Flag::Psh),
                    Field::Flag(Flag::Ack),
                    Field::Flag(Flag::Urg),
                    Field::Flag(Flag::Ece),
                    Field::Flag(Flag::Cwr),
                    Field::Flag(Flag::Ns),
                    Field::Length,
                    Field::HeaderLength,
                    Field::PayloadLength,
                    Field::UrgentAt,
                    Field::WindowLength,
                ]
            }
        }
        impl Flag {
            pub fn eval(&self, flags: &TcpFlags) -> Value {
                use Flag::*;
                Value::Bool(match self {
                    Fin => flags.fin,
                    Syn => flags.syn,
                    Rst => flags.rst,
                    Psh => flags.psh,
                    Ack => flags.ack,
                    Urg => flags.urg,
                    Ece => flags.ece,
                    Cwr => flags.cwr,
                    Ns => flags.ns,
                })
            }
        }
        #[derive(Debug, thiserror::Error)]
        pub enum FieldError {
            #[error("Cannot extract Tcp field from non-Tcp packet")]
            WrongProtocol,
            #[error("Error converting integers: {0}")]
            IntConvert(#[from] TryFromIntError),
        }
    }
    pub mod udp {
        use super::{Packet, TransportMetadataExtra, TryFromIntError, Value};
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum Field {
            SrcPort,
            DstPort,
            Length,
            Checksum,
        }
        impl Field {
            pub fn all() -> Vec<Field> {
                vec![Field::SrcPort, Field::DstPort, Field::Length, Field::Checksum]
            }
            pub fn eval(
                &self,
                packet: &Packet,
                default_on_error: bool,
            ) -> Result<Value, FieldError> {
                use Field::*;
                let result =
                    if let TransportMetadataExtra::Udp(ref udp_metadata) = packet.transport.extra {
                        match self {
                            SrcPort => Ok(Value::Int(packet.transport.src.into())),
                            DstPort => Ok(Value::Int(packet.transport.dst.into())),
                            Length => Ok(Value::Int(udp_metadata.length.into())),
                            Checksum => Ok(Value::Int(udp_metadata.checksum.into())),
                        }
                    } else {
                        Err(FieldError::WrongProtocol)
                    };
                if default_on_error {
                    Ok(result.unwrap_or(Value::Int(0)))
                } else {
                    result
                }
            }
        }
        #[derive(Debug, thiserror::Error)]
        pub enum FieldError {
            #[error("Cannot extract Udp field from non-Udp packet")]
            WrongProtocol,
            #[error("Error converting integers: {0}")]
            IntConvert(#[from] TryFromIntError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Register {
    pub ty: RegisterType,
    pub index: usize,
    pub host: bool,
}
impl Register {
    pub fn to_label(&self) -> String {
        let prefix = if self.host { "hreg" } else { "reg" };
        format!("{}_{}_{}", prefix, self.ty, self.index)
    }
    pub fn as_uninitialized_value(&self) -> Value {
        match self.ty {
            RegisterType::Float => Value::Float(0.0),
            RegisterType::Int => Value::Int(0),
            RegisterType::Bool => Value::Bool(false),
        }
    }
}
impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prefix = if self.host { "hreg" } else { "reg" };
        write!(f, "{}:{}.{}", prefix, self.ty, self.index)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum RegisterType {
    Float,
    Int,
    Bool,
}
impl fmt::Display for RegisterType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use RegisterType::*;
        f.write_str(match self {
            Float => "f",
            Int => "i",
            Bool => "b",
        })
    }
}
/// Reference to a model input or output slot
#[derive(Clone, Debug, PartialEq)]
pub struct ModelSlot {
    pub name: String,
    pub index: usize,
}
impl fmt::Display for ModelSlot {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "model:{}:{}", self.name, self.index)
    }
}

#[derive(Clone, Debug, PartialEq, DeserializeFromStr)]
pub enum Operator {
    Comparison(ComparisonOperator),
    Logic(LogicOperator),
}
impl Operator {
    pub fn all() -> Vec<Operator> {
        vec![
            Operator::Comparison(ComparisonOperator::Less),
            Operator::Comparison(ComparisonOperator::LessEqual),
            Operator::Comparison(ComparisonOperator::NotEqual),
            Operator::Comparison(ComparisonOperator::Equal),
            Operator::Comparison(ComparisonOperator::Greater),
            Operator::Comparison(ComparisonOperator::GreaterEqual),
            Operator::Logic(LogicOperator::And),
            Operator::Logic(LogicOperator::Or),
            Operator::Logic(LogicOperator::Xor),
            Operator::Logic(LogicOperator::Nand),
            Operator::Logic(LogicOperator::Nor),
            Operator::Logic(LogicOperator::Xnor),
        ]
    }
}
impl FromStr for Operator {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        program_parse::OperatorParser::new()
            .parse(s)
            .map_err(|e| e.to_string())
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum ComparisonOperator {
    Less,
    LessEqual,
    NotEqual,
    Equal,
    Greater,
    GreaterEqual,
}
#[derive(Clone, Debug, PartialEq)]
pub enum LogicOperator {
    And,
    Or,
    Xor,
    Nand,
    Nor,
    Xnor,
}

fn i64_to_f64(i: i64) -> f64 {
    let f = i as f64;
    let i2: i64 = f as i64;
    if i2 != i {
        tracing::warn!("Precision loss converting i64 ({i}) to f64 ({f}), round-trip gives {i2}");
    }
    f
}
impl Operator {
    pub fn call(&self, lhs: &Value, rhs: &Value) -> bool {
        // Match up types
        match self {
            Operator::Comparison(op) => match (lhs, rhs) {
                // If types match, just keep them the same
                (Value::Float(l), Value::Float(r)) => op.call(l, r),
                (Value::Int(l), Value::Int(r)) => op.call(l, r),
                (Value::Bool(l), Value::Bool(r)) => op.call(l, r),
                // LHS is the base, and RHS should be made compatible
                (Value::Float(l), Value::Int(r)) => {
                    let r_f = i64_to_f64(*r);
                    op.call(*l, r_f)
                }
                (Value::Float(l), Value::Bool(r)) => {
                    let r_f = f64::from(u8::from(*r));
                    op.call(*l, r_f)
                }
                (Value::Int(l), Value::Bool(r)) => {
                    let r_i = i64::from(*r);
                    op.call(*l, r_i)
                }
                // RHS is the base, and LHS should be made compatible
                (Value::Int(l), Value::Float(r)) => {
                    let l_f = i64_to_f64(*l);
                    op.call(l_f, *r)
                }
                (Value::Bool(l), Value::Float(r)) => {
                    let l_f = f64::from(u8::from(*l));
                    op.call(l_f, *r)
                }
                (Value::Bool(l), Value::Int(r)) => {
                    let r_i = i64::from(*l);
                    op.call(r_i, *r)
                }
            },
            Operator::Logic(op) => {
                let lhs = lhs.as_bool();
                let rhs = rhs.as_bool();
                op.call(lhs, rhs)
            }
        }
    }
    pub fn invert(&self) -> Self {
        use Operator::*;
        match self {
            Comparison(op) => Comparison(op.invert()),
            Logic(op) => Logic(op.invert()),
        }
    }
}
impl ComparisonOperator {
    fn call<T>(&self, lhs: T, rhs: T) -> bool
    where
        T: PartialEq + PartialOrd,
    {
        use ComparisonOperator::*;
        match self {
            Less => lhs < rhs,
            LessEqual => lhs <= rhs,
            NotEqual => lhs != rhs,
            Equal => lhs == rhs,
            Greater => lhs > rhs,
            GreaterEqual => lhs >= rhs,
        }
    }
    pub fn invert(&self) -> Self {
        use ComparisonOperator::*;
        match self {
            Less => Greater,
            LessEqual => GreaterEqual,
            NotEqual => NotEqual,
            Equal => Equal,
            Greater => Less,
            GreaterEqual => LessEqual,
        }
    }
}
impl LogicOperator {
    fn call(&self, lhs: bool, rhs: bool) -> bool {
        use LogicOperator::*;
        match self {
            And => lhs && rhs,
            Or => lhs || rhs,
            Xor => lhs ^ rhs,
            Nand => !(lhs && rhs),
            Nor => !(lhs || rhs),
            Xnor => !(lhs ^ rhs),
        }
    }
    pub fn invert(&self) -> Self {
        use LogicOperator::*;
        match self {
            And => And,
            Or => Or,
            Xor => Xor,
            Nand => Nand,
            Nor => Nor,
            Xnor => Xnor,
        }
    }
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Operator::*;
        match self {
            Comparison(op) => op.fmt(f),
            Logic(op) => op.fmt(f),
        }
    }
}
impl fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ComparisonOperator::*;
        f.write_str(match self {
            Less => "<",
            LessEqual => "<=",
            NotEqual => "!=",
            Equal => "==",
            Greater => ">",
            GreaterEqual => ">=",
        })
    }
}
impl fmt::Display for LogicOperator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LogicOperator::*;
        f.write_str(match self {
            And => "&&",
            Or => "||",
            Xor => "^",
            Nand => "nand",
            Nor => "nor",
            Xnor => "xnor",
        })
    }
}

enum MathOperator {
    Numeric(MathOperatorNumeric),
    Logic(LogicOperator),
}
enum MathOperatorNumeric {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl MathOperator {
    pub fn call(&self, lhs: &Value, rhs: &Value) -> Value {
        // Match up types
        match self {
            MathOperator::Numeric(op) => match (lhs, rhs) {
                // If types match, just keep them the same
                (Value::Float(l), Value::Float(r)) => Value::Float(op.call(*l, *r)),
                (Value::Int(l), Value::Int(r)) => Value::Int(op.call(*l, *r)),
                (Value::Bool(l), Value::Bool(r)) => {
                    let l_i = u8::from(*l);
                    let r_i = u8::from(*r);
                    Value::Int(i64::from(op.call(l_i, r_i)))
                }
                // LHS is the base, and RHS should be made compatible
                (Value::Float(l), Value::Int(r)) => {
                    let r_f = i64_to_f64(*r);
                    Value::Float(op.call(*l, r_f))
                }
                (Value::Float(l), Value::Bool(r)) => {
                    let r_f = f64::from(u8::from(*r));
                    Value::Float(op.call(*l, r_f))
                }
                (Value::Int(l), Value::Bool(r)) => {
                    let r_i = i64::from(*r);
                    Value::Int(op.call(*l, r_i))
                }
                // RHS is the base, and LHS should be made compatible
                (Value::Int(l), Value::Float(r)) => {
                    let l_f = i64_to_f64(*l);
                    Value::Float(op.call(l_f, *r))
                }
                (Value::Bool(l), Value::Float(r)) => {
                    let l_f = f64::from(u8::from(*l));
                    Value::Float(op.call(l_f, *r))
                }
                (Value::Bool(l), Value::Int(r)) => {
                    let r_i = i64::from(*l);
                    Value::Int(op.call(r_i, *r))
                }
            },
            MathOperator::Logic(op) => {
                let lhs = lhs.as_bool();
                let rhs = rhs.as_bool();
                Value::Bool(op.call(lhs, rhs))
            }
        }
    }
}
use std::ops::{Add, Div, Mul, Rem, Sub};
impl MathOperatorNumeric {
    fn call<T>(&self, lhs: T, rhs: T) -> T
    where
        T: Add<Output = T>
            + Sub<Output = T>
            + Mul<Output = T>
            + Div<Output = T>
            + Rem<Output = T>
            + Zero
            + PartialEq,
    {
        use MathOperatorNumeric::*;
        match self {
            Add => lhs + rhs,
            Sub => lhs - rhs,
            Mul => lhs * rhs,
            Div => {
                if rhs != T::zero() {
                    lhs / rhs
                } else {
                    T::zero()
                }
            }
            Mod => {
                if rhs != T::zero() {
                    lhs % rhs
                } else {
                    T::zero()
                }
            }
        }
    }
}
#[derive(Clone, Debug)]
pub enum Operation {
    Copy {
        from: Input,
        to: Register,
    },
    Add {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Sub {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Mul {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Div {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Mod {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    And {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Or {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Xor {
        lhs: Input,
        rhs: Input,
        out: Register,
    },
    Regex {
        index: usize,
        out: Register,
    },
    Return(Action),
    Noop,
    Model {
        name: String,
    },
    CopyToModel {
        from: Input,
        name: String,
        index: usize,
    },
}
impl Operation {
    fn has_constant_math_value(&self) -> Option<(Value, Register)> {
        use Operation::*;
        match self {
            Add { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Numeric(MathOperatorNumeric::Add))
                    .map(|val| (val, out.clone()))
            }
            Sub { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Numeric(MathOperatorNumeric::Sub))
                    .map(|val| (val, out.clone()))
            }
            Mul { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Numeric(MathOperatorNumeric::Mul))
                    .map(|val| (val, out.clone()))
            }
            Div { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Numeric(MathOperatorNumeric::Div))
                    .map(|val| (val, out.clone()))
            }
            Mod { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Numeric(MathOperatorNumeric::Mod))
                    .map(|val| (val, out.clone()))
            }
            And { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Logic(LogicOperator::And))
                    .map(|val| (val, out.clone()))
            }
            Or { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Logic(LogicOperator::Or))
                    .map(|val| (val, out.clone()))
            }
            Xor { lhs, rhs, out } => {
                Self::const_math_operator(lhs, rhs, MathOperator::Logic(LogicOperator::Xor))
                    .map(|val| (val, out.clone()))
            }
            _ => None,
        }
    }
    fn const_math_operator(lhs: &Input, rhs: &Input, operator: MathOperator) -> Option<Value> {
        if let Some(ref lhs) = lhs.const_value() {
            rhs.const_value()
                .as_ref()
                .map(|rhs| operator.call(lhs, rhs))
        } else {
            None
        }
    }
}
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Operation::*;
        match self {
            Copy { from, to } => write!(f, "COPY {from}->{to}"),
            Add { lhs, rhs, out }
            | Sub { lhs, rhs, out }
            | Mul { lhs, rhs, out }
            | Div { lhs, rhs, out }
            | Mod { lhs, rhs, out }
            | And { lhs, rhs, out }
            | Or { lhs, rhs, out }
            | Xor { lhs, rhs, out } => {
                let name = match self {
                    Add { .. } => "ADD",
                    Sub { .. } => "SUB",
                    Mul { .. } => "MUL",
                    Div { .. } => "DIV",
                    Mod { .. } => "MOD",
                    And { .. } => "AND",
                    Or { .. } => "OR",
                    Xor { .. } => "XOR",
                    _ => unreachable!(),
                };
                write!(f, "{name} {lhs},{rhs}->{out}")
            }
            Regex { index, out } => write!(f, "REGEX {index}->{out}"),
            Return(action) => write!(f, "RETURN {action}"),
            Noop => write!(f, "NOOP"),
            Model { ref name } => write!(f, "MODEL {name}"),
            CopyToModel { from, name, index } => {
                write!(f, "COPY {from}->model:{name}:in:{index}")
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, DeserializeFromStr)]
pub enum Action {
    #[default]
    Allow,
    AllowAll,
    TerminateAll,
    ResetAll,
}
impl Action {
    enum_all! { Action::Allow, Action::AllowAll, Action::TerminateAll, Action::ResetAll }
}
impl FromStr for Action {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        program_parse::ActionParser::new()
            .parse(s)
            .map_err(|e| e.to_string())
    }
}
impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Action::*;
        f.write_str(match self {
            Allow => "allow",
            AllowAll => "allow_all",
            TerminateAll => "terminate",
            ResetAll => "reset",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // --- Operator::call with comparison operators ---

    #[test]
    fn operator_call_int_less_than_int() {
        let op = Operator::Comparison(ComparisonOperator::Less);
        assert!(op.call(&Value::Int(1), &Value::Int(2)));
        assert!(!op.call(&Value::Int(2), &Value::Int(1)));
        assert!(!op.call(&Value::Int(1), &Value::Int(1)));
    }

    #[test]
    fn operator_call_float_greater_than_float() {
        let op = Operator::Comparison(ComparisonOperator::Greater);
        assert!(op.call(&Value::Float(3.5), &Value::Float(2.0)));
        assert!(!op.call(&Value::Float(1.0), &Value::Float(2.0)));
    }

    #[test]
    fn operator_call_int_equal_float_coercion() {
        let op = Operator::Comparison(ComparisonOperator::Equal);
        // Int == Float should coerce: Int(5) compared with Float(5.0)
        assert!(op.call(&Value::Int(5), &Value::Float(5.0)));
        assert!(!op.call(&Value::Int(5), &Value::Float(5.1)));
    }

    #[test]
    fn operator_call_float_equal_int_coercion() {
        let op = Operator::Comparison(ComparisonOperator::Equal);
        assert!(op.call(&Value::Float(5.0), &Value::Int(5)));
        assert!(!op.call(&Value::Float(5.1), &Value::Int(5)));
    }

    // --- Operator::call with logic operators ---

    #[test]
    fn operator_call_bool_and() {
        let op = Operator::Logic(LogicOperator::And);
        assert!(op.call(&Value::Bool(true), &Value::Bool(true)));
        assert!(!op.call(&Value::Bool(true), &Value::Bool(false)));
        assert!(!op.call(&Value::Bool(false), &Value::Bool(false)));
    }

    #[test]
    fn operator_call_bool_or() {
        let op = Operator::Logic(LogicOperator::Or);
        assert!(op.call(&Value::Bool(true), &Value::Bool(false)));
        assert!(op.call(&Value::Bool(false), &Value::Bool(true)));
        assert!(!op.call(&Value::Bool(false), &Value::Bool(false)));
    }

    #[test]
    fn operator_call_bool_xor() {
        let op = Operator::Logic(LogicOperator::Xor);
        assert!(op.call(&Value::Bool(true), &Value::Bool(false)));
        assert!(op.call(&Value::Bool(false), &Value::Bool(true)));
        assert!(!op.call(&Value::Bool(true), &Value::Bool(true)));
        assert!(!op.call(&Value::Bool(false), &Value::Bool(false)));
    }

    // --- Operator::all() ---

    #[test]
    fn operator_all_no_duplicates() {
        let all = Operator::all();
        assert!(!all.is_empty());
        // Check no duplicates
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Duplicate operator found at indices {i} and {j}");
                }
            }
        }
    }

    // --- Action tests ---

    #[test]
    fn action_all_contains_four_variants() {
        let all = Action::all();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&Action::Allow));
        assert!(all.contains(&Action::AllowAll));
        assert!(all.contains(&Action::TerminateAll));
        assert!(all.contains(&Action::ResetAll));
    }

    #[test]
    fn action_from_str_allow() {
        let action = Action::from_str("allow").unwrap();
        assert_eq!(action, Action::Allow);
    }

    #[test]
    fn action_from_str_terminate() {
        let action = Action::from_str("terminate").unwrap();
        assert_eq!(action, Action::TerminateAll);
    }

    #[test]
    fn action_display_allow() {
        assert_eq!(format!("{}", Action::Allow), "allow");
    }

    #[test]
    fn action_display_allow_all() {
        assert_eq!(format!("{}", Action::AllowAll), "allow_all");
    }

    #[test]
    fn action_display_terminate() {
        assert_eq!(format!("{}", Action::TerminateAll), "terminate");
    }

    #[test]
    fn action_from_str_reset() {
        let action = Action::from_str("reset").unwrap();
        assert_eq!(action, Action::ResetAll);
    }

    #[test]
    fn action_from_str_reset_uppercase() {
        let action = Action::from_str("RESET").unwrap();
        assert_eq!(action, Action::ResetAll);
    }

    #[test]
    fn action_display_reset() {
        assert_eq!(format!("{}", Action::ResetAll), "reset");
    }

    // --- i64_to_f64 ---

    #[test]
    fn i64_to_f64_basic() {
        assert_eq!(i64_to_f64(0), 0.0);
        assert_eq!(i64_to_f64(42), 42.0);
        assert_eq!(i64_to_f64(-100), -100.0);
    }

    #[test]
    fn i64_to_f64_max_safe_integer() {
        // 2^53 is exactly representable as f64
        let val = 1_i64 << 53;
        assert_eq!(i64_to_f64(val), val as f64);
    }

    // --- Value comparisons and type coercion ---

    #[test]
    fn value_as_bool() {
        assert!(Value::Bool(true).as_bool());
        assert!(!Value::Bool(false).as_bool());
        assert!(Value::Int(1).as_bool());
        assert!(!Value::Int(0).as_bool());
        assert!(Value::Float(1.0).as_bool());
        assert!(!Value::Float(0.0).as_bool());
    }

    #[test]
    fn comparison_less_equal() {
        let op = Operator::Comparison(ComparisonOperator::LessEqual);
        assert!(op.call(&Value::Int(1), &Value::Int(1)));
        assert!(op.call(&Value::Int(1), &Value::Int(2)));
        assert!(!op.call(&Value::Int(3), &Value::Int(2)));
    }

    #[test]
    fn comparison_not_equal() {
        let op = Operator::Comparison(ComparisonOperator::NotEqual);
        assert!(op.call(&Value::Int(1), &Value::Int(2)));
        assert!(!op.call(&Value::Int(1), &Value::Int(1)));
    }

    #[test]
    fn comparison_greater_equal() {
        let op = Operator::Comparison(ComparisonOperator::GreaterEqual);
        assert!(op.call(&Value::Float(2.0), &Value::Float(2.0)));
        assert!(op.call(&Value::Float(3.0), &Value::Float(2.0)));
        assert!(!op.call(&Value::Float(1.0), &Value::Float(2.0)));
    }

    #[test]
    fn logic_nand() {
        let op = Operator::Logic(LogicOperator::Nand);
        assert!(!op.call(&Value::Bool(true), &Value::Bool(true)));
        assert!(op.call(&Value::Bool(true), &Value::Bool(false)));
        assert!(op.call(&Value::Bool(false), &Value::Bool(false)));
    }

    #[test]
    fn logic_nor() {
        let op = Operator::Logic(LogicOperator::Nor);
        assert!(!op.call(&Value::Bool(true), &Value::Bool(false)));
        assert!(!op.call(&Value::Bool(false), &Value::Bool(true)));
        assert!(op.call(&Value::Bool(false), &Value::Bool(false)));
    }

    #[test]
    fn logic_xnor() {
        let op = Operator::Logic(LogicOperator::Xnor);
        assert!(op.call(&Value::Bool(true), &Value::Bool(true)));
        assert!(!op.call(&Value::Bool(true), &Value::Bool(false)));
        assert!(op.call(&Value::Bool(false), &Value::Bool(false)));
    }

    // =========================================================================
    // Packet construction helpers for program tests
    // =========================================================================

    use crate::program::packet::{
        IpMetadata, IpVersionMetadata, Packet, TcpFlags, TcpMetadata, TransportMetadata,
        TransportMetadataExtra, UdpMetadata,
    };
    use crate::program::env::{EnvFields, RegisterBanks, Registers};
    use smoltcp::wire::{Ipv4Address, TcpSeqNumber};

    fn make_tcp_packet(payload: &[u8]) -> Packet {
        Packet {
            timestamp: Some(0.0),
            ip: IpMetadata {
                header_len: 20,
                total_len: 40 + payload.len(),
                hop_limit: 64,
                next_header: smoltcp::wire::IpProtocol::Tcp,
                version: IpVersionMetadata::V4 {
                    src: Ipv4Address::new(10, 0, 0, 1),
                    dst: Ipv4Address::new(10, 0, 0, 2),
                    dscp: 0,
                    ecn: 0,
                    ident: 0,
                    dont_frag: false,
                    more_frags: false,
                    frag_offset: 0,
                    checksum: 0,
                },
            },
            direction: 0,
            transport: TransportMetadata {
                src: 12345,
                dst: 80,
                extra: TransportMetadataExtra::Tcp(TcpMetadata {
                    seq: TcpSeqNumber(1000),
                    ack: TcpSeqNumber(0),
                    header_len: 20,
                    urgent_at: 0,
                    window_len: 65535,
                    flags: TcpFlags {
                        fin: false,
                        syn: false,
                        rst: false,
                        psh: false,
                        ack: false,
                        urg: false,
                        ece: false,
                        cwr: false,
                        ns: false,
                    },
                }),
            },
            payload: payload.to_vec(),
        }
    }

    fn make_syn_packet() -> Packet {
        let mut pkt = make_tcp_packet(&[]);
        if let TransportMetadataExtra::Tcp(ref mut tcp) = pkt.transport.extra {
            tcp.flags.syn = true;
        }
        pkt
    }

    fn make_udp_packet(payload: &[u8]) -> Packet {
        Packet {
            timestamp: Some(0.0),
            ip: IpMetadata {
                header_len: 20,
                total_len: 28 + payload.len(),
                hop_limit: 64,
                next_header: smoltcp::wire::IpProtocol::Udp,
                version: IpVersionMetadata::V4 {
                    src: Ipv4Address::new(10, 0, 0, 1),
                    dst: Ipv4Address::new(10, 0, 0, 2),
                    dscp: 0,
                    ecn: 0,
                    ident: 0,
                    dont_frag: false,
                    more_frags: false,
                    frag_offset: 0,
                    checksum: 0,
                },
            },
            direction: 0,
            transport: TransportMetadata {
                src: 12345,
                dst: 53,
                extra: TransportMetadataExtra::Udp(UdpMetadata {
                    length: 8 + payload.len() as u16,
                    checksum: 0,
                }),
            },
            payload: payload.to_vec(),
        }
    }

    fn default_registers() -> Registers {
        Registers::new(16, false)
    }

    fn default_host_registers() -> Registers {
        Registers::new(16, false)
    }

    fn default_env_fields() -> EnvFields {
        EnvFields::default()
    }

    // =========================================================================
    // Group 4: CensorLang parse + run end-to-end
    // =========================================================================

    #[test]
    fn program_parse_unconditional_return() {
        let prog: Program = "RETURN terminate".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        assert!(prog.lines[0].condition.is_none());
        assert!(matches!(prog.lines[0].operation, Operation::Return(Action::TerminateAll)));
    }

    #[test]
    fn program_parse_conditional_return() {
        let prog: Program = "if field:tcp.flag.syn == True: RETURN terminate".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        assert!(prog.lines[0].condition.is_some());
        assert!(matches!(prog.lines[0].operation, Operation::Return(Action::TerminateAll)));
    }

    #[test]
    fn program_parse_copy_operation() {
        let prog: Program = "COPY 42 -> reg:i.0".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        match &prog.lines[0].operation {
            Operation::Copy { from, to } => {
                assert_eq!(*from, Input::Int(42));
                assert_eq!(to.ty, RegisterType::Int);
                assert_eq!(to.index, 0);
            }
            other => panic!("Expected Copy, got {:?}", other),
        }
    }

    #[test]
    fn program_parse_math_operation() {
        let prog: Program = "ADD reg:f.0, 1.0 -> reg:f.1".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        match &prog.lines[0].operation {
            Operation::Add { lhs, rhs, out } => {
                assert!(matches!(lhs, Input::Register(r) if r.ty == RegisterType::Float && r.index == 0));
                assert_eq!(*rhs, Input::Float(1.0));
                assert_eq!(out.ty, RegisterType::Float);
                assert_eq!(out.index, 1);
            }
            other => panic!("Expected Add, got {:?}", other),
        }
    }

    #[test]
    fn program_run_empty_returns_allow() {
        let prog = Program::default();
        let pkt = make_tcp_packet(b"hello");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::Allow);
    }

    #[test]
    fn program_run_unconditional_terminate() {
        let prog: Program = "RETURN terminate".parse().unwrap();
        let pkt = make_tcp_packet(b"hello");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_run_conditional_true_returns_terminate() {
        let prog: Program = "if field:tcp.payload.len > 0: RETURN terminate".parse().unwrap();
        let pkt = make_tcp_packet(b"hello");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_run_conditional_false_returns_allow() {
        let prog: Program = "if field:tcp.payload.len > 0: RETURN terminate".parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::Allow);
    }

    #[test]
    fn program_run_copy_then_conditional_on_register() {
        let source = "COPY 5 -> reg:i.0\nif reg:i.0 == 5: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_run_first_return_wins() {
        let source = "RETURN terminate\nRETURN allow_all";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    // =========================================================================
    // Group 5: Field evaluation
    // =========================================================================

    #[test]
    fn field_eval_tcp_payload_length() {
        let pkt = make_tcp_packet(b"0123456789");
        let fields = default_env_fields();
        let val = field::tcp::Field::PayloadLength.eval(&pkt, false).unwrap();
        assert!(matches!(val, Value::Int(10)));
        // Also test via the top-level Field enum
        let val2 = field::Field::Tcp(field::tcp::Field::PayloadLength)
            .eval(&pkt, &fields, false)
            .unwrap();
        assert!(matches!(val2, Value::Int(10)));
    }

    #[test]
    fn field_eval_tcp_flag_syn() {
        let pkt = make_syn_packet();
        let val = field::tcp::Field::Flag(field::tcp::Flag::Syn)
            .eval(&pkt, false)
            .unwrap();
        assert!(matches!(val, Value::Bool(true)));
    }

    #[test]
    fn field_eval_tcp_on_udp_errors() {
        let pkt = make_udp_packet(b"data");
        let result = field::tcp::Field::PayloadLength.eval(&pkt, false);
        assert!(result.is_err());
    }

    #[test]
    fn field_eval_tcp_on_udp_defaults() {
        let pkt = make_udp_packet(b"data");
        let val = field::tcp::Field::PayloadLength.eval(&pkt, true).unwrap();
        assert!(matches!(val, Value::Int(0)));
    }

    #[test]
    fn field_eval_payload_entropy_zeros() {
        let pkt = make_tcp_packet(&[0u8; 100]);
        let fields = default_env_fields();
        let val = field::Field::PayloadEntropy.eval(&pkt, &fields, false).unwrap();
        assert!(matches!(val, Value::Float(f) if f == 0.0));
    }

    #[test]
    fn field_eval_env_num_packets() {
        let pkt = make_tcp_packet(b"");
        let fields = EnvFields { num_packets: 5, ..Default::default() };
        let val = field::Field::Env(field::env::Field::NumPackets)
            .eval(&pkt, &fields, false)
            .unwrap();
        assert!(matches!(val, Value::Int(5)));
    }

    #[test]
    fn field_eval_host_num_connections() {
        let pkt = make_tcp_packet(b"");
        let fields = EnvFields { host_num_connections: 42, ..Default::default() };
        let val = field::Field::Env(field::env::Field::HostNumConnections)
            .eval(&pkt, &fields, false)
            .unwrap();
        assert!(matches!(val, Value::Int(42)));
    }

    #[test]
    fn field_eval_host_num_packets() {
        let pkt = make_tcp_packet(b"");
        let fields = EnvFields { host_num_packets: 100, ..Default::default() };
        let val = field::Field::Env(field::env::Field::HostNumPackets)
            .eval(&pkt, &fields, false)
            .unwrap();
        assert!(matches!(val, Value::Int(100)));
    }

    #[test]
    fn field_eval_timestamp_present() {
        let mut pkt = make_tcp_packet(b"");
        pkt.timestamp = Some(1.5);
        let fields = default_env_fields();
        let val = field::Field::Timestamp.eval(&pkt, &fields, false).unwrap();
        assert!(matches!(val, Value::Float(f) if (f - 1.5).abs() < f64::EPSILON));
    }

    #[test]
    fn field_eval_timestamp_missing_errors() {
        let mut pkt = make_tcp_packet(b"");
        pkt.timestamp = None;
        let fields = default_env_fields();
        let result = field::Field::Timestamp.eval(&pkt, &fields, false);
        assert!(result.is_err());
    }

    #[test]
    fn field_eval_timestamp_missing_defaults() {
        let mut pkt = make_tcp_packet(b"");
        pkt.timestamp = None;
        let fields = default_env_fields();
        let val = field::Field::Timestamp.eval(&pkt, &fields, true).unwrap();
        assert!(matches!(val, Value::Float(f) if f == 0.0));
    }

    #[test]
    fn field_eval_ip_header_len() {
        let pkt = make_tcp_packet(b"");
        let fields = default_env_fields();
        let val = field::Field::Ip(field::ip::Field::HeaderLen)
            .eval(&pkt, &fields, false)
            .unwrap();
        assert!(matches!(val, Value::Int(20)));
    }

    // =========================================================================
    // Group 6: Optimization passes
    // =========================================================================

    #[test]
    fn optimise_strips_noops() {
        let mut prog = Program {
            lines: vec![
                Line {
                    condition: None,
                    operation: Operation::Noop,
                },
                Line {
                    condition: None,
                    operation: Operation::Noop,
                },
            ],
            regexes: vec![],
        };
        prog.optimise();
        assert_eq!(prog.lines.len(), 0);
    }

    #[test]
    fn optimise_dead_code_after_unconditional_return() {
        let source = "RETURN terminate\nCOPY 1 -> reg:i.0";
        let prog: Program = source.parse().unwrap();
        // Program::new calls optimise
        let prog = Program::new(prog.lines);
        assert_eq!(prog.lines.len(), 1);
        assert!(matches!(prog.lines[0].operation, Operation::Return(Action::TerminateAll)));
    }

    #[test]
    fn optimise_always_true_condition_removed() {
        let source = "if 1 == 1: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let prog = Program::new(prog.lines);
        assert_eq!(prog.lines.len(), 1);
        // Condition should be stripped (always true)
        assert!(prog.lines[0].condition.is_none());
        assert!(matches!(prog.lines[0].operation, Operation::Return(Action::TerminateAll)));
    }

    #[test]
    fn optimise_always_false_condition_removed() {
        let source = "if 1 == 2: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let prog = Program::new(prog.lines);
        // Line should be entirely removed (always false → noop → stripped)
        assert_eq!(prog.lines.len(), 0);
    }

    #[test]
    fn optimise_constant_folding() {
        // ADD 2, 3 -> reg:i.0 then if reg:i.0 == 5: RETURN terminate
        // The add should be constant-folded to COPY 5 -> reg:i.0, then the
        // condition can evaluate since the register is known
        let source = "ADD 2, 3 -> reg:i.0\nif reg:i.0 == 5: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let prog = Program::new(prog.lines);
        // After optimization, should reduce to an unconditional return
        assert!(!prog.lines.is_empty());
        // The final line should be a return terminate
        let last = prog.lines.last().unwrap();
        assert!(matches!(last.operation, Operation::Return(Action::TerminateAll)));
    }

    // =========================================================================
    // Group 7: Math edge cases
    // =========================================================================

    #[test]
    fn math_div_by_zero_returns_zero() {
        let source = "DIV 10, 0 -> reg:i.0\nif reg:i.0 == 0: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn math_mod_by_zero_returns_zero() {
        let source = "MOD 10, 0 -> reg:i.0\nif reg:i.0 == 0: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn math_add_float_int_coercion() {
        let source = "ADD 1.5, 2 -> reg:f.0";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        drop(banks);
        let val = regs.get(&Register { ty: RegisterType::Float, index: 0, host: false }).unwrap();
        assert!(matches!(val, Value::Float(f) if (f - 3.5).abs() < f64::EPSILON));
    }

    // =========================================================================
    // Group 8: REGEX operation
    // =========================================================================

    #[test]
    fn program_parse_regex_directive() {
        let source = "regex \"example\\.com\"\nREGEX 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        assert_eq!(prog.regexes.len(), 1);
        assert_eq!(prog.regexes[0].as_str(), "example\\.com");
    }

    #[test]
    fn program_regex_matches_payload() {
        let source = "regex \"example\\.com\"\nREGEX 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"GET http://example.com/ HTTP/1.1");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_regex_no_match_allows() {
        let source = "regex \"example\\.com\"\nREGEX 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"GET http://other.org/ HTTP/1.1");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::Allow);
    }

    #[test]
    fn program_regex_multiple_patterns() {
        let source = "regex \"blocked\"\nregex \"forbidden\"\nREGEX 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate\nREGEX 1 -> reg:b.1\nif reg:b.1 == True: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        assert_eq!(prog.regexes.len(), 2);
        // Match second pattern
        let pkt = make_tcp_packet(b"this is forbidden content");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_regex_index_out_of_bounds() {
        let source = "REGEX 5 -> reg:b.0";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"data");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None);
        assert!(result.is_err());
    }

    #[test]
    fn program_regex_invalid_pattern_errors() {
        let source = "regex \"[invalid\"";
        let result: Result<Program, _> = source.parse();
        assert!(result.is_err());
    }

    #[test]
    fn program_regex_dead_code_elimination() {
        // REGEX writing to a register that's never read should be pruned
        let source = "regex \"test\"\nREGEX 0 -> reg:b.0";
        let prog: Program = source.parse().unwrap();
        let prog = Program::new_with_regexes(prog.lines, prog.regexes);
        // The REGEX line writes reg:b.0 but nothing reads it, so it should be optimized away
        assert_eq!(prog.lines.len(), 0);
    }

    // =========================================================================
    // Port field tests
    // =========================================================================

    #[test]
    fn field_tcp_src_port() {
        let pkt = make_tcp_packet(b"data");
        let field = field::Field::Tcp(field::tcp::Field::SrcPort);
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Int(12345)));
    }

    #[test]
    fn field_tcp_dst_port() {
        let pkt = make_tcp_packet(b"data");
        let field = field::Field::Tcp(field::tcp::Field::DstPort);
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Int(80)));
    }

    #[test]
    fn field_udp_src_port() {
        let pkt = make_udp_packet(b"data");
        let field = field::Field::Udp(field::udp::Field::SrcPort);
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Int(12345)));
    }

    #[test]
    fn field_udp_dst_port() {
        let pkt = make_udp_packet(b"data");
        let field = field::Field::Udp(field::udp::Field::DstPort);
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Int(53)));
    }

    #[test]
    fn field_tcp_port_wrong_protocol() {
        let pkt = make_udp_packet(b"data");
        let field = field::Field::Tcp(field::tcp::Field::SrcPort);
        // Should error when trying to read TCP field from UDP packet
        let result = field.eval(&pkt, &default_env_fields(), false);
        assert!(result.is_err());
    }

    #[test]
    fn field_tcp_port_wrong_protocol_default_on_error() {
        let pkt = make_udp_packet(b"data");
        let field = field::Field::Tcp(field::tcp::Field::SrcPort);
        // With default_on_error, should return 0
        let result = field.eval(&pkt, &default_env_fields(), true).unwrap();
        assert!(matches!(result, Value::Int(0)));
    }

    // =========================================================================
    // Popcount field tests
    // =========================================================================

    #[test]
    fn field_payload_average_popcount() {
        // 0xFF has popcount 8, 0x00 has popcount 0 -> avg = 4.0
        let pkt = make_tcp_packet(&[0xFF, 0x00]);
        let field = field::Field::PayloadAveragePopcount;
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Float(f) if f == 4.0));
    }

    #[test]
    fn field_payload_average_popcount_all_ones() {
        let pkt = make_tcp_packet(&[0xFF, 0xFF, 0xFF]);
        let field = field::Field::PayloadAveragePopcount;
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Float(f) if f == 8.0));
    }

    // =========================================================================
    // Port field grammar parse tests
    // =========================================================================

    #[test]
    fn parse_field_tcp_src() {
        let field: field::Field = "tcp.src".parse().unwrap();
        assert_eq!(field, field::Field::Tcp(field::tcp::Field::SrcPort));
    }

    #[test]
    fn parse_field_tcp_dst() {
        let field: field::Field = "tcp.dst".parse().unwrap();
        assert_eq!(field, field::Field::Tcp(field::tcp::Field::DstPort));
    }

    #[test]
    fn parse_field_udp_src() {
        let field: field::Field = "udp.src".parse().unwrap();
        assert_eq!(field, field::Field::Udp(field::udp::Field::SrcPort));
    }

    #[test]
    fn parse_field_udp_dst() {
        let field: field::Field = "udp.dst".parse().unwrap();
        assert_eq!(field, field::Field::Udp(field::udp::Field::DstPort));
    }

    #[test]
    fn parse_field_payload_avg_popcount() {
        let field: field::Field = "transport.payload.avg_popcount".parse().unwrap();
        assert_eq!(field, field::Field::PayloadAveragePopcount);
    }

    // =========================================================================
    // Per-host field parsing tests
    // =========================================================================

    #[test]
    fn parse_field_host_num_connections() {
        let field: field::Field = "host.num_connections".parse().unwrap();
        assert_eq!(field, field::Field::Env(field::env::Field::HostNumConnections));
    }

    #[test]
    fn parse_field_host_num_packets() {
        let field: field::Field = "host.num_packets".parse().unwrap();
        assert_eq!(field, field::Field::Env(field::env::Field::HostNumPackets));
    }

    #[test]
    fn program_host_num_connections_condition() {
        let prog: Program = "if field:host.num_connections > 10 : RETURN terminate"
            .parse()
            .unwrap();
        let pkt = make_tcp_packet(b"data");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();

        // Below threshold: allow
        let fields = EnvFields { host_num_connections: 5, ..Default::default() };
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::Allow);

        // Above threshold: terminate
        let fields = EnvFields { host_num_connections: 15, ..Default::default() };
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_host_num_packets_copy_to_register() {
        let prog: Program = "COPY field:host.num_packets -> reg:i.0"
            .parse()
            .unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = EnvFields { host_num_packets: 42, ..Default::default() };
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let _ = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        drop(banks);
        assert!(matches!(
            regs.get(&Register { ty: RegisterType::Int, index: 0, host: false }),
            Some(Value::Int(42))
        ));
    }

    // =========================================================================
    // Reset action program tests
    // =========================================================================

    #[test]
    fn program_parse_return_reset() {
        let prog: Program = "RETURN reset".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        assert!(matches!(
            prog.lines[0].operation,
            Operation::Return(Action::ResetAll)
        ));
    }

    #[test]
    fn program_run_returns_reset() {
        let prog: Program = "if field:tcp.payload.len > 0: RETURN reset".parse().unwrap();
        let pkt = make_tcp_packet(b"data");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::ResetAll);
    }

    // =========================================================================
    // Port-based conditional program tests
    // =========================================================================

    #[test]
    fn program_tcp_port_filter() {
        let source = "if field:tcp.dst == 80: RETURN reset";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"GET / HTTP/1.1");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::ResetAll);
    }

    #[test]
    fn program_tcp_port_filter_no_match() {
        let source = "if field:tcp.dst == 443: RETURN reset";
        let prog: Program = source.parse().unwrap();
        // Test packet has dst=80, not 443
        let pkt = make_tcp_packet(b"GET / HTTP/1.1");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::Allow);
    }

    #[test]
    fn program_udp_port_filter() {
        let source = "if field:udp.dst == 53: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_udp_packet(b"\x00\x00");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    #[test]
    fn program_popcount_threshold() {
        let source = "if field:transport.payload.avg_popcount > 3.4: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        // 0xFF bytes have popcount 8, well above 3.4
        let pkt = make_tcp_packet(&[0xFF, 0xFF]);
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
    }

    // =========================================================================
    // Destination host field parsing tests
    // =========================================================================

    #[test]
    fn parse_field_dst_host_num_connections() {
        let field: field::Field = "dst_host.num_connections".parse().unwrap();
        assert_eq!(field, field::Field::Env(field::env::Field::DstHostNumConnections));
    }

    #[test]
    fn parse_field_dst_host_num_packets() {
        let field: field::Field = "dst_host.num_packets".parse().unwrap();
        assert_eq!(field, field::Field::Env(field::env::Field::DstHostNumPackets));
    }

    // =========================================================================
    // Host register parsing and execution tests
    // =========================================================================

    #[test]
    fn program_parse_host_register() {
        let prog: Program = "COPY True -> hreg:b.0".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        match &prog.lines[0].operation {
            Operation::Copy { from, to } => {
                assert_eq!(*from, Input::Bool(true));
                assert_eq!(to.ty, RegisterType::Bool);
                assert_eq!(to.index, 0);
                assert!(to.host);
            }
            other => panic!("Expected Copy, got {:?}", other),
        }
    }

    #[test]
    fn program_host_register_write_and_read() {
        // Write True to hreg:b.0 then check it conditionally
        let source = "COPY True -> hreg:b.0\nif hreg:b.0 == True: RETURN terminate";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::TerminateAll);
        drop(banks);
        // Verify host register was written
        let hreg = Register { ty: RegisterType::Bool, index: 0, host: false };
        let val = host_regs.get(&hreg).unwrap();
        assert!(matches!(val, Value::Bool(true)));
    }

    // =========================================================================
    // Model operation parsing tests
    // =========================================================================

    #[test]
    fn program_parse_model_copy_to_input() {
        let prog: Program = "COPY 10 -> model:wf:in:0".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        match &prog.lines[0].operation {
            Operation::CopyToModel { from, name, index } => {
                assert_eq!(*from, Input::Int(10));
                assert_eq!(name, "wf");
                assert_eq!(*index, 0);
            }
            other => panic!("Expected CopyToModel, got {:?}", other),
        }
    }

    #[test]
    fn program_parse_model_output_read() {
        let prog: Program = "COPY model:wf:out:0 -> reg:f.0".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        match &prog.lines[0].operation {
            Operation::Copy { from, to } => {
                assert!(
                    matches!(from, Input::ModelOutput(slot) if slot.name == "wf" && slot.index == 0)
                );
                assert_eq!(to.ty, RegisterType::Float);
                assert_eq!(to.index, 0);
            }
            other => panic!("Expected Copy, got {:?}", other),
        }
    }

    #[test]
    fn program_parse_model_operation() {
        let prog: Program = "MODEL wf".parse().unwrap();
        assert_eq!(prog.lines.len(), 1);
        assert!(
            matches!(&prog.lines[0].operation, Operation::Model { name } if name == "wf")
        );
    }
}
