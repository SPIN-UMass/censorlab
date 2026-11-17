use crate::program::check::{check, CheckErrors, ModelSignatures};
use crate::program::config::Config as ProgramEnvConfig;
use crate::program::env::{EnvFields, RegisterBanks, RegisterWriteError};
use crate::program::packet::Packet;
use crate::program::packet::{IpVersionMetadata, TcpFlags, TransportMetadataExtra};
use crate::subnet::IpNet;
use fnv::FnvHashSet;
use lalrpop_util::lalrpop_mod;

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
    #[error("Program rejected: {0}")]
    Check(#[from] CheckErrors),
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
    /// Subnets declared with `subnet "cidr"`, referenced by index from SRC_IN/DST_IN
    #[serde(skip)]
    pub subnets: Vec<IpNet>,
}
impl Program {
    /// Loads a program for execution: parse, check against the configuration
    /// (see [`crate::program::check`]) and optimise.
    pub fn load(
        program_path: PathBuf,
        config: &ProgramEnvConfig,
        models: Option<&ModelSignatures>,
    ) -> Result<Self, ProgramLoadError> {
        let source = fs::read_to_string(program_path)?;
        Self::from_source_checked(&source, config, models)
    }
    /// Parse, check and optimise a program held in memory
    pub fn from_source_checked(
        source: &str,
        config: &ProgramEnvConfig,
        models: Option<&ModelSignatures>,
    ) -> Result<Self, ProgramLoadError> {
        let (mut program, line_numbers) =
            Self::parse_numbered(source).map_err(ProgramLoadError::Parse)?;
        check(&program, Some(&line_numbers), config, models)?;
        program.optimise();
        Ok(program)
    }
    /// Parse a program without checking or optimising it, also returning the
    /// 1-based source line number of each parsed line
    pub fn parse_numbered(s: &str) -> Result<(Self, Vec<usize>), String> {
        let mut lines = Vec::new();
        let mut line_numbers = Vec::new();
        let mut regexes = Vec::new();
        let mut subnets = Vec::new();
        for (number, line) in s.lines().enumerate() {
            let number = number + 1;
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
                    let re = BytesRegex::new(pattern).map_err(|e| {
                        format!("line {number}: invalid regex pattern \"{pattern}\": {e}")
                    })?;
                    regexes.push(re);
                } else {
                    return Err(format!(
                        "line {number}: invalid regex directive, expected regex \"pattern\", got: {trimmed}"
                    ));
                }
                continue;
            }
            // Parse subnet directives: subnet "cidr" (same strict syntax as the config)
            if let Some(rest) = trimmed.strip_prefix("subnet ") {
                let cidr = rest
                    .trim()
                    .strip_prefix('"')
                    .and_then(|r| r.strip_suffix('"'))
                    .ok_or_else(|| {
                        format!(
                            "line {number}: invalid subnet directive, expected subnet \"cidr\", got: {trimmed}"
                        )
                    })?;
                let net: IpNet = cidr
                    .parse()
                    .map_err(|e| format!("line {number}: invalid subnet directive: {e}"))?;
                subnets.push(net);
                continue;
            }
            let line = program_parse::LineParser::new()
                .parse(trimmed)
                .map_err(|e| format!("line {number}: {e}"))?;
            lines.push(line);
            line_numbers.push(number);
        }
        // Subnet references must name a declared subnet
        for (line, number) in lines.iter().zip(&line_numbers) {
            if let Operation::SubnetIn { index, .. } = line.operation {
                if index >= subnets.len() {
                    return Err(format!(
                        "line {number}: subnet index {index} out of bounds ({} subnet(s) declared): {line}",
                        subnets.len()
                    ));
                }
            }
        }
        Ok((Program { lines, regexes, subnets }, line_numbers))
    }
}
impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for re in &self.regexes {
            writeln!(f, "regex \"{}\"", re.as_str())?;
        }
        for net in &self.subnets {
            writeln!(f, "subnet \"{net}\"")?;
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
        Self::new_with_tables(lines, regexes, vec![])
    }
    pub fn new_with_tables(lines: Vec<Line>, regexes: Vec<BytesRegex>, subnets: Vec<IpNet>) -> Self {
        let mut program = Program { lines, regexes, subnets };
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
                | Regex { ref out, .. }
                | RegexSni { ref out, .. }
                | SubnetIn { ref out, .. } => {
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
        // Evaluate lines in order; the first executed RETURN (of any action,
        // including plain `allow`) ends processing of this packet.
        for line in &self.lines {
            if let Some(action) =
                line.run(packet, registers, fields, field_default_on_error, &self.regexes, &self.subnets, model_io, model_sender)?
            {
                return Ok(action);
            }
        }
        Ok(Action::default())
    }
}
impl FromStr for Program {
    type Err = String;
    /// Parse only: the program is neither checked nor optimised (use
    /// [`Program::from_source_checked`] / [`Program::load`] for execution)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_numbered(s).map(|(program, _)| program)
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
            | Regex { ref out, .. }
            | RegexSni { ref out, .. }
            | SubnetIn { ref out, .. } => Some(out.clone()),
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
        subnets: &[IpNet],
        model_io: &mut ModelIO,
        model_sender: Option<&std::sync::mpsc::SyncSender<crate::model::ModelThreadMessage>>,
    ) -> Result<Option<Action>, LineExecutionError> {
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
                RegexSni { index, out } => {
                    let re = regexes
                        .get(*index)
                        .ok_or(LineExecutionError::RegexIndex(*index))?;
                    let matched = packet
                        .tls
                        .hello
                        .as_ref()
                        .is_some_and(|h| h.sni_list.iter().any(|name| re.is_match(name)));
                    registers.set(out, &Value::Bool(matched))?;
                }
                SubnetIn { index, endpoint, out } => {
                    let net = subnets
                        .get(*index)
                        .ok_or(LineExecutionError::SubnetIndex(*index))?;
                    let addr: std::net::IpAddr = match (&packet.ip.version, endpoint) {
                        (IpVersionMetadata::V4 { src, .. }, Endpoint::Src) => (*src).into(),
                        (IpVersionMetadata::V4 { dst, .. }, Endpoint::Dst) => (*dst).into(),
                        (IpVersionMetadata::V6 { src, .. }, Endpoint::Src) => (*src).into(),
                        (IpVersionMetadata::V6 { dst, .. }, Endpoint::Dst) => (*dst).into(),
                    };
                    registers.set(out, &Value::Bool(net.contains(addr)))?;
                }
                Return(action) => {
                    return Ok(Some(*action));
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
            Ok(None)
        } else {
            Ok(None)
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
    #[error("Subnet index {0} out of bounds")]
    SubnetIndex(usize),
    #[error("Failed to send request to model thread")]
    ModelSendError,
    #[error("Failed to receive response from model thread")]
    ModelRecvError,
    #[error("Model inference error: {0}")]
    ModelError(crate::model::ModelThreadError),
}
impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // One source line per Line, so a displayed program parses back
        if let Some(ref cond) = self.condition {
            write!(f, "if {cond}: {}", self.operation)
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
    /// The register type this value belongs in
    pub fn type_of(&self) -> RegisterType {
        match self {
            Value::Float(_) => RegisterType::Float,
            Value::Int(_) => RegisterType::Int,
            Value::Bool(_) => RegisterType::Bool,
        }
    }
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
            Field(field) => write!(f, "field:{field}"),
            Register(reg) => reg.fmt(f),
            ModelOutput(slot) => write!(f, "model:{}:out:{}", slot.name, slot.index),
            Float(flt) => {
                // Float literals need a fractional part to parse as floats;
                // Rust's Display for f64 never uses exponent notation.
                let s = flt.to_string();
                if s.contains('.') {
                    f.write_str(&s)
                } else {
                    write!(f, "{s}.0")
                }
            }
            Int(i) => i.fmt(f),
            Bool(true) => f.write_str("True"),
            Bool(false) => f.write_str("False"),
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
        RegisterType, TransportMetadataExtra, TryFromIntError, Value,
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
        /// Packet direction (1 = client→WAN, -1 = WAN→client, 0 = unknown)
        Direction,
        /// Entropy of the transport-layer payload
        PayloadEntropy,
        /// Average popcount (bits per byte) of the transport-layer payload
        PayloadAveragePopcount,
        PayloadPrintableFraction,
        /// A field describing the connection's reassembled TLS ClientHello
        Tls(tls::Field),
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
                Field::Direction => Ok(Value::Int(packet.direction.into())),
                Field::PayloadEntropy => Ok(Value::Float(packet.payload_entropy())),
                Field::PayloadAveragePopcount => Ok(Value::Float(packet.payload_average_popcount())),
                Field::PayloadPrintableFraction => Ok(Value::Float(packet.payload_printable_fraction())),
                Field::Tls(field) => field.eval(packet, default_on_error).map_err(FieldError::Tls),
            }
        }
        /// Static type of the field: `eval` always yields a value of this type
        /// (including the default substituted on error)
        pub fn ty(&self) -> RegisterType {
            match self {
                Field::Env(_) | Field::Direction => RegisterType::Int,
                Field::Timestamp
                | Field::PayloadEntropy
                | Field::PayloadAveragePopcount
                | Field::PayloadPrintableFraction => RegisterType::Float,
                Field::Ip(field) => field.ty(),
                Field::Tcp(field) => field.ty(),
                Field::Udp(field) => field.ty(),
                Field::Tls(field) => field.ty(),
            }
        }
        pub fn all() -> Vec<Field> {
            let mut fields = vec![
                Field::Env(env::Field::NumPackets),
                Field::Env(env::Field::HostNumConnections),
                Field::Env(env::Field::HostNumPackets),
                Field::Env(env::Field::DstHostNumConnections),
                Field::Env(env::Field::DstHostNumPackets),
                Field::Timestamp,
            ];
            for field in ip::Field::all() {
                fields.push(Field::Ip(field))
            }
            for field in tcp::Field::all() {
                fields.push(Field::Tcp(field));
            }
            for field in udp::Field::all() {
                fields.push(Field::Udp(field));
            }
            fields.push(Field::Direction);
            fields.push(Field::PayloadEntropy);
            fields.push(Field::PayloadAveragePopcount);
            fields.push(Field::PayloadPrintableFraction);
            for field in tls::Field::all() {
                fields.push(Field::Tls(field));
            }
            fields
        }
    }
    impl Field {
        /// The field's name in CensorLang source (the inverse of `FieldParser`)
        pub fn name(&self) -> &'static str {
            use ip::{V4Field, V6Field};
            use tcp::Flag;
            match self {
                Field::Env(env::Field::NumPackets) => "env.num_packets",
                Field::Env(env::Field::HostNumConnections) => "host.num_connections",
                Field::Env(env::Field::HostNumPackets) => "host.num_packets",
                Field::Env(env::Field::DstHostNumConnections) => "dst_host.num_connections",
                Field::Env(env::Field::DstHostNumPackets) => "dst_host.num_packets",
                Field::Timestamp => "timestamp",
                Field::Ip(ip::Field::HeaderLen) => "ip.header_len",
                Field::Ip(ip::Field::TotalLen) => "ip.total_len",
                Field::Ip(ip::Field::HopLimit) => "ip.hop_limit",
                Field::Ip(ip::Field::V4(V4Field::Dscp)) => "ip4.dscp",
                Field::Ip(ip::Field::V4(V4Field::Ecn)) => "ip4.ecn",
                Field::Ip(ip::Field::V4(V4Field::Ident)) => "ip4.ident",
                Field::Ip(ip::Field::V4(V4Field::DontFrag)) => "ip4.dont_frag",
                Field::Ip(ip::Field::V4(V4Field::MoreFrags)) => "ip4.more_frags",
                Field::Ip(ip::Field::V4(V4Field::FragOffset)) => "ip4.frag_offset",
                Field::Ip(ip::Field::V4(V4Field::Checksum)) => "ip4.checksum",
                Field::Ip(ip::Field::V6(V6Field::TrafficClass)) => "ip6.traffic_class",
                Field::Ip(ip::Field::V6(V6Field::FlowLabel)) => "ip6.flow_label",
                Field::Ip(ip::Field::V6(V6Field::PayloadLen)) => "ip6.payload_len",
                Field::Tcp(tcp::Field::SrcPort) => "tcp.src",
                Field::Tcp(tcp::Field::DstPort) => "tcp.dst",
                Field::Tcp(tcp::Field::Seq) => "tcp.seq",
                Field::Tcp(tcp::Field::Ack) => "tcp.ack",
                Field::Tcp(tcp::Field::Flag(Flag::Fin)) => "tcp.flag.fin",
                Field::Tcp(tcp::Field::Flag(Flag::Syn)) => "tcp.flag.syn",
                Field::Tcp(tcp::Field::Flag(Flag::Rst)) => "tcp.flag.rst",
                Field::Tcp(tcp::Field::Flag(Flag::Psh)) => "tcp.flag.psh",
                Field::Tcp(tcp::Field::Flag(Flag::Ack)) => "tcp.flag.ack",
                Field::Tcp(tcp::Field::Flag(Flag::Urg)) => "tcp.flag.urg",
                Field::Tcp(tcp::Field::Flag(Flag::Ece)) => "tcp.flag.ece",
                Field::Tcp(tcp::Field::Flag(Flag::Cwr)) => "tcp.flag.cwr",
                Field::Tcp(tcp::Field::Flag(Flag::Ns)) => "tcp.flag.ns",
                Field::Tcp(tcp::Field::Length) => "tcp.len",
                Field::Tcp(tcp::Field::HeaderLength) => "tcp.header.len",
                Field::Tcp(tcp::Field::PayloadLength) => "tcp.payload.len",
                Field::Tcp(tcp::Field::UrgentAt) => "tcp.urgent_at",
                Field::Tcp(tcp::Field::WindowLength) => "tcp.window_len",
                Field::Udp(udp::Field::SrcPort) => "udp.src",
                Field::Udp(udp::Field::DstPort) => "udp.dst",
                Field::Udp(udp::Field::Length) => "udp.length",
                Field::Udp(udp::Field::Checksum) => "udp.checksum",
                Field::Direction => "direction",
                Field::PayloadEntropy => "transport.payload.entropy",
                Field::PayloadAveragePopcount => "transport.payload.avg_popcount",
                Field::PayloadPrintableFraction => "transport.payload.printable_fraction",
                Field::Tls(field) => field.name(),
            }
        }
    }
    impl std::fmt::Display for Field {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str(self.name())
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
        #[error("Error getting a TLS field: {0}")]
        Tls(tls::FieldError),
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
        use super::{IpVersionMetadata, Packet, TryFromIntError, RegisterType, Value};
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
            pub fn ty(&self) -> RegisterType {
                match self {
                    Field::V4(V4Field::DontFrag) | Field::V4(V4Field::MoreFrags) => {
                        RegisterType::Bool
                    }
                    _ => RegisterType::Int,
                }
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
                    Ok(result.unwrap_or_else(|_| self.ty().default_value()))
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
    /// Fields describing the connection's TCP-reassembled TLS ClientHello.
    ///
    /// `tls.hello.state` and `tls.hello.complete` are defined for every
    /// packet.  The remaining fields describe the ClientHello and exist once it
    /// has been recognised (`tls.hello.complete == True`: the completing packet
    /// and every later packet of the connection); before that they are an error, or 0/False with
    /// `field_default_on_error`.
    pub mod tls {
        use super::{Packet, RegisterType, Value};

        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum Field {
            /// 0 idle, 1 pending, 2 complete, 3 failed, 4 ambiguous
            State,
            /// True once the ClientHello has been recognised
            Complete,
            SniCount,
            SniInvalidUtf8,
            DuplicateExtensions,
            MalformedExtensions,
            RecordCount,
            TcpSegments,
        }
        impl Field {
            pub fn eval(
                &self,
                packet: &Packet,
                default_on_error: bool,
            ) -> Result<Value, FieldError> {
                use Field::*;
                let hello = packet.tls.hello.as_deref();
                let int = |f: fn(&crate::application::tls::ClientHelloInfo) -> usize| {
                    hello
                        .map(|h| Value::Int(i64::try_from(f(h)).unwrap_or(i64::MAX)))
                        .ok_or(FieldError::NoClientHello)
                };
                let flag = |f: fn(&crate::application::tls::ClientHelloInfo) -> bool| {
                    hello.map(|h| Value::Bool(f(h))).ok_or(FieldError::NoClientHello)
                };
                let (result, default) = match self {
                    State => (Ok(Value::Int(packet.tls.status.code())), Value::Int(0)),
                    Complete => (Ok(Value::Bool(hello.is_some())), Value::Bool(false)),
                    SniCount => (int(|h| h.sni_count()), Value::Int(0)),
                    SniInvalidUtf8 => (flag(|h| h.sni_invalid_utf8), Value::Bool(false)),
                    DuplicateExtensions => (flag(|h| h.duplicate_extensions), Value::Bool(false)),
                    MalformedExtensions => (int(|h| h.malformed_extensions.len()), Value::Int(0)),
                    RecordCount => (int(|h| h.record_count), Value::Int(0)),
                    TcpSegments => (int(|h| h.tcp_segments), Value::Int(0)),
                };
                if default_on_error {
                    Ok(result.unwrap_or(default))
                } else {
                    result
                }
            }
            /// Static type of the field (also the type of its default)
            pub fn ty(&self) -> RegisterType {
                use Field::*;
                match self {
                    Complete | SniInvalidUtf8 | DuplicateExtensions => RegisterType::Bool,
                    State | SniCount | MalformedExtensions | RecordCount | TcpSegments => {
                        RegisterType::Int
                    }
                }
            }
            /// The field's name in CensorLang source
            pub fn name(&self) -> &'static str {
                use Field::*;
                match self {
                    State => "tls.hello.state",
                    Complete => "tls.hello.complete",
                    SniCount => "tls.hello.sni_count",
                    SniInvalidUtf8 => "tls.hello.sni_invalid_utf8",
                    DuplicateExtensions => "tls.hello.duplicate_extensions",
                    MalformedExtensions => "tls.hello.malformed_extensions",
                    RecordCount => "tls.hello.record_count",
                    TcpSegments => "tls.hello.tcp_segments",
                }
            }
            pub fn all() -> Vec<Field> {
                use Field::*;
                vec![
                    State,
                    Complete,
                    SniCount,
                    SniInvalidUtf8,
                    DuplicateExtensions,
                    MalformedExtensions,
                    RecordCount,
                    TcpSegments,
                ]
            }
        }
        #[derive(Debug, thiserror::Error)]
        pub enum FieldError {
            #[error("No ClientHello has been recognised on this connection yet")]
            NoClientHello,
        }
    }
    pub mod tcp {
        use super::{Packet, TcpFlags, TransportMetadataExtra, TryFromIntError, RegisterType, Value};

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
            pub fn ty(&self) -> RegisterType {
                match self {
                    Field::Flag(_) => RegisterType::Bool,
                    _ => RegisterType::Int,
                }
            }
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
                            Seq => Ok(Value::Int(tcp_metadata.seq_number().into())),
                            Ack => Ok(Value::Int(tcp_metadata.ack_number().into())),
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
                    Ok(result.unwrap_or_else(|_| self.ty().default_value()))
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
        use super::{Packet, TransportMetadataExtra, TryFromIntError, RegisterType, Value};
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
            pub fn ty(&self) -> RegisterType {
                RegisterType::Int
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
                    Ok(result.unwrap_or_else(|_| self.ty().default_value()))
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
        self.ty.default_value()
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
impl RegisterType {
    /// Zero value of the type: initial register contents and the value of a
    /// field that cannot be read when `field_default_on_error` is set
    pub fn default_value(&self) -> Value {
        match self {
            RegisterType::Float => Value::Float(0.0),
            RegisterType::Int => Value::Int(0),
            RegisterType::Bool => Value::Bool(false),
        }
    }
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
                    // Promote to Int first (False - True == -1, not a u8 underflow)
                    Value::Int(op.call(i64::from(*l), i64::from(*r)))
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
/// Arithmetic as CensorLang defines it.  Every operation is total, so a program
/// can never fault (or panic the engine) on any packet:
///
/// * integers use two's-complement wrapping (`i64::MAX + 1 == i64::MIN`,
///   `i64::MIN / -1 == i64::MIN`, `i64::MIN % -1 == 0`), identically in debug
///   and release builds;
/// * division and modulo by zero yield zero, for integers and floats alike;
/// * floats otherwise follow IEEE 754.
trait Arith: Copy {
    fn cl_add(self, rhs: Self) -> Self;
    fn cl_sub(self, rhs: Self) -> Self;
    fn cl_mul(self, rhs: Self) -> Self;
    fn cl_div(self, rhs: Self) -> Self;
    fn cl_rem(self, rhs: Self) -> Self;
}
impl Arith for i64 {
    fn cl_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn cl_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
    fn cl_mul(self, rhs: Self) -> Self {
        self.wrapping_mul(rhs)
    }
    fn cl_div(self, rhs: Self) -> Self {
        if rhs == 0 {
            0
        } else {
            self.wrapping_div(rhs)
        }
    }
    fn cl_rem(self, rhs: Self) -> Self {
        if rhs == 0 {
            0
        } else {
            self.wrapping_rem(rhs)
        }
    }
}
impl Arith for f64 {
    fn cl_add(self, rhs: Self) -> Self {
        self + rhs
    }
    fn cl_sub(self, rhs: Self) -> Self {
        self - rhs
    }
    fn cl_mul(self, rhs: Self) -> Self {
        self * rhs
    }
    fn cl_div(self, rhs: Self) -> Self {
        if rhs == 0.0 {
            0.0
        } else {
            self / rhs
        }
    }
    fn cl_rem(self, rhs: Self) -> Self {
        if rhs == 0.0 {
            0.0
        } else {
            self % rhs
        }
    }
}
impl MathOperatorNumeric {
    fn call<T: Arith>(&self, lhs: T, rhs: T) -> T {
        use MathOperatorNumeric::*;
        match self {
            Add => lhs.cl_add(rhs),
            Sub => lhs.cl_sub(rhs),
            Mul => lhs.cl_mul(rhs),
            Div => lhs.cl_div(rhs),
            Mod => lhs.cl_rem(rhs),
        }
    }
}
/// Which packet address a SubnetIn operation tests
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Src,
    Dst,
}
impl fmt::Display for Endpoint {
    /// The CensorLang opcode for this endpoint
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Endpoint::Src => write!(f, "SRC_IN"),
            Endpoint::Dst => write!(f, "DST_IN"),
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
    /// True if any SNI host_name of the connection's recognised ClientHello
    /// matches regex `index` (False until a ClientHello has been recognised).
    RegexSni {
        index: usize,
        out: Register,
    },
    /// Whether the packet's source/destination address is in declared subnet `index`
    SubnetIn {
        index: usize,
        endpoint: Endpoint,
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
            Copy { from, to } => write!(f, "COPY {from} -> {to}"),
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
                write!(f, "{name} {lhs}, {rhs} -> {out}")
            }
            Regex { index, out } => write!(f, "REGEX {index} -> {out}"),
            RegexSni { index, out } => write!(f, "REGEX_SNI {index} -> {out}"),
            SubnetIn { index, endpoint, out } => write!(f, "{endpoint} {index} -> {out}"),
            Return(action) => write!(f, "RETURN {action}"),
            Noop => write!(f, "NOOP"),
            Model { ref name } => write!(f, "MODEL {name}"),
            CopyToModel { from, name, index } => {
                write!(f, "COPY {from} -> model:{name}:in:{index}")
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
            tls: Default::default(),
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
            tls: Default::default(),
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

    #[test]
    fn negative_literals_are_negative() {
        // The grammar accepted a leading '-' but discarded it, so `-1 == 1`.
        let prog: Program = "if field:direction == -1: RETURN terminate".parse().unwrap();
        match &prog.lines[0].condition.as_ref().unwrap().rhs {
            Input::Int(v) => assert_eq!(*v, -1),
            other => panic!("expected Int(-1), got {other:?}"),
        }
        let prog: Program = "if field:transport.payload.entropy < -0.5: RETURN terminate".parse().unwrap();
        match &prog.lines[0].condition.as_ref().unwrap().rhs {
            Input::Float(v) => assert_eq!(*v, -0.5),
            other => panic!("expected Float(-0.5), got {other:?}"),
        }
    }

    #[test]
    fn program_run_conditional_return_allow_stops_execution() {
        // `RETURN allow` must end evaluation of the current packet even though
        // `allow` is also the default (no-op) action.  A guard such as
        // `if field:tcp.payload.len == 0: RETURN allow` must prevent a later
        // unconditional `RETURN allow_all` from whitelisting the connection.
        let source = "if field:tcp.payload.len == 0: RETURN allow\nRETURN allow_all";
        let prog: Program = source.parse().unwrap();
        let pkt = make_tcp_packet(b"");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::Allow);

        // With a payload the guard does not fire and the program falls through.
        let pkt = make_tcp_packet(b"data");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        let result = prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap();
        assert_eq!(result, Action::AllowAll);
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
    fn field_default_on_error_is_typed() {
        let pkt = make_udp_packet(b"data");
        let val = field::tcp::Field::Flag(field::tcp::Flag::Syn).eval(&pkt, true).unwrap();
        assert!(matches!(val, Value::Bool(false)), "{val:?}");
        let mut v6 = make_tcp_packet(b"");
        v6.ip.version = IpVersionMetadata::V6 {
            src: smoltcp::wire::Ipv6Address::UNSPECIFIED,
            dst: smoltcp::wire::Ipv6Address::UNSPECIFIED,
            traffic_class: 0,
            flow_label: 0,
            payload_len: 0,
        };
        let val = field::ip::Field::V4(field::ip::V4Field::DontFrag).eval(&v6, true).unwrap();
        assert!(matches!(val, Value::Bool(false)), "{val:?}");
    }

    #[test]
    fn field_tcp_seq_ack_non_negative() {
        let mut pkt = make_tcp_packet(b"");
        if let TransportMetadataExtra::Tcp(ref mut tcp) = pkt.transport.extra {
            tcp.seq = TcpSeqNumber(-1);
            tcp.ack = TcpSeqNumber(i32::MIN);
        }
        let seq = field::tcp::Field::Seq.eval(&pkt, false).unwrap();
        let ack = field::tcp::Field::Ack.eval(&pkt, false).unwrap();
        assert!(matches!(seq, Value::Int(4294967295)), "{seq:?}");
        assert!(matches!(ack, Value::Int(2147483648)), "{ack:?}");
    }

    #[test]
    fn field_values_match_static_types() {
        // Every field evaluates to its declared static type, both when present
        // and when defaulted on error.
        let fields = EnvFields::default();
        for pkt in [make_tcp_packet(b"abc"), make_udp_packet(b"abc")] {
            for f in field::Field::all() {
                let v = f.eval(&pkt, &fields, true).unwrap();
                assert_eq!(Value::type_of(&v), f.ty(), "{f:?} -> {v:?}");
            }
        }
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
            subnets: vec![],
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
    // Group 8b: subnet membership (SRC_IN / DST_IN)
    // =========================================================================

    fn run_source(source: &str) -> Action {
        let prog: Program = source.parse().unwrap();
        // make_tcp_packet: 10.0.0.1 -> 10.0.0.2
        let pkt = make_tcp_packet(b"data");
        let mut regs = default_registers();
        let mut host_regs = default_host_registers();
        let fields = default_env_fields();
        let mut banks = RegisterBanks::new(&mut regs, &mut host_regs);
        prog.run(&pkt, &mut banks, &fields, false, &mut ModelIO::default(), None).unwrap()
    }

    #[test]
    fn program_parse_subnet_directive() {
        let source = "subnet \"10.0.0.0/8\"\nsubnet \"2001:db8::/32\"\nsubnet \"1.2.3.4\"\nSRC_IN 2 -> reg:b.0\nDST_IN 0 -> reg:b.1";
        let prog: Program = source.parse().unwrap();
        let nets: Vec<String> = prog.subnets.iter().map(|n| n.to_string()).collect();
        assert_eq!(nets, ["10.0.0.0/8", "2001:db8::/32", "1.2.3.4/32"]);
        // Display round-trips
        let reparsed: Program = prog.to_string().parse().unwrap();
        assert_eq!(reparsed.to_string(), prog.to_string());
        assert!(prog.to_string().contains("SRC_IN 2 -> reg:b.0"), "{prog}");
    }

    #[test]
    fn program_subnet_src_and_dst() {
        // 10.0.0.0/31 holds the source (10.0.0.1) but not the destination (10.0.0.2)
        let source = "subnet \"10.0.0.0/31\"\nDST_IN 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate\nSRC_IN 0 -> reg:b.1\nif reg:b.1 == True: RETURN reset";
        assert_eq!(run_source(source), Action::ResetAll);
        let source = "subnet \"10.0.0.2\"\nDST_IN 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate\nSRC_IN 0 -> reg:b.1\nif reg:b.1 == True: RETURN reset";
        assert_eq!(run_source(source), Action::TerminateAll);
        // Other family never matches
        let source = "subnet \"::/0\"\nDST_IN 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate\nSRC_IN 0 -> reg:b.1\nif reg:b.1 == True: RETURN reset";
        assert_eq!(run_source(source), Action::Allow);
        // /0 matches everything of its family
        let source = "subnet \"0.0.0.0/0\"\nDST_IN 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate";
        assert_eq!(run_source(source), Action::TerminateAll);
    }

    #[test]
    fn program_subnet_invalid_rejected_at_parse() {
        for bad in [
            "subnet \"10.0.0.1/8\"",
            "subnet \"10.0.0.0/33\"",
            "subnet \"2001:db8::/129\"",
            "subnet 10.0.0.0/8",
            "subnet \"10.0.0.0/8\" extra",
            "subnet \"\"",
        ] {
            assert!(bad.parse::<Program>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn program_subnet_index_checked_at_parse() {
        assert!("SRC_IN 0 -> reg:b.0".parse::<Program>().is_err());
        assert!("subnet \"10.0.0.0/8\"\nDST_IN 1 -> reg:b.0".parse::<Program>().is_err());
        assert!("subnet \"10.0.0.0/8\"\nif reg:b.1 == True: DST_IN 0 -> reg:b.0".parse::<Program>().is_ok());
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
    fn field_payload_printable_fraction() {
        // 'A' and ' ' are printable, 0x00 and 0xFF are not -> 2/4
        let pkt = make_tcp_packet(&[b'A', 0x00, b' ', 0xFF]);
        let field = field::Field::PayloadPrintableFraction;
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Float(f) if f == 0.5));
    }

    #[test]
    fn parse_field_payload_printable_fraction() {
        let field: field::Field = "transport.payload.printable_fraction".parse().unwrap();
        assert_eq!(field, field::Field::PayloadPrintableFraction);
    }

    #[test]
    fn field_payload_average_popcount() {
        // 0xFF has popcount 8, 0x00 has popcount 0 -> avg = 4.0
        let pkt = make_tcp_packet(&[0xFF, 0x00]);
        let field = field::Field::PayloadAveragePopcount;
        let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
        assert!(matches!(result, Value::Float(f) if f == 4.0));
    }

    #[test]
    fn empty_payload_features_are_zero_not_nan() {
        // Entropy, popcount and printable fraction must all be 0.0 for an
        // empty payload; NaN would silently poison comparisons and model inputs.
        let pkt = make_tcp_packet(&[]);
        for field in [
            field::Field::PayloadEntropy,
            field::Field::PayloadAveragePopcount,
            field::Field::PayloadPrintableFraction,
        ] {
            let result = field.eval(&pkt, &default_env_fields(), false).unwrap();
            assert!(
                matches!(result, Value::Float(f) if f == 0.0),
                "{field:?} on empty payload gave {result:?}"
            );
        }
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

    // --- Integer arithmetic is total: two's-complement wrapping, x/0 = x%0 = 0 ---

    fn int_op(op: MathOperatorNumeric, l: i64, r: i64) -> i64 {
        match MathOperator::Numeric(op).call(&Value::Int(l), &Value::Int(r)) {
            Value::Int(i) => i,
            other => panic!("expected Int, got {other:?}"),
        }
    }

    #[test]
    fn math_int_overflow_wraps() {
        assert_eq!(int_op(MathOperatorNumeric::Add, i64::MAX, 1), i64::MIN);
        assert_eq!(int_op(MathOperatorNumeric::Sub, i64::MIN, 1), i64::MAX);
        assert_eq!(int_op(MathOperatorNumeric::Mul, i64::MAX, 2), -2);
        assert_eq!(int_op(MathOperatorNumeric::Div, i64::MIN, -1), i64::MIN);
        assert_eq!(int_op(MathOperatorNumeric::Mod, i64::MIN, -1), 0);
        assert_eq!(int_op(MathOperatorNumeric::Div, i64::MIN, 0), 0);
        assert_eq!(int_op(MathOperatorNumeric::Mod, 7, 0), 0);
        assert_eq!(int_op(MathOperatorNumeric::Div, -7, 2), -3);
        assert_eq!(int_op(MathOperatorNumeric::Mod, -7, 2), -1);
    }

    #[test]
    fn math_bool_bool_promotes_to_int() {
        let v = MathOperator::Numeric(MathOperatorNumeric::Sub).call(&Value::Bool(false), &Value::Bool(true));
        assert!(matches!(v, Value::Int(-1)));
    }

    #[test]
    fn optimise_folds_overflowing_constants_without_panicking() {
        let prog: Program = "DIV -9223372036854775808, -1 -> reg:i.0\nif reg:i.0 < 0: RETURN terminate"
            .parse()
            .unwrap();
        let prog = Program::new(prog.lines);
        assert!(matches!(
            &prog.lines[0].operation,
            Operation::Copy { from: Input::Int(i64::MIN), .. }
        ));
    }

    #[test]
    fn math_float_division_by_zero_is_zero() {
        let v = MathOperator::Numeric(MathOperatorNumeric::Div).call(&Value::Float(1.0), &Value::Float(0.0));
        assert!(matches!(v, Value::Float(f) if f == 0.0));
    }

    // --- Loading for execution checks and optimises ---

    #[test]
    fn from_source_checked_rejects_ill_typed_program() {
        let config = ProgramEnvConfig::default();
        let err = Program::from_source_checked("DIV field:tcp.payload.len, 2 -> reg:f.0", &config, None)
            .unwrap_err();
        assert!(matches!(err, ProgramLoadError::Check(_)), "{err}");
        let err = Program::from_source_checked("COPY 1 -> reg:i.0\nNOPE", &config, None).unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn from_source_checked_optimises() {
        let config = ProgramEnvConfig::default();
        let prog = Program::from_source_checked("NOOP\nADD 2, 3 -> reg:i.0\nif reg:i.0 == 5: RETURN terminate\nRETURN allow\nRETURN reset", &config, None)
            .unwrap();
        assert_eq!(prog.to_string(), "COPY 5 -> reg:i.0\nif reg:i.0 == 5: RETURN terminate\nRETURN allow\n");
    }

    // --- Display is the inverse of parsing ---

    #[test]
    fn field_display_round_trips() {
        for f in field::Field::all() {
            let shown = f.to_string();
            let parsed: field::Field = shown.parse().unwrap_or_else(|e| panic!("{shown}: {e}"));
            assert_eq!(parsed, f);
        }
    }

    #[test]
    fn program_display_round_trips() {
        let src = r#"regex "^(GET |POST )"
regex "a\"b"
if field:tcp.payload.len == 0: RETURN allow
if field:ip4.dont_frag == True: RETURN allow_all
if reg:b.0 != False: RETURN terminate
COPY field:transport.payload.entropy -> reg:f.1
COPY 1.0 -> reg:f.2
COPY -2.5 -> reg:f.3
COPY -9223372036854775808 -> reg:i.1
ADD reg:i.1, 1 -> reg:i.1
SUB hreg:i.2, field:env.num_packets -> hreg:i.2
MUL 2, reg:f.1 -> reg:f.1
DIV field:tcp.payload.len, 2 -> reg:i.3
MOD reg:i.3, 7 -> reg:i.3
AND reg:b.0, True -> reg:b.1
OR reg:b.0, field:tcp.flag.syn -> reg:b.1
XOR reg:b.0, reg:b.1 -> reg:b.2
REGEX 1 -> reg:b.0
COPY reg:f.1 -> model:m:in:3
MODEL m
COPY model:m:out:1 -> reg:f.4
if field:tcp.seq >= 100: RETURN reset
if reg:f.1 xnor reg:b.2: RETURN reset
NOOP
"#;
        let prog: Program = src.parse().unwrap();
        let shown = prog.to_string();
        let reparsed: Program = shown.parse().unwrap_or_else(|e| panic!("{shown}\n{e}"));
        assert_eq!(reparsed.lines.len(), prog.lines.len());
        assert_eq!(reparsed.to_string(), shown);
        // Values survive the round trip exactly
        assert!(shown.contains("COPY 1.0 -> reg:f.2"), "{shown}");
        assert!(shown.contains("field:ip4.dont_frag == True"), "{shown}");
        assert!(shown.contains("DIV field:tcp.payload.len, 2 -> reg:i.3"), "{shown}");
    }

    // --- Parser robustness: numeric literals are recognized, never panic ---

    #[test]
    fn parse_out_of_range_integer_is_error() {
        assert!("COPY 99999999999999999999 -> reg:i.0".parse::<Program>().is_err());
        assert!("COPY -99999999999999999999 -> reg:i.0".parse::<Program>().is_err());
    }

    #[test]
    fn parse_i64_min_literal() {
        let prog: Program = "COPY -9223372036854775808 -> reg:i.0".parse().unwrap();
        assert!(matches!(
            &prog.lines[0].operation,
            Operation::Copy { from: Input::Int(i64::MIN), .. }
        ));
    }

    #[test]
    fn parse_out_of_range_register_index_is_error() {
        assert!("COPY 1 -> reg:i.99999999999999999999".parse::<Program>().is_err());
        assert!("REGEX 99999999999999999999 -> reg:b.0".parse::<Program>().is_err());
        assert!("COPY 1 -> model:m:in:99999999999999999999".parse::<Program>().is_err());
        assert!("COPY model:m:out:99999999999999999999 -> reg:f.0".parse::<Program>().is_err());
    }

    #[test]
    fn parse_non_finite_float_is_error() {
        let huge = format!("COPY {}.0 -> reg:f.0", "9".repeat(400));
        assert!(huge.parse::<Program>().is_err());
    }

    #[test]
    fn parse_model_name_that_is_a_keyword() {
        // Model names follow the same rule in MODEL and in model:<name>:in/out
        let prog: Program = "COPY 1 -> model:f:in:0\nMODEL f\nCOPY model:f:out:0 -> reg:f.0"
            .parse()
            .unwrap();
        assert!(matches!(&prog.lines[1].operation, Operation::Model { name } if name == "f"));
        let prog: Program = "MODEL allow".parse().unwrap();
        assert!(matches!(&prog.lines[0].operation, Operation::Model { name } if name == "allow"));
    }
}
