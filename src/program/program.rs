use crate::program::env::{EnvFields, RegisterWriteError, Registers};
use crate::program::packet::Packet;
use crate::program::packet::{IpVersionMetadata, TcpFlags, TransportMetadataExtra};
use fnv::FnvHashSet;
use lalrpop_util::lalrpop_mod;
use num::Zero;
use serde::Deserialize;
use serde_with::DeserializeFromStr;
use std::fmt;
use std::fs;
use std::io;
use std::num::TryFromIntError;
use std::path::PathBuf;
use std::str::FromStr;

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
}
impl Program {
    /// Loads a program
    pub fn load(program_path: PathBuf) -> Result<Self, io::Error> {
        // Load the program
        let program = fs::read_to_string(program_path)?;
        // TODO: Handle error
        let program = program.parse().unwrap();
        Ok(program)
    }
}
impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{}", line)?;
        }
        Ok(())
    }
}
impl Program {
    pub fn new(lines: Vec<Line>) -> Self {
        let mut program = Program { lines };
        program.optimise();
        program
    }
    pub fn non_return_points(&self) -> impl Iterator<Item = (usize, &Line)> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| !matches!(line.operation, Operation::Model | Operation::Return(_)))
    }
    pub fn return_points(&self) -> impl Iterator<Item = (usize, &Line)> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| matches!(line.operation, Operation::Model | Operation::Return(_)))
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
                    if written.contains(&reg.index) {
                        regs.insert(reg.index);
                    } else {
                        condition.lhs = reg.as_uninitialized_value().into();
                        changed = true;
                    }
                }
                if let Input::Register(ref reg) = condition.rhs {
                    if written.contains(&reg.index) {
                        regs.insert(reg.index);
                    } else {
                        condition.rhs = reg.as_uninitialized_value().into();
                        changed = true;
                    }
                }
            }
            use Operation::*;
            match line.operation {
                Copy { ref mut from, .. } => {
                    if let Input::Register(ref reg) = from {
                        if written.contains(&reg.index) {
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
                        if written.contains(&reg.index) {
                            regs.insert(reg.index);
                        } else {
                            *lhs = reg.as_uninitialized_value().into();
                            changed = true;
                        }
                    }
                    if let Input::Register(ref reg) = rhs {
                        if written.contains(&reg.index) {
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
                    regs.push(Some(to.index));
                }
                Add { ref out, .. }
                | Sub { ref out, .. }
                | Mul { ref out, .. }
                | Div { ref out, .. }
                | Mod { ref out, .. }
                | And { ref out, .. }
                | Or { ref out, .. }
                | Xor { ref out, .. } => {
                    regs.push(Some(out.index));
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
        registers: &mut Registers,
        fields: &EnvFields,
        field_default_on_error: bool,
    ) -> Result<Action, LineExecutionError> {
        let mut action = Action::default();
        for line in &self.lines {
            action = line.run(packet, registers, fields, field_default_on_error)?;
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
        for line in s.lines() {
            let line = program_parse::LineParser::new()
                .parse(line)
                .map_err(|e| e.to_string())?;
            lines.push(line);
        }
        Ok(Program { lines })
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
            | Xor { ref out, .. } => Some(out.clone()),
            _ => None,
        }
    }
    pub fn run(
        &self,
        packet: &Packet,
        registers: &mut Registers,
        fields: &EnvFields,
        field_default_on_error: bool,
    ) -> Result<Action, LineExecutionError> {
        // Only execute the line if the condition evaluates to true
        if self
            .condition
            .as_ref()
            .map(|cond| cond.eval(packet, &*registers, fields, field_default_on_error))
            .transpose()?
            .unwrap_or(true)
        {
            use Operation::*;
            match &self.operation {
                Copy { from, to } => {
                    let val = from.eval(packet, &*registers, fields, field_default_on_error)?;
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
                    )?;
                }
                Return(action) => {
                    return Ok(*action);
                }
                Noop => {}
                Model => {}
            };
            Ok(Action::default())
        } else {
            Ok(Action::default())
        }
    }
    fn run_math_operator(
        packet: &Packet,
        registers: &mut Registers,
        fields: &EnvFields,
        math_operator: MathOperator,
        lhs: &Input,
        rhs: &Input,
        out: &Register,
        field_default_on_error: bool,
    ) -> Result<(), LineExecutionError> {
        let lhs = lhs.eval(packet, &*registers, fields, field_default_on_error)?;
        let rhs = rhs.eval(packet, &*registers, fields, field_default_on_error)?;
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
        registers: &Registers,
        fields: &EnvFields,
        field_default_on_error: bool,
    ) -> Result<bool, ConditionError> {
        // Evaluate the value of the LHS
        let lhs = self
            .lhs
            .eval(packet, registers, fields, field_default_on_error)
            .map_err(ConditionError::Lhs)?;
        // Evaluate the value of the RHS
        let rhs = self
            .rhs
            .eval(packet, registers, fields, field_default_on_error)
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
                Input::Field(_) | Input::Register(_) => {
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
            _ => None,
        }
    }
    pub fn eval(
        &self,
        packet: &Packet,
        registers: &Registers,
        fields: &EnvFields,
        field_default_on_error: bool,
    ) -> Result<Value, InputError> {
        match self {
            Input::Field(field) => field
                .eval(packet, fields, field_default_on_error)
                .map_err(|e| e.into()),
            Input::Register(reg) => registers
                .get(reg)
                .ok_or(InputError::RegisterIndex(reg.index)),
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
            }
        }
        // TODO: macro
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
        }

        impl Field {
            pub fn eval(&self, fields: &EnvFields) -> Value {
                use Field::*;
                match self {
                    NumPackets => Value::Int(fields.num_packets.into()),
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
                    // TODO: pick custom defaults for each field
                    Ok(result.unwrap_or(Value::Bool(false)))
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
            fn all() -> Vec<Self> {
                use V4Field::*;
                vec![Dscp, Ecn, Ident, DontFrag, MoreFrags, FragOffset, Checksum]
            }
        }
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum V6Field {
            TrafficClass,
            FlowLabel,
            PayloadLen,
        }
        impl V6Field {
            fn all() -> Vec<Self> {
                use V6Field::*;
                vec![TrafficClass, FlowLabel, PayloadLen]
            }
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
            Seq,
            Ack,
            Flag(Flag),
            Length,
            HeaderLength,
            PayloadLength,
            UrgentAt,
            WindowLength,
            // TODO: options
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
                    // TODO: pick custom defaults for each field
                    Ok(result.unwrap_or(Value::Bool(false)))
                } else {
                    result
                }
            }
            pub fn all() -> Vec<Field> {
                vec![
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
            Length,
            Checksum,
        }
        impl Field {
            pub fn all() -> [Field; 2] {
                [Field::Length, Field::Checksum]
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
                            Length => Ok(Value::Int(udp_metadata.length.into())),
                            Checksum => Ok(Value::Int(udp_metadata.checksum.into())),
                        }
                    } else {
                        Err(FieldError::WrongProtocol)
                    };
                if default_on_error {
                    // TODO: pick custom defaults for each field
                    Ok(result.unwrap_or(Value::Bool(false)))
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
}
impl Register {
    pub fn to_label(&self) -> String {
        format!("reg_{}_{}", self.ty, self.index)
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
        write!(f, "reg:{}.{}", self.ty, self.index)
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
#[derive(Clone, Debug, PartialEq, DeserializeFromStr)]
pub enum Operator {
    Comparison(ComparisonOperator),
    Logic(LogicOperator),
}
impl Operator {
    // TODO: make a macro to auto generate this
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
    {
        // Warn if there was precision loss
        // TODO: should this be an error
        let i2: i64 = f as i64;
        if i2 != i {
            //warn!("Precision loss in i64->f64")
        }
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
    Return(Action),
    Noop,
    Model,
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
        f.write_str(match self {
            Copy { .. } => "COPY",
            Add { .. } => "ADD",
            Sub { .. } => "SUB",
            Mul { .. } => "MUL",
            Div { .. } => "DIV",
            Mod { .. } => "MOD",
            And { .. } => "AND",
            Or { .. } => "OR",
            Xor { .. } => "XOR",
            Return(_) => "RETURN ",
            Noop => "NOOP",
            Model => "MODEL",
        })?;
        match self {
            Copy { from, to } => write!(f, " {from}->{to}"),
            Add { lhs, rhs, out }
            | Sub { lhs, rhs, out }
            | Mul { lhs, rhs, out }
            | Div { lhs, rhs, out }
            | Mod { lhs, rhs, out }
            | And { lhs, rhs, out }
            | Or { lhs, rhs, out }
            | Xor { lhs, rhs, out } => write!(f, " {lhs},{rhs}->{out}"),
            Return(action) => action.fmt(f),
            _ => Ok(()),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, DeserializeFromStr)]
pub enum Action {
    #[default]
    Allow,
    AllowAll,
    TerminateAll,
}
impl Action {
    // TODO: make this a macro
    pub fn all() -> Vec<Self> {
        vec![Action::Allow, Action::AllowAll, Action::TerminateAll]
    }
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
        })
    }
}
