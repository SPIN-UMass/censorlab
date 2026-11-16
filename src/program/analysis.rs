//! Static analysis of CensorLang programs.
//!
//! CensorLang is loop-free and operates on fixed, typed register banks, so the
//! resources a program can consume are decidable from its text alone:
//!
//! * **Per-connection memory** is the set of connection registers the program
//!   can ever touch (plus the engine's fixed per-connection bookkeeping); host
//!   registers are shared by all connections of a host and are reported
//!   separately.
//! * **Per-packet work** is bounded by the number of lines: every line runs at
//!   most once per packet and the first executed `RETURN` ends evaluation.  The
//!   bound is reported as a vector of operation counts so that a cost model
//!   (cycles per copy, per arithmetic op, per regex byte, per model call) can be
//!   dotted with it.  Regex evaluations are linear in payload length (the
//!   `regex` crate guarantees linear-time matching), model calls cost whatever
//!   the ONNX graph costs — both are therefore reported as counts.
//!
//! The analysis runs on the *optimised* program, i.e. what the engine executes.

use crate::program::program::{Input, Line, Operation, Program, Register, RegisterType};
use serde::Serialize;
use std::collections::BTreeSet;

/// Size in bytes of one register of each type.
pub const FLOAT_REGISTER_BYTES: usize = 8;
pub const INT_REGISTER_BYTES: usize = 8;
pub const BOOL_REGISTER_BYTES: usize = 1;

/// Fixed per-connection state the engine keeps for every CensorLang
/// connection regardless of the program: packet counter and connection
/// bookkeeping (`EnvFields`, one `u32` each for the five counters).
pub const ENGINE_PER_CONNECTION_BYTES: usize = 5 * 4;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RegisterUsage {
    pub float: BTreeSet<usize>,
    pub int: BTreeSet<usize>,
    pub bool: BTreeSet<usize>,
}

impl RegisterUsage {
    fn insert(&mut self, reg: &Register) {
        match reg.ty {
            RegisterType::Float => self.float.insert(reg.index),
            RegisterType::Int => self.int.insert(reg.index),
            RegisterType::Bool => self.bool.insert(reg.index),
        };
    }

    /// Bytes needed to hold exactly the registers used.
    pub fn bytes(&self) -> usize {
        self.float.len() * FLOAT_REGISTER_BYTES
            + self.int.len() * INT_REGISTER_BYTES
            + self.bool.len() * BOOL_REGISTER_BYTES
    }

    pub fn count(&self) -> usize {
        self.float.len() + self.int.len() + self.bool.len()
    }
}

/// Per-packet operation counts — the upper bound on what one packet can cost.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OperationCounts {
    /// Lines guarded by an `if`: one comparison each.
    pub conditions: usize,
    /// Register/field/constant reads (condition operands + operation inputs).
    pub reads: usize,
    /// Register writes.
    pub writes: usize,
    pub copies: usize,
    pub arithmetic: usize,
    pub logic: usize,
    /// Regex evaluations against the payload (each linear in payload length).
    pub regex: usize,
    pub model_inputs: usize,
    pub model_calls: usize,
    pub returns: usize,
}

impl OperationCounts {
    /// Total primitive operations excluding the payload-proportional regex and
    /// model terms (which are reported as counts).
    pub fn constant_ops(&self) -> usize {
        self.conditions + self.reads + self.writes + self.copies + self.arithmetic + self.logic + self.returns
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProgramAnalysis {
    /// Lines in the program as written.
    pub source_lines: usize,
    /// Lines after the optimiser (what executes).
    pub lines: usize,
    /// Maximum lines evaluated for a single packet (= `lines`: loop-free,
    /// first executed RETURN wins).
    pub max_lines_per_packet: usize,
    /// Regex patterns compiled for the program.
    pub regexes: usize,
    /// Distinct fields read (e.g. `tcp.payload.len`).
    pub fields: BTreeSet<String>,
    /// Distinct ONNX models referenced.
    pub models: BTreeSet<String>,
    pub connection_registers: RegisterUsage,
    pub host_registers: RegisterUsage,
    /// Bytes of program-visible state per connection (registers only).
    pub per_connection_register_bytes: usize,
    /// Bytes of state per connection including the engine's fixed counters.
    pub per_connection_bytes: usize,
    /// Bytes of program-visible state per host.
    pub per_host_register_bytes: usize,
    /// Worst-case per-packet operation counts.
    pub per_packet: OperationCounts,
    /// True if every path ends in an explicit RETURN (otherwise the engine's
    /// default `allow` applies).
    pub ends_with_unconditional_return: bool,
}

fn count_input(input: &Input, counts: &mut OperationCounts, fields: &mut BTreeSet<String>,
               conn: &mut RegisterUsage, host: &mut RegisterUsage) {
    counts.reads += 1;
    match input {
        Input::Register(reg) => {
            if reg.host { host.insert(reg) } else { conn.insert(reg) }
        }
        Input::Field(field) => {
            fields.insert(format!("{field:?}"));
        }
        Input::ModelOutput(_) | Input::Float(_) | Input::Int(_) | Input::Bool(_) => {}
    }
}

fn count_output(reg: &Register, counts: &mut OperationCounts, conn: &mut RegisterUsage, host: &mut RegisterUsage) {
    counts.writes += 1;
    if reg.host { host.insert(reg) } else { conn.insert(reg) }
}

/// Analyse one line, accumulating into the counters.
fn analyse_line(line: &Line, counts: &mut OperationCounts, fields: &mut BTreeSet<String>,
                models: &mut BTreeSet<String>, conn: &mut RegisterUsage, host: &mut RegisterUsage) {
    if let Some(cond) = &line.condition {
        counts.conditions += 1;
        count_input(&cond.lhs, counts, fields, conn, host);
        count_input(&cond.rhs, counts, fields, conn, host);
    }
    use Operation::*;
    match &line.operation {
        Copy { from, to } => {
            counts.copies += 1;
            count_input(from, counts, fields, conn, host);
            count_output(to, counts, conn, host);
        }
        Add { lhs, rhs, out } | Sub { lhs, rhs, out } | Mul { lhs, rhs, out }
        | Div { lhs, rhs, out } | Mod { lhs, rhs, out } => {
            counts.arithmetic += 1;
            count_input(lhs, counts, fields, conn, host);
            count_input(rhs, counts, fields, conn, host);
            count_output(out, counts, conn, host);
        }
        And { lhs, rhs, out } | Or { lhs, rhs, out } | Xor { lhs, rhs, out } => {
            counts.logic += 1;
            count_input(lhs, counts, fields, conn, host);
            count_input(rhs, counts, fields, conn, host);
            count_output(out, counts, conn, host);
        }
        Regex { out, .. } | RegexSni { out, .. } => {
            counts.regex += 1;
            count_output(out, counts, conn, host);
        }
        CopyToModel { from, name, .. } => {
            counts.model_inputs += 1;
            models.insert(name.clone());
            count_input(from, counts, fields, conn, host);
        }
        Model { name } => {
            counts.model_calls += 1;
            models.insert(name.clone());
        }
        Return(_) => counts.returns += 1,
        Noop => {}
    }
}

impl ProgramAnalysis {
    /// Analyse a program.  `source` is the program text, used only to count the
    /// lines as written (the `Program` has already been optimised).
    pub fn of(program: &Program, source: Option<&str>) -> Self {
        let mut counts = OperationCounts::default();
        let mut fields = BTreeSet::new();
        let mut models = BTreeSet::new();
        let mut conn = RegisterUsage::default();
        let mut host = RegisterUsage::default();
        for line in &program.lines {
            analyse_line(line, &mut counts, &mut fields, &mut models, &mut conn, &mut host);
        }
        let source_lines = source
            .map(|s| {
                s.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("regex "))
                    .count()
            })
            .unwrap_or(program.lines.len());
        let ends_with_unconditional_return = program
            .lines
            .last()
            .map(|l| l.condition.is_none() && matches!(l.operation, Operation::Return(_)))
            .unwrap_or(false);
        let per_connection_register_bytes = conn.bytes();
        ProgramAnalysis {
            source_lines,
            lines: program.lines.len(),
            max_lines_per_packet: program.lines.len(),
            regexes: program.regexes.len(),
            fields,
            models,
            per_connection_register_bytes,
            per_connection_bytes: per_connection_register_bytes + ENGINE_PER_CONNECTION_BYTES,
            per_host_register_bytes: host.bytes(),
            connection_registers: conn,
            host_registers: host,
            per_packet: counts,
            ends_with_unconditional_return,
        }
    }

    /// Human-readable report.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("lines (source / optimised):      {} / {}\n", self.source_lines, self.lines));
        s.push_str(&format!("max lines evaluated per packet:  {}\n", self.max_lines_per_packet));
        s.push_str(&format!("regex patterns:                  {}\n", self.regexes));
        s.push_str(&format!("fields read:                     {}\n",
                            if self.fields.is_empty() { "-".to_string() } else { self.fields.iter().cloned().collect::<Vec<_>>().join(", ") }));
        s.push_str(&format!("models:                          {}\n",
                            if self.models.is_empty() { "-".to_string() } else { self.models.iter().cloned().collect::<Vec<_>>().join(", ") }));
        s.push_str(&format!("connection registers (f/i/b):    {}/{}/{}  = {} B (+{} B engine state = {} B per connection)\n",
                            self.connection_registers.float.len(), self.connection_registers.int.len(),
                            self.connection_registers.bool.len(), self.per_connection_register_bytes,
                            ENGINE_PER_CONNECTION_BYTES, self.per_connection_bytes));
        s.push_str(&format!("host registers (f/i/b):          {}/{}/{}  = {} B per host\n",
                            self.host_registers.float.len(), self.host_registers.int.len(),
                            self.host_registers.bool.len(), self.per_host_register_bytes));
        let p = &self.per_packet;
        s.push_str("per-packet worst case:\n");
        s.push_str(&format!("  conditions {:>3}  reads {:>3}  writes {:>3}  copies {:>3}  arith {:>3}  logic {:>3}  returns {:>3}\n",
                            p.conditions, p.reads, p.writes, p.copies, p.arithmetic, p.logic, p.returns));
        s.push_str(&format!("  constant-time ops {:>3}   regex evaluations {:>2} (× payload length)   model calls {:>2}\n",
                            p.constant_ops(), p.regex, p.model_calls));
        s.push_str(&format!("ends with unconditional RETURN:  {}\n", self.ends_with_unconditional_return));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WU_DETECTOR: &str = r#"
regex "^(\x16\x03|GET )"
regex "^[\x20-\x7e]{6}"
if field:tcp.payload.len == 0: RETURN allow
if field:tcp.payload.len == 517: RETURN allow_all
REGEX 0 -> reg:b.0
if reg:b.0 == True: RETURN allow_all
REGEX 1 -> reg:b.1
if reg:b.1 == True: RETURN allow_all
if field:transport.payload.avg_popcount < 3.4: RETURN allow_all
if field:transport.payload.entropy > 0.375: RETURN terminate
RETURN allow_all
"#;

    #[test]
    fn analysis_of_wu_detector() {
        let prog: Program = WU_DETECTOR.parse().unwrap();
        let a = ProgramAnalysis::of(&prog, Some(WU_DETECTOR));
        assert_eq!(a.source_lines, 9);
        assert_eq!(a.lines, 9);
        assert_eq!(a.max_lines_per_packet, 9);
        assert_eq!(a.regexes, 2);
        // Two boolean connection registers, no host registers
        assert_eq!(a.connection_registers.bool, [0usize, 1].into_iter().collect());
        assert!(a.connection_registers.float.is_empty() && a.connection_registers.int.is_empty());
        assert_eq!(a.per_connection_register_bytes, 2 * BOOL_REGISTER_BYTES);
        assert_eq!(a.per_connection_bytes, 2 + ENGINE_PER_CONNECTION_BYTES);
        assert_eq!(a.per_host_register_bytes, 0);
        assert_eq!(a.per_packet.conditions, 6);
        assert_eq!(a.per_packet.regex, 2);
        assert_eq!(a.per_packet.returns, 7);
        assert_eq!(a.per_packet.writes, 2);
        assert!(a.fields.iter().any(|f| f.contains("Payload") || f.contains("payload")), "{:?}", a.fields);
        assert!(a.ends_with_unconditional_return);
    }

    #[test]
    fn analysis_counts_host_registers_and_arithmetic() {
        let src = "ADD hreg:i.3, 1 -> hreg:i.3\nif hreg:i.3 > 100: RETURN terminate";
        let prog: Program = src.parse().unwrap();
        let a = ProgramAnalysis::of(&prog, Some(src));
        assert_eq!(a.host_registers.int, [3usize].into_iter().collect());
        assert_eq!(a.per_host_register_bytes, INT_REGISTER_BYTES);
        assert_eq!(a.per_connection_register_bytes, 0);
        assert_eq!(a.per_packet.arithmetic, 1);
        assert_eq!(a.per_packet.conditions, 1);
        assert!(!a.ends_with_unconditional_return);
    }
}
