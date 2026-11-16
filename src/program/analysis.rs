//! Static analysis of CensorLang programs.
//!
//! CensorLang is loop-free and operates on fixed, typed register banks, so the
//! resources a program can consume are decidable from its text alone:
//!
//! * **Per-connection memory** is reported two ways.  *Touched* is the set of
//!   connection registers the program can ever read or write.  *Allocated* is
//!   what the engine actually holds per connection: three full register banks
//!   of `num_registers` each (float, int, bool), the model input/output
//!   buffers the program fills, and the engine's fixed per-connection state
//!   (`ProgramEnv`: counters, TCP/UDP tracking, bank and map headers).  Host
//!   registers are shared by all connections of a host and are reported
//!   separately, likewise touched and allocated.
//! * **Per-packet work** is bounded by the number of lines: every line runs at
//!   most once per packet and the first executed `RETURN` ends evaluation.  The
//!   bound is reported as a vector of operation counts so that a cost model
//!   (cycles per copy, per arithmetic op, per regex byte, per model call) can be
//!   dotted with it.  Regex evaluations are linear in payload length (the
//!   `regex` crate guarantees linear-time matching), model calls cost whatever
//!   the ONNX graph costs — both are therefore reported as counts.
//!
//! The analysis runs on the *optimised* program, i.e. what the engine executes
//! (the program is checked and optimised exactly as `Program::load` does).

use crate::program::check::{check, ModelSignatures};
use crate::program::config::Config;
use crate::program::env::ProgramEnv;
use crate::program::program::{Input, Line, Operation, Program, ProgramLoadError, Register, RegisterType};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

/// Size in bytes of one register of each type.
pub const FLOAT_REGISTER_BYTES: usize = 8;
pub const INT_REGISTER_BYTES: usize = 8;
pub const BOOL_REGISTER_BYTES: usize = 1;

/// Bytes of one register of each type, i.e. of one index across all three banks.
pub const REGISTER_SET_BYTES: usize = FLOAT_REGISTER_BYTES + INT_REGISTER_BYTES + BOOL_REGISTER_BYTES;

/// Fixed per-connection state the engine keeps for every CensorLang
/// connection regardless of the program: the `ProgramEnv` itself (the
/// `EnvFields` counters, TCP/UDP connection tracking, and the inline headers
/// of the register banks and model I/O maps).  Heap contents (register banks,
/// model buffers) are accounted separately.
pub const ENGINE_PER_CONNECTION_BYTES: usize = size_of::<ProgramEnv>();

/// Heap bytes per entry of a model I/O map besides the values themselves
/// (the key `String` and value `Vec<f64>` headers).
const MODEL_IO_ENTRY_BYTES: usize = size_of::<String>() + size_of::<Vec<f64>>();

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
    /// Subnet membership tests (SRC_IN/DST_IN): one mask-and-compare each.
    pub subnet: usize,
    pub model_inputs: usize,
    pub model_calls: usize,
    pub returns: usize,
}

impl OperationCounts {
    /// Total primitive operations excluding the payload-proportional regex and
    /// model terms (which are reported as counts).
    pub fn constant_ops(&self) -> usize {
        self.conditions + self.reads + self.writes + self.copies + self.arithmetic + self.logic + self.subnet + self.returns
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
    /// Subnets declared for the program.
    pub subnets: usize,
    /// Distinct fields read (e.g. `tcp.payload.len`).
    pub fields: BTreeSet<String>,
    /// Distinct ONNX models referenced.
    pub models: BTreeSet<String>,
    pub connection_registers: RegisterUsage,
    pub host_registers: RegisterUsage,
    /// Registers per bank the engine allocates (`num_registers`).
    pub num_registers: usize,
    /// Bytes of the connection registers the program touches.
    pub per_connection_register_bytes: usize,
    /// Bytes of the connection register banks actually allocated
    /// (`num_registers` × (8 + 8 + 1)), whatever the program touches.
    pub per_connection_allocated_register_bytes: usize,
    /// Bytes of model input/output buffers per connection: inputs up to the
    /// highest index written, outputs up to the highest index read (a lower
    /// bound: the output length is set by the model), plus map entries.
    pub per_connection_model_io_bytes: usize,
    /// Touched registers + model buffers + fixed engine state.
    pub per_connection_touched_bytes: usize,
    /// Allocated register banks + model buffers + fixed engine state: what
    /// the engine holds per connection.
    pub per_connection_bytes: usize,
    /// Bytes of the host registers the program touches.
    pub per_host_register_bytes: usize,
    /// Bytes of the host register banks actually allocated per host.
    pub per_host_allocated_register_bytes: usize,
    /// Worst-case per-packet operation counts.
    pub per_packet: OperationCounts,
    /// True if every path ends in an explicit RETURN (otherwise the engine's
    /// default `allow` applies).
    pub ends_with_unconditional_return: bool,
}

/// Accumulators for one pass over a program.
#[derive(Default)]
struct Acc {
    counts: OperationCounts,
    fields: BTreeSet<String>,
    models: BTreeSet<String>,
    conn: RegisterUsage,
    host: RegisterUsage,
    /// Per model: highest input index written, highest output index read
    model_slots: BTreeMap<String, (Option<usize>, Option<usize>)>,
}

impl Acc {
    fn input(&mut self, input: &Input) {
        self.counts.reads += 1;
        match input {
            Input::Register(reg) => {
                if reg.host { self.host.insert(reg) } else { self.conn.insert(reg) }
            }
            Input::Field(field) => {
                self.fields.insert(field.to_string());
            }
            Input::ModelOutput(slot) => {
                self.models.insert(slot.name.clone());
                let out = &mut self.model_slots.entry(slot.name.clone()).or_default().1;
                *out = Some(out.map_or(slot.index, |i| i.max(slot.index)));
            }
            Input::Float(_) | Input::Int(_) | Input::Bool(_) => {}
        }
    }

    fn output(&mut self, reg: &Register) {
        self.counts.writes += 1;
        if reg.host { self.host.insert(reg) } else { self.conn.insert(reg) }
    }

    /// Analyse one line, accumulating into the counters.
    fn line(&mut self, line: &Line) {
        if let Some(cond) = &line.condition {
            self.counts.conditions += 1;
            self.input(&cond.lhs);
            self.input(&cond.rhs);
        }
        use Operation::*;
        match &line.operation {
            Copy { from, to } => {
                self.counts.copies += 1;
                self.input(from);
                self.output(to);
            }
            Add { lhs, rhs, out } | Sub { lhs, rhs, out } | Mul { lhs, rhs, out }
            | Div { lhs, rhs, out } | Mod { lhs, rhs, out } => {
                self.counts.arithmetic += 1;
                self.input(lhs);
                self.input(rhs);
                self.output(out);
            }
            And { lhs, rhs, out } | Or { lhs, rhs, out } | Xor { lhs, rhs, out } => {
                self.counts.logic += 1;
                self.input(lhs);
                self.input(rhs);
                self.output(out);
            }
            Regex { out, .. } => {
                self.counts.regex += 1;
                self.output(out);
            }
            SubnetIn { out, .. } => {
                self.counts.subnet += 1;
                self.output(out);
            }
            CopyToModel { from, name, index } => {
                self.counts.model_inputs += 1;
                self.models.insert(name.clone());
                let input = &mut self.model_slots.entry(name.clone()).or_default().0;
                *input = Some(input.map_or(*index, |i| i.max(*index)));
                self.input(from);
            }
            Model { name } => {
                self.counts.model_calls += 1;
                self.models.insert(name.clone());
            }
            Return(_) => self.counts.returns += 1,
            Noop => {}
        }
    }

    /// Bytes of model I/O buffers one connection holds
    fn model_io_bytes(&self) -> usize {
        self.model_slots
            .iter()
            .map(|(name, (input, output))| {
                [input, output]
                    .into_iter()
                    .flatten()
                    .map(|max| MODEL_IO_ENTRY_BYTES + name.len() + (max + 1) * FLOAT_REGISTER_BYTES)
                    .sum::<usize>()
            })
            .sum()
    }
}

impl ProgramAnalysis {
    /// Check, optimise and analyse a program exactly as the engine would load
    /// it (see `Program::from_source_checked`).
    pub fn from_source(
        source: &str,
        config: &Config,
        models: Option<&ModelSignatures>,
    ) -> Result<Self, ProgramLoadError> {
        let (program, line_numbers) =
            Program::parse_numbered(source).map_err(ProgramLoadError::Parse)?;
        check(&program, Some(&line_numbers), config, models)?;
        let mut optimised = program.clone();
        optimised.optimise();
        Ok(Self::of(&program, &optimised, usize::from(config.program.num_registers)))
    }

    /// Analyse `optimised` (what executes); `source` is the same program
    /// before optimisation, used for the line count as written.
    pub fn of(source: &Program, optimised: &Program, num_registers: usize) -> Self {
        let mut acc = Acc::default();
        for line in &optimised.lines {
            acc.line(line);
        }
        let ends_with_unconditional_return = optimised
            .lines
            .last()
            .map(|l| l.condition.is_none() && matches!(l.operation, Operation::Return(_)))
            .unwrap_or(false);
        let per_connection_register_bytes = acc.conn.bytes();
        let per_connection_allocated_register_bytes = num_registers * REGISTER_SET_BYTES;
        let per_connection_model_io_bytes = acc.model_io_bytes();
        ProgramAnalysis {
            source_lines: source.lines.len(),
            lines: optimised.lines.len(),
            max_lines_per_packet: optimised.lines.len(),
            regexes: optimised.regexes.len(),
            subnets: optimised.subnets.len(),
            num_registers,
            per_connection_register_bytes,
            per_connection_allocated_register_bytes,
            per_connection_model_io_bytes,
            per_connection_touched_bytes: per_connection_register_bytes
                + per_connection_model_io_bytes
                + ENGINE_PER_CONNECTION_BYTES,
            per_connection_bytes: per_connection_allocated_register_bytes
                + per_connection_model_io_bytes
                + ENGINE_PER_CONNECTION_BYTES,
            per_host_register_bytes: acc.host.bytes(),
            per_host_allocated_register_bytes: num_registers * REGISTER_SET_BYTES,
            connection_registers: acc.conn,
            host_registers: acc.host,
            fields: acc.fields,
            models: acc.models,
            per_packet: acc.counts,
            ends_with_unconditional_return,
        }
    }

    /// Human-readable report.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("lines (source / optimised):      {} / {}\n", self.source_lines, self.lines));
        s.push_str(&format!("max lines evaluated per packet:  {}\n", self.max_lines_per_packet));
        s.push_str(&format!("regex patterns:                  {}\n", self.regexes));
        s.push_str(&format!("subnets:                         {}\n", self.subnets));
        s.push_str(&format!("fields read:                     {}\n",
                            if self.fields.is_empty() { "-".to_string() } else { self.fields.iter().cloned().collect::<Vec<_>>().join(", ") }));
        s.push_str(&format!("models:                          {}\n",
                            if self.models.is_empty() { "-".to_string() } else { self.models.iter().cloned().collect::<Vec<_>>().join(", ") }));
        s.push_str(&format!("connection registers (f/i/b):    {}/{}/{} touched = {} B; {} allocated per bank = {} B\n",
                            self.connection_registers.float.len(), self.connection_registers.int.len(),
                            self.connection_registers.bool.len(), self.per_connection_register_bytes,
                            self.num_registers, self.per_connection_allocated_register_bytes));
        s.push_str(&format!("model I/O buffers:               {} B per connection\n",
                            self.per_connection_model_io_bytes));
        s.push_str(&format!("per connection:                  {} B allocated ({} B touched), incl. {} B engine state\n",
                            self.per_connection_bytes, self.per_connection_touched_bytes,
                            ENGINE_PER_CONNECTION_BYTES));
        s.push_str(&format!("host registers (f/i/b):          {}/{}/{} touched = {} B; {} B allocated per host\n",
                            self.host_registers.float.len(), self.host_registers.int.len(),
                            self.host_registers.bool.len(), self.per_host_register_bytes,
                            self.per_host_allocated_register_bytes));
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

    fn analyse(src: &str) -> ProgramAnalysis {
        ProgramAnalysis::from_source(src, &Config::default(), None).unwrap()
    }

    #[test]
    fn analysis_of_wu_detector() {
        let a = analyse(WU_DETECTOR);
        assert_eq!(a.source_lines, 9);
        assert_eq!(a.lines, 9);
        assert_eq!(a.max_lines_per_packet, 9);
        assert_eq!(a.regexes, 2);
        // Two boolean connection registers, no host registers
        assert_eq!(a.connection_registers.bool, [0usize, 1].into_iter().collect());
        assert!(a.connection_registers.float.is_empty() && a.connection_registers.int.is_empty());
        assert_eq!(a.per_connection_register_bytes, 2 * BOOL_REGISTER_BYTES);
        assert_eq!(a.per_connection_touched_bytes, 2 + ENGINE_PER_CONNECTION_BYTES);
        // The engine allocates all three banks in full (16 registers each)
        assert_eq!(a.per_connection_allocated_register_bytes, 16 * (8 + 8 + 1));
        assert_eq!(a.per_connection_bytes, 16 * 17 + ENGINE_PER_CONNECTION_BYTES);
        assert_eq!(a.per_host_register_bytes, 0);
        assert_eq!(a.per_host_allocated_register_bytes, 16 * 17);
        assert_eq!(a.per_packet.conditions, 6);
        assert_eq!(a.per_packet.regex, 2);
        assert_eq!(a.per_packet.returns, 7);
        assert_eq!(a.per_packet.writes, 2);
        // Field names are as written in CensorLang
        assert_eq!(
            a.fields.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["tcp.payload.len", "transport.payload.avg_popcount", "transport.payload.entropy"]
        );
        assert!(a.ends_with_unconditional_return);
    }

    #[test]
    fn analysis_reports_source_and_optimised_lines() {
        // NOOP is stripped, the constant ADD is folded, the dead write to
        // reg:i.1 is removed and nothing after the unconditional RETURN runs
        let a = analyse("NOOP\nADD 2, 3 -> reg:i.0\nCOPY 1 -> reg:i.1\nif reg:i.0 == 5: RETURN terminate\nRETURN allow\nRETURN reset");
        assert_eq!(a.source_lines, 6);
        assert_eq!(a.lines, 3);
        assert_eq!(a.per_packet.arithmetic, 0);
        assert_eq!(a.per_packet.copies, 1);
    }

    #[test]
    fn analysis_counts_model_buffers() {
        let a = analyse("COPY 1 -> model:m:in:9\nMODEL m\nCOPY model:m:out:1 -> reg:f.0\nif reg:f.0 > 0.5: RETURN terminate");
        let entry = MODEL_IO_ENTRY_BYTES + 1;
        assert_eq!(a.per_connection_model_io_bytes, (entry + 10 * 8) + (entry + 2 * 8));
        assert_eq!(
            a.per_connection_bytes,
            16 * 17 + a.per_connection_model_io_bytes + ENGINE_PER_CONNECTION_BYTES
        );
    }

    #[test]
    fn analysis_rejects_programs_the_engine_rejects() {
        assert!(ProgramAnalysis::from_source("DIV 1, 2 -> reg:f.0", &Config::default(), None).is_err());
    }

    #[test]
    fn analysis_counts_subnet_tests() {
        let src = "subnet \"10.0.0.0/8\"\nsubnet \"2001:db8::/32\"\nDST_IN 0 -> reg:b.0\nif reg:b.0 == True: RETURN terminate\nSRC_IN 1 -> reg:b.1\nif reg:b.1 == True: RETURN terminate";
        let a = analyse(src);
        assert_eq!(a.source_lines, 4);
        assert_eq!(a.subnets, 2);
        assert_eq!(a.per_packet.subnet, 2);
        assert_eq!(a.per_packet.writes, 2);
        assert!(a.report().contains("subnets:"));
    }

    #[test]
    fn analysis_counts_host_registers_and_arithmetic() {
        let src = "ADD hreg:i.3, 1 -> hreg:i.3\nif hreg:i.3 > 100: RETURN terminate";
        let a = analyse(src);
        assert_eq!(a.host_registers.int, [3usize].into_iter().collect());
        assert_eq!(a.per_host_register_bytes, INT_REGISTER_BYTES);
        assert_eq!(a.per_connection_register_bytes, 0);
        assert_eq!(a.per_packet.arithmetic, 1);
        assert_eq!(a.per_packet.conditions, 1);
        assert!(!a.ends_with_unconditional_return);
    }
}
