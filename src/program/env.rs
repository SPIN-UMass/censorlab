use crate::program::config::Config;
use crate::program::packet::{
    ConnectionIdentifier, Direction, Packet, TransportMetadataExtra, TransportProtocol,
};
use crate::program::program::{Action, Program, Register, RegisterType, Value};

/// Environment that handles a single connection
#[derive(Debug)]
pub struct ProgramEnv {
    registers: Registers,
    fields: EnvFields,
    inner: ProgramEnvInner,
}

impl ProgramEnv {
    pub fn new(id: ConnectionIdentifier, config: &Config) -> Self {
        use TransportProtocol::*;
        let registers = Registers::new(
            config.program.num_registers.into(),
            config.env.relax_register_types,
        );
        let inner = match id.transport_proto {
            Tcp => ProgramEnvInner::Tcp(tcp::ProgramEnv::new(id)),
            Udp => ProgramEnvInner::Udp(udp::ProgramEnv::new(id)),
        };
        ProgramEnv {
            registers,
            fields: EnvFields { num_packets: 0 },
            inner,
        }
    }
    pub fn process(
        &mut self,
        packet: &Packet,
        program: &Program,
        field_default_on_error: bool,
    ) -> Action {
        self.fields.num_packets += 1;
        self.inner.process(
            packet,
            program,
            &mut self.registers,
            &self.fields,
            field_default_on_error,
        )
    }
    /// Check whether the connection has finished (both FIN-ACKs seen for TCP).
    /// Not currently called but retained as part of the connection lifecycle API.
    #[allow(dead_code)]
    fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
    pub fn has_received_first_data_packet(&self) -> bool {
        self.inner.has_received_first_data_packet()
    }
}

#[derive(Debug, Default)]
pub struct Registers {
    /// Register bank of floats
    float: Vec<f64>,
    /// Register bank of ints
    int: Vec<i64>,
    /// Register bank of bools
    bool: Vec<bool>,
    /// Whether to be automatically put values into their proper banks
    relax_register_types: bool,
}
impl Registers {
    /// Constructor
    pub fn new(num_registers: usize, relax_register_types: bool) -> Self {
        Registers {
            float: vec![0.0f64; num_registers],
            int: vec![0i64; num_registers],
            bool: vec![false; num_registers],
            relax_register_types,
        }
    }
    /// Get the value of a register
    pub fn get(&self, register: &Register) -> Option<Value> {
        match register.ty {
            RegisterType::Float => self.float.get(register.index).cloned().map(Value::Float),
            RegisterType::Int => self.int.get(register.index).cloned().map(Value::Int),
            RegisterType::Bool => self.bool.get(register.index).cloned().map(Value::Bool),
        }
    }
    /// Set the value of a register
    pub fn set(&mut self, register: &Register, value: &Value) -> Result<(), RegisterWriteError> {
        match (&register.ty, value, self.relax_register_types) {
            (RegisterType::Float, Value::Float(f), _) | (_, Value::Float(f), true) => self
                .float
                .get_mut(register.index)
                .map(|r| {
                    *r = *f;
                })
                .ok_or(RegisterWriteError::InvalidIndex),
            (RegisterType::Int, Value::Int(i), _) | (_, Value::Int(i), true) => self
                .int
                .get_mut(register.index)
                .map(|r| {
                    *r = *i;
                })
                .ok_or(RegisterWriteError::InvalidIndex),
            (RegisterType::Bool, Value::Bool(b), _) | (_, Value::Bool(b), true) => self
                .bool
                .get_mut(register.index)
                .map(|r| {
                    *r = *b;
                })
                .ok_or(RegisterWriteError::InvalidIndex),
            (_, _, _) => Err(RegisterWriteError::InvalidType),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum RegisterWriteError {
    #[error("Attempted to write a value to a register of the wrong type")]
    InvalidType,
    #[error("Attempted to write a value to an out-of-bounds index")]
    InvalidIndex,
}
#[derive(Debug)]
pub struct EnvFields {
    pub num_packets: u32,
}
#[derive(Debug)]
pub enum ProgramEnvInner {
    Tcp(tcp::ProgramEnv),
    Udp(udp::ProgramEnv),
}
impl ProgramEnvInner {
    fn process(
        &mut self,
        packet: &Packet,
        program: &Program,
        registers: &mut Registers,
        fields: &EnvFields,
        field_default_on_error: bool,
    ) -> Action {
        use ProgramEnvInner::*;
        match self {
            Tcp(env) => env.process(packet, program, registers, fields, field_default_on_error),
            Udp(env) => env.process(packet, program, registers, fields, field_default_on_error),
        }
    }
    /// Check whether the connection has finished (both FIN-ACKs seen for TCP).
    /// Not currently called but retained as part of the connection lifecycle API.
    #[allow(dead_code)]
    fn is_finished(&self) -> bool {
        use ProgramEnvInner::*;
        match self {
            Tcp(env) => env.is_finished(),
            Udp(_) => false,
        }
    }
    pub fn has_received_first_data_packet(&self) -> bool {
        use ProgramEnvInner::*;
        match self {
            Tcp(env) => env.has_received_first_data_packet(),
            Udp(env) => env.has_received_first_data_packet(),
        }
    }
}

mod tcp {
    use super::{
        Action, ConnectionIdentifier, Direction, EnvFields, Packet, Program, Registers,
        TransportMetadataExtra,
    };
    use tracing::{error, warn};
    #[derive(Debug)]
    pub struct ProgramEnv {
        init_id: ConnectionIdentifier,
        pub default_action: Action,
        pub total_processed: u32,
        pub last_fully_processed: u32,
        hidden: Hidden,
    }
    impl ProgramEnv {
        pub fn new(id: ConnectionIdentifier) -> Self {
            ProgramEnv {
                init_id: id,
                default_action: Action::default(),
                total_processed: 0,
                last_fully_processed: 0,
                hidden: Default::default(),
            }
        }
        pub fn process(
            &mut self,
            packet: &Packet,
            program: &Program,
            registers: &mut Registers,
            fields: &EnvFields,
            field_default_on_error: bool,
        ) -> Action {
            self.total_processed += 1;
            match self.default_action {
                Action::AllowAll => Action::Allow,
                Action::TerminateAll => Action::TerminateAll,
                Action::Allow => {
                    if let TransportMetadataExtra::Tcp(_) = packet.transport.extra {
                        // First calculate the direction
                        if let Some(direction) =
                            self.init_id.direction(&packet.connection_identifier())
                        {
                            // Do secret processing
                            self.hidden.process(packet, &direction);
                            // Run the program using the packet
                            match program.run(packet, registers, fields, field_default_on_error) {
                                Ok(Action::Allow) => {}
                                Ok(Action::AllowAll) => {
                                    self.default_action = Action::AllowAll;
                                }
                                Ok(Action::TerminateAll) => {
                                    self.default_action = Action::TerminateAll;
                                }
                                Err(err) => {
                                    error!("Error processing packet through program: {err}");
                                }
                            };
                        } else {
                            warn!("Was unable to find direction for packet");
                        }
                    } else {
                        warn!("Tried to process a non-Tcp packet in a Tcp environment");
                    };
                    self.last_fully_processed += 1;
                    self.default_action
                }
            }
        }
        pub fn is_finished(&self) -> bool {
            self.hidden.is_finished()
        }
        pub fn has_received_first_data_packet(&self) -> bool {
            self.hidden.has_received_first_data_packet
        }
    }
    /// Internal struct used to track things beyond the program program
    #[derive(Default, Debug)]
    struct Hidden {
        fin_ack_from: bool,
        fin_ack_to: bool,
        has_received_first_data_packet: bool,
    }
    impl Hidden {
        pub fn process(&mut self, packet: &Packet, direction: &Direction) {
            if let TransportMetadataExtra::Tcp(ref tcp_metadata) = packet.transport.extra {
                if tcp_metadata.flags.fin && tcp_metadata.flags.ack {
                    match direction {
                        Direction::FromInitiator => self.fin_ack_from = true,
                        Direction::ToInitiator => self.fin_ack_to = true,
                    }
                }
                if !packet.payload.is_empty() {
                    self.has_received_first_data_packet = true;
                }
            }
        }
        fn is_finished(&self) -> bool {
            self.fin_ack_from && self.fin_ack_to
        }
    }
}
mod udp {
    use super::{
        Action, ConnectionIdentifier, EnvFields, Packet, Program, Registers, TransportMetadataExtra,
    };
    use tracing::{error, warn};
    #[derive(Debug)]
    pub struct ProgramEnv {
        init_id: ConnectionIdentifier,
        pub default_action: Action,
        pub total_processed: u32,
        pub last_fully_processed: u32,
        hidden: Hidden,
    }
    impl ProgramEnv {
        pub fn new(id: ConnectionIdentifier) -> Self {
            ProgramEnv {
                init_id: id,
                default_action: Action::default(),
                total_processed: 0,
                last_fully_processed: 0,
                hidden: Default::default(),
            }
        }
        pub fn process(
            &mut self,
            packet: &Packet,
            program: &Program,
            registers: &mut Registers,
            fields: &EnvFields,
            field_default_on_error: bool,
        ) -> Action {
            self.total_processed += 1;
            match self.default_action {
                Action::AllowAll => Action::Allow,
                Action::TerminateAll => Action::TerminateAll,
                Action::Allow => {
                    if let TransportMetadataExtra::Udp(_) = packet.transport.extra {
                        // First calculate the direction
                        if let Some(_direction) =
                            self.init_id.direction(&packet.connection_identifier())
                        {
                            // Do secret processing
                            self.hidden.process(packet);
                            // Run the program using the packet
                            match program.run(packet, registers, fields, field_default_on_error) {
                                Ok(Action::Allow) => {}
                                Ok(Action::AllowAll) => {
                                    self.default_action = Action::AllowAll;
                                }
                                Ok(Action::TerminateAll) => {
                                    self.default_action = Action::TerminateAll;
                                }
                                Err(err) => {
                                    error!("Error processing packet through program: {err}");
                                }
                            };
                        } else {
                            warn!("Was unable to find direction for packet");
                        }
                    } else {
                        warn!("Tried to process a non-Udp packet in a Udp environment");
                    };
                    self.last_fully_processed += 1;
                    self.default_action
                }
            }
        }
        pub fn has_received_first_data_packet(&self) -> bool {
            self.hidden.has_received_first_data_packet
        }
    }
    /// Internal struct used to track things beyond the program program
    #[derive(Default, Debug)]
    struct Hidden {
        has_received_first_data_packet: bool,
    }
    impl Hidden {
        pub fn process(&mut self, packet: &Packet) {
            if !packet.payload.is_empty() {
                self.has_received_first_data_packet = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::program::{Register, RegisterType, Value};

    #[test]
    fn registers_new_initializes_to_defaults() {
        let regs = Registers::new(4, false);
        for i in 0..4 {
            let f = regs.get(&Register { ty: RegisterType::Float, index: i });
            assert!(matches!(f, Some(Value::Float(v)) if v == 0.0));
            let int = regs.get(&Register { ty: RegisterType::Int, index: i });
            assert!(matches!(int, Some(Value::Int(0))));
            let b = regs.get(&Register { ty: RegisterType::Bool, index: i });
            assert!(matches!(b, Some(Value::Bool(false))));
        }
    }

    #[test]
    fn registers_get_set_float() {
        let mut regs = Registers::new(4, false);
        let reg = Register { ty: RegisterType::Float, index: 1 };
        regs.set(&reg, &Value::Float(3.14)).unwrap();
        let val = regs.get(&reg).unwrap();
        assert!(matches!(val, Value::Float(f) if (f - 3.14).abs() < f64::EPSILON));
    }

    #[test]
    fn registers_get_set_int() {
        let mut regs = Registers::new(4, false);
        let reg = Register { ty: RegisterType::Int, index: 2 };
        regs.set(&reg, &Value::Int(42)).unwrap();
        assert!(matches!(regs.get(&reg), Some(Value::Int(42))));
    }

    #[test]
    fn registers_get_set_bool() {
        let mut regs = Registers::new(4, false);
        let reg = Register { ty: RegisterType::Bool, index: 0 };
        regs.set(&reg, &Value::Bool(true)).unwrap();
        assert!(matches!(regs.get(&reg), Some(Value::Bool(true))));
    }

    #[test]
    fn registers_set_wrong_type_strict() {
        let mut regs = Registers::new(4, false);
        let int_reg = Register { ty: RegisterType::Int, index: 0 };
        let result = regs.set(&int_reg, &Value::Float(1.0));
        assert!(matches!(result, Err(RegisterWriteError::InvalidType)));
    }

    #[test]
    fn registers_set_wrong_type_relaxed() {
        let mut regs = Registers::new(4, true);
        let int_reg = Register { ty: RegisterType::Int, index: 0 };
        // With relax_register_types=true, a Float value goes to the float bank
        regs.set(&int_reg, &Value::Float(2.5)).unwrap();
        let float_reg = Register { ty: RegisterType::Float, index: 0 };
        assert!(matches!(regs.get(&float_reg), Some(Value::Float(f)) if (f - 2.5).abs() < f64::EPSILON));
    }

    #[test]
    fn registers_get_out_of_bounds() {
        let regs = Registers::new(2, false);
        let reg = Register { ty: RegisterType::Int, index: 10 };
        assert!(regs.get(&reg).is_none());
    }

    #[test]
    fn registers_set_out_of_bounds() {
        let mut regs = Registers::new(2, false);
        let reg = Register { ty: RegisterType::Int, index: 10 };
        let result = regs.set(&reg, &Value::Int(1));
        assert!(matches!(result, Err(RegisterWriteError::InvalidIndex)));
    }
}

/// Aggregate stats from censorship
#[derive(Debug)]
pub struct AggregateStats {
    pub num_connections_allowed: u32,
    pub num_connections_terminated: u32,
    pub num_packets_unconditionally_allowed: u32,
    pub num_packets_unconditionally_terminated: u32,
    pub total_packets: u32,
}
impl AggregateStats {
    pub fn fitness(&self, is_allowed: bool) -> f64 {
        if is_allowed {
            f64::from(self.num_connections_allowed)
                + f64::from(self.num_packets_unconditionally_allowed)
                    / f64::from(self.total_packets)
        } else {
            f64::from(self.num_connections_terminated)
                + f64::from(self.num_packets_unconditionally_terminated)
                    / f64::from(self.total_packets)
        }
    }
}
