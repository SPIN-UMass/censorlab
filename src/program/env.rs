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
    fn process(
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

/// Used to measure a baseline
struct ConnectionStats {
    was_terminated: bool,
    last_packet: u32,
    total_packets: u32,
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
