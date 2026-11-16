// Style lints allowed crate-wide so `clippy -D warnings` (the flake's
// `checks.<system>.clippy`) stays useful without a mass rewrite. None of these
// flagged a correctness issue when they were reviewed; revisit individually.
#![allow(
    clippy::too_many_arguments,       // packet/action builders take many header fields
    clippy::upper_case_acronyms,      // DNS record types (AAAA, CNAME, ...) mirror the RFC names
    clippy::module_inception,         // program::program
    clippy::large_enum_variant,       // ExecutionEnvironment; boxing would churn hot paths
    clippy::enum_variant_names,       // nfq IpTables* error variants
    clippy::io_other_error,           // io::Error::new(ErrorKind::Other, ..) call sites
    clippy::needless_range_loop,      // index-based QUIC varint decode
    clippy::while_let_loop,           // signal handler loop
    clippy::vec_init_then_push,       // byte-by-byte wire format builders read clearer as pushes
    clippy::doc_lazy_continuation,    // wire.rs doc lists (file is under active change elsewhere)
    clippy::needless_borrows_for_generic_args, // wire.rs: removing the borrow would move the &mut
)]

pub mod application;
pub mod arp;
pub mod censor;
pub mod config;
pub mod delay;
pub mod expiring_map;
//pub mod epoll;
pub mod ipc;
pub mod model;
pub mod program;
pub mod subnet;
pub mod sys;
pub mod transport;
