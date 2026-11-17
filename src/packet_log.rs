//! Log events attributed to the packet being processed.
//!
//! Every log event emitted while a packet is processed past the IP layer (by
//! the engine, a CensorLang program or a Python script) is wrapped in an
//! `ip{direction=.. src=.. dst=..}` span naming the packet. Creating that span
//! for every packet is expensive, since the log formatter renders its fields
//! as soon as it is created, while almost no packet logs anything. So the
//! span is only created when an event is actually emitted: [`enter`] records
//! the packet in a thread-local, and the [`debug!`], [`info!`], [`warn!`] and
//! [`error!`] macros of this module emit their event inside the span while a
//! packet is recorded, and as a plain event otherwise.
//!
//! Code that can run while a packet is processed must log through these
//! macros instead of `tracing`'s for its events to carry the span.
use crate::censor::{Direction, IpPair};
use std::cell::Cell;

#[derive(Clone, Copy)]
struct PacketContext {
    direction: Direction,
    ips: IpPair,
}

thread_local! {
    static CURRENT: Cell<Option<PacketContext>> = const { Cell::new(None) };
}

/// Restores the previously recorded packet (if any) when dropped
#[must_use = "the packet is only recorded until the guard is dropped"]
pub struct PacketGuard {
    previous: Option<PacketContext>,
}
impl Drop for PacketGuard {
    fn drop(&mut self) {
        CURRENT.set(self.previous);
    }
}

/// Attribute log events on this thread to the packet `ips` travelling in
/// `direction` until the returned guard is dropped.
pub fn enter(direction: Direction, ips: IpPair) -> PacketGuard {
    PacketGuard {
        previous: CURRENT.replace(Some(PacketContext { direction, ips })),
    }
}

/// Run `emit` (which emits one event) inside the current packet's span, if a
/// packet is being processed on this thread.
#[doc(hidden)]
pub fn in_packet_span<R>(emit: impl FnOnce() -> R) -> R {
    match CURRENT.get() {
        Some(PacketContext { direction, ips }) => tracing::info_span!(
            target: "censorlab::censor",
            "ip",
            direction = tracing::field::display(direction),
            src = tracing::field::display(ips.src()),
            dst = tracing::field::display(ips.dst())
        )
        .in_scope(emit),
        None => emit(),
    }
}

/// Emit an event at `$level`, inside the current packet's span if there is one
#[doc(hidden)]
#[macro_export]
macro_rules! __packet_event {
    ($level:expr, $($arg:tt)+) => {
        // Only build the span for events that will be recorded
        if ::tracing::enabled!($level) {
            $crate::packet_log::in_packet_span(|| ::tracing::event!($level, $($arg)+))
        }
    };
}

/// `tracing::debug!`, inside the current packet's span (see the module docs)
macro_rules! packet_debug {
    ($($arg:tt)+) => { $crate::__packet_event!(::tracing::Level::DEBUG, $($arg)+) };
}
/// `tracing::info!`, inside the current packet's span (see the module docs)
macro_rules! packet_info {
    ($($arg:tt)+) => { $crate::__packet_event!(::tracing::Level::INFO, $($arg)+) };
}
/// `tracing::warn!`, inside the current packet's span (see the module docs)
macro_rules! packet_warn {
    ($($arg:tt)+) => { $crate::__packet_event!(::tracing::Level::WARN, $($arg)+) };
}
/// `tracing::error!`, inside the current packet's span (see the module docs)
macro_rules! packet_error {
    ($($arg:tt)+) => { $crate::__packet_event!(::tracing::Level::ERROR, $($arg)+) };
}
// Renamed on export: a macro_rules `warn` would clash with the `#[warn]` attribute
pub(crate) use {
    packet_debug as debug, packet_error as error, packet_info as info, packet_warn as warn,
};

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::Ipv4Address;

    fn ips() -> IpPair {
        IpPair::V4 {
            src: Ipv4Address::new(10, 0, 0, 1),
            dst: Ipv4Address::new(10, 0, 0, 2),
        }
    }

    fn recorded() -> Option<(Direction, IpPair)> {
        CURRENT.get().map(|ctx| (ctx.direction, ctx.ips))
    }

    #[test]
    fn guard_restores_previous_packet() {
        assert!(recorded().is_none());
        {
            let _outer = enter(Direction::ClientToWan, ips());
            {
                let _inner = enter(Direction::WanToClient, ips().swap());
                assert_eq!(recorded(), Some((Direction::WanToClient, ips().swap())));
            }
            assert_eq!(recorded(), Some((Direction::ClientToWan, ips())));
        }
        assert!(recorded().is_none());
    }
}
