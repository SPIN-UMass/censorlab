//! Per-connection reassembly of a TCP client's TLS ClientHello.
//!
//! Only the *handshake prefix* of the client→server byte stream is
//! reassembled, and only until the ClientHello has been recognised (or
//! recognition has failed).  Afterwards the tracker holds no buffers; it keeps
//! only the recognised ClientHello, which is reported on the completing packet
//! and every later packet of the connection.
//!
//! # Stream model
//! * The client is the sender of a SYN without ACK (or the receiver of a
//!   SYN-ACK).  If no handshake was observed, the sender of the first
//!   payload-carrying segment is taken as the client, unless that segment is
//!   known to come from the WAN side.
//! * The initial sequence number is ISN+1 from the SYN (or the SYN-ACK's
//!   acknowledgement number); failing that, the sequence number of the first
//!   data segment.  All offsets use wrapping [`TcpSeqNumber`] arithmetic.
//! * Bytes are placed at their stream offset in a window of
//!   [`STREAM_WINDOW`] bytes.  Segments may arrive in any order; bytes beyond
//!   the window are discarded.  Contiguous bytes from offset 0 are fed to the
//!   streaming record-layer recogniser
//!   ([`ClientHelloDefragmenter`]).  If the window is filled without a complete
//!   ClientHello, recognition fails with [`TlsParseError::BufferLimit`]; a
//!   ClientHello whose declared length cannot fit the window fails early with
//!   [`TlsParseError::TooLarge`].
//!
//! # Overlaps
//! A retransmission whose overlapping bytes are identical to those already
//! held is accepted.  If a segment overlaps held bytes with *different*
//! content, the stream is ambiguous: a receiver might keep either copy
//! (first-wins vs last-wins is OS-specific), so no ClientHello is reported
//! and the status becomes [`HelloStatus::Ambiguous`] — the censor program
//! decides what to do with that.  Overlaps are only detected while the
//! ClientHello is still being reassembled; conflicting retransmissions after
//! it has been recognised are not examined.
use super::tls::{ClientHelloDefragmenter, ClientHelloInfo, DefragStep, TlsParseError};
use crate::program::packet::{Packet, TransportMetadataExtra};
use smoltcp::wire::{IpAddress, TcpSeqNumber};
use std::sync::Arc;

/// Maximum number of client stream bytes buffered while looking for a
/// ClientHello.  Covers the largest hellos seen in practice (post-quantum
/// key shares push Chrome's to ~1.8 KiB; large PSK tickets a few KiB more).
pub const STREAM_WINDOW: usize = 16 * 1024;

/// Reassembly status of a connection's ClientHello.
///
/// The numeric codes are exposed to CensorLang as `tls.hello.state`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HelloStatus {
    /// No client payload seen yet (or not a TCP connection).
    #[default]
    Idle = 0,
    /// Client bytes buffered; the ClientHello is not yet complete.
    Pending = 1,
    /// The ClientHello has been recognised.
    Complete = 2,
    /// The client's first flight is not a valid ClientHello.
    Failed = 3,
    /// Conflicting overlapping TCP data was seen during reassembly.
    Ambiguous = 4,
}
impl HelloStatus {
    pub fn code(self) -> i64 {
        self as i64
    }
    pub fn name(self) -> &'static str {
        match self {
            HelloStatus::Idle => "idle",
            HelloStatus::Pending => "pending",
            HelloStatus::Complete => "complete",
            HelloStatus::Failed => "failed",
            HelloStatus::Ambiguous => "ambiguous",
        }
    }
}

/// What the tracker reports for one packet.
#[derive(Clone, Debug, Default)]
pub struct TlsHelloObservation {
    /// Status after processing this packet.
    pub status: HelloStatus,
    /// The ClientHello, present on the packet that completed it and on every
    /// later packet of the connection.
    pub hello: Option<Arc<ClientHelloInfo>>,
    /// Why recognition failed, when `status` is `Failed`.
    pub error: Option<TlsParseError>,
}

type Endpoint = (IpAddress, u16);

/// One TCP segment as seen by the tracker.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub seq: TcpSeqNumber,
    pub ack_number: TcpSeqNumber,
    pub syn: bool,
    pub ack: bool,
    /// True if the packet is known to come from the WAN (server) side.
    pub from_wan: bool,
    pub payload: &'a [u8],
}

#[derive(Debug)]
enum Phase {
    /// No client data buffered yet.
    Await {
        client: Option<Endpoint>,
        base: Option<TcpSeqNumber>,
    },
    Buffering(Box<Buffer>),
    /// Terminal: the ClientHello was recognised.
    Complete(Arc<ClientHelloInfo>),
    /// Terminal: the client's first flight is not a valid ClientHello.
    Failed(TlsParseError),
    /// Terminal: conflicting overlapping data was seen.
    Ambiguous,
}

#[derive(Debug)]
struct Buffer {
    client: Endpoint,
    /// Sequence number of stream offset 0.
    base: TcpSeqNumber,
    /// Stream bytes by offset (valid where `have` is set).
    data: Vec<u8>,
    have: Vec<bool>,
    /// Number of contiguous bytes already fed to the recogniser.
    fed: usize,
    /// Segments that contributed new bytes.
    segments: usize,
    defrag: ClientHelloDefragmenter,
}

/// Tracks one connection's client ClientHello.
#[derive(Debug)]
pub struct ClientHelloTracker {
    phase: Phase,
}

impl Default for ClientHelloTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHelloTracker {
    pub fn new() -> Self {
        Self {
            phase: Phase::Await {
                client: None,
                base: None,
            },
        }
    }

    /// Feed a parsed packet; non-TCP packets yield an idle observation.
    pub fn observe_packet(&mut self, packet: &Packet) -> TlsHelloObservation {
        let TransportMetadataExtra::Tcp(tcp) = packet.transport.extra else {
            return TlsHelloObservation::default();
        };
        self.observe(Segment {
            src: (packet.ip.src(), packet.transport.src),
            dst: (packet.ip.dst(), packet.transport.dst),
            seq: tcp.seq,
            ack_number: tcp.ack,
            syn: tcp.flags.syn,
            ack: tcp.flags.ack,
            from_wan: packet.direction < 0,
            payload: &packet.payload,
        })
    }

    /// Feed one TCP segment.
    pub fn observe(&mut self, seg: Segment<'_>) -> TlsHelloObservation {
        let phase = std::mem::replace(&mut self.phase, Phase::Ambiguous);
        self.phase = step(phase, &seg);
        self.observation()
    }

    /// The current state as reported on a packet.
    pub fn observation(&self) -> TlsHelloObservation {
        let status = |status| TlsHelloObservation {
            status,
            ..Default::default()
        };
        match &self.phase {
            Phase::Await { .. } => status(HelloStatus::Idle),
            Phase::Buffering(_) => status(HelloStatus::Pending),
            Phase::Complete(hello) => TlsHelloObservation {
                status: HelloStatus::Complete,
                hello: Some(Arc::clone(hello)),
                error: None,
            },
            Phase::Failed(error) => TlsHelloObservation {
                status: HelloStatus::Failed,
                hello: None,
                error: Some(error.clone()),
            },
            Phase::Ambiguous => status(HelloStatus::Ambiguous),
        }
    }
}

fn step(phase: Phase, seg: &Segment<'_>) -> Phase {
    // Sequence number of the first payload byte (SYN occupies one).
    let data_seq = if seg.syn { seg.seq + 1 } else { seg.seq };
    match phase {
        Phase::Await { mut client, mut base } => {
            if seg.syn && !seg.ack && client.map_or(true, |c| c == seg.src) {
                client = Some(seg.src);
                base = Some(data_seq);
            } else if seg.syn && seg.ack && client.map_or(true, |c| c == seg.dst) {
                client = Some(seg.dst);
                base = Some(seg.ack_number);
            }
            if seg.payload.is_empty() {
                return Phase::Await { client, base };
            }
            let client = match client {
                Some(c) if c == seg.src => c,
                Some(_) => return Phase::Await { client, base },
                None if seg.from_wan => return Phase::Await { client, base },
                None => seg.src,
            };
            let buffer = Box::new(Buffer {
                client,
                base: base.unwrap_or(data_seq),
                data: Vec::new(),
                have: Vec::new(),
                fed: 0,
                segments: 0,
                defrag: ClientHelloDefragmenter::new(STREAM_WINDOW),
            });
            insert(buffer, data_seq, seg.payload)
        }
        Phase::Buffering(buffer) => {
            if seg.src != buffer.client || seg.payload.is_empty() {
                Phase::Buffering(buffer)
            } else {
                insert(buffer, data_seq, seg.payload)
            }
        }
        finished @ (Phase::Complete(_) | Phase::Failed(_) | Phase::Ambiguous) => finished,
    }
}

/// Place `payload` (starting at `seq`) into the window and feed any newly
/// contiguous bytes to the recogniser.
fn insert(
    mut buf: Box<Buffer>,
    seq: TcpSeqNumber,
    payload: &[u8],
) -> Phase {
    // Offset of the payload relative to the stream start, trimming any
    // bytes that precede it.
    let (offset, bytes) = if seq >= buf.base {
        (seq - buf.base, payload)
    } else {
        let skip = buf.base - seq;
        if skip >= payload.len() {
            return Phase::Buffering(buf);
        }
        (0, &payload[skip..])
    };
    if offset >= STREAM_WINDOW {
        return Phase::Buffering(buf);
    }
    let end = (offset + bytes.len()).min(STREAM_WINDOW);
    let bytes = &bytes[..end - offset];

    // Reject conflicting overlaps before modifying anything.
    let held_end = end.min(buf.have.len());
    for pos in offset..held_end {
        if buf.have[pos] && buf.data[pos] != bytes[pos - offset] {
            return Phase::Ambiguous;
        }
    }
    if buf.data.len() < end {
        buf.data.resize(end, 0);
        buf.have.resize(end, false);
    }
    let mut new_bytes = false;
    for (pos, &b) in (offset..end).zip(bytes) {
        if !buf.have[pos] {
            buf.have[pos] = true;
            buf.data[pos] = b;
            new_bytes = true;
        }
    }
    if new_bytes {
        buf.segments += 1;
    }

    let contiguous = buf.fed + buf.have[buf.fed..].iter().take_while(|h| **h).count();
    if contiguous == buf.fed {
        return Phase::Buffering(buf);
    }
    let Buffer {
        client,
        base,
        data,
        have,
        fed,
        segments,
        defrag,
    } = *buf;
    match defrag.push(&data[fed..contiguous]) {
        DefragStep::Done(Ok(mut info)) => {
            info.tcp_segments = segments;
            Phase::Complete(Arc::new(info))
        }
        DefragStep::Done(Err(e)) => Phase::Failed(e),
        DefragStep::NeedMore(_) if contiguous >= STREAM_WINDOW => {
            Phase::Failed(TlsParseError::BufferLimit)
        }
        DefragStep::NeedMore(defrag) => Phase::Buffering(Box::new(Buffer {
            client,
            base,
            data,
            have,
            fed: contiguous,
            segments,
            defrag,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::Ipv4Address;

    const CLIENT: Endpoint = (IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)), 40000);
    const SERVER: Endpoint = (IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 443);

    /// A ClientHello handshake message with an SNI, ALPN "h2" and `pad` bytes
    /// of padding extension.
    fn hello_msg(sni: &str, pad: usize) -> Vec<u8> {
        let mut exts = Vec::new();
        let name = sni.as_bytes();
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        exts.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        exts.push(0);
        exts.extend_from_slice(&(name.len() as u16).to_be_bytes());
        exts.extend_from_slice(name);
        exts.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        exts.extend_from_slice(&[0x00, 0x15]);
        exts.extend_from_slice(&(pad as u16).to_be_bytes());
        exts.extend(std::iter::repeat(0).take(pad));
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&[0, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![0x01];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Wrap `msg` in records of at most `frag` bytes each.
    fn records(msg: &[u8], frag: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in msg.chunks(frag) {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    fn client_seg(seq: u32, payload: &[u8]) -> Segment<'_> {
        Segment {
            src: CLIENT,
            dst: SERVER,
            seq: TcpSeqNumber(seq as i32),
            ack_number: TcpSeqNumber(0),
            syn: false,
            ack: true,
            from_wan: false,
            payload,
        }
    }

    fn syn(isn: u32) -> Segment<'static> {
        Segment {
            syn: true,
            ack: false,
            ..client_seg(isn, &[])
        }
    }

    /// Track a connection that starts with a SYN at `isn`.
    fn tracker_with_syn(isn: u32) -> ClientHelloTracker {
        let mut t = ClientHelloTracker::new();
        assert_eq!(t.observe(syn(isn)).status, HelloStatus::Idle);
        t
    }

    #[test]
    fn single_segment_hello() {
        let stream = records(&hello_msg("one.example", 0), 1 << 14);
        let mut t = tracker_with_syn(1000);
        let obs = t.observe(client_seg(1001, &stream));
        assert_eq!(obs.status, HelloStatus::Complete);
        let hello = obs.hello.unwrap();
        assert_eq!(hello.sni_str(), Some("one.example"));
        assert_eq!(hello.tcp_segments, 1);
        assert!(!hello.reassembled());
        // Later packets (either direction) keep reporting the same hello.
        let obs = t.observe(client_seg(1001 + stream.len() as u32, b"\x17\x03\x03\x00\x01x"));
        assert_eq!(obs.status, HelloStatus::Complete);
        assert!(Arc::ptr_eq(&obs.hello.unwrap(), &hello));
        let server = Segment {
            src: SERVER,
            dst: CLIENT,
            from_wan: true,
            ..client_seg(5000, b"\x16\x03\x03\x00\x01\x02")
        };
        assert_eq!(t.observe(server).hello.unwrap().sni_str(), Some("one.example"));
    }

    #[test]
    fn data_on_syn() {
        // TCP Fast Open: the ClientHello rides on the SYN.
        let stream = records(&hello_msg("tfo.example", 0), 1 << 14);
        let mut t = ClientHelloTracker::new();
        let obs = t.observe(Segment {
            syn: true,
            ack: false,
            ..client_seg(1000, &stream)
        });
        assert_eq!(obs.hello.unwrap().sni_str(), Some("tfo.example"));
    }

    #[test]
    fn one_byte_segments() {
        let stream = records(&hello_msg("tiny.example", 0), 1 << 14);
        let mut t = tracker_with_syn(1000);
        let mut obs = TlsHelloObservation::default();
        for (i, b) in stream.iter().enumerate() {
            obs = t.observe(client_seg(1001 + i as u32, std::slice::from_ref(b)));
            assert_eq!(obs.status == HelloStatus::Complete, i == stream.len() - 1);
        }
        assert_eq!(obs.hello.unwrap().tcp_segments, stream.len());
    }

    #[test]
    fn later_syn_ignored() {
        let stream = records(&hello_msg("resyn.example", 0), 1 << 14);
        let mut t = tracker_with_syn(1000);
        t.observe(client_seg(1001, &stream[..20]));
        t.observe(syn(9999));
        let obs = t.observe(client_seg(1021, &stream[20..]));
        assert_eq!(obs.hello.unwrap().sni_str(), Some("resyn.example"));
    }

    #[test]
    fn hello_split_across_two_segments() {
        // A post-quantum-sized hello (~1.8 KiB) exceeding one 1460-byte MSS.
        let stream = records(&hello_msg("pq.example", 1700), 1 << 14);
        assert!(stream.len() > 1460);
        let mut t = tracker_with_syn(5000);
        let obs = t.observe(client_seg(5001, &stream[..1460]));
        assert_eq!(obs.status, HelloStatus::Pending);
        assert!(obs.hello.is_none());
        let obs = t.observe(client_seg(5001 + 1460, &stream[1460..]));
        assert_eq!(obs.status, HelloStatus::Complete);
        let hello = obs.hello.unwrap();
        assert_eq!(hello.sni_str(), Some("pq.example"));
        assert_eq!(hello.alpn, vec![b"h2".to_vec()]);
        assert_eq!(hello.tcp_segments, 2);
        assert!(hello.reassembled());
    }

    #[test]
    fn hello_split_across_three_segments() {
        let stream = records(&hello_msg("three.example", 0), 1 << 14);
        let mut t = tracker_with_syn(0);
        // Cut inside the record header and inside the SNI.
        let cuts = [3, 60, stream.len()];
        let mut prev = 0;
        let mut last = None;
        for c in cuts {
            last = Some(t.observe(client_seg(1 + prev as u32, &stream[prev..c])));
            prev = c;
        }
        let obs = last.unwrap();
        assert_eq!(obs.status, HelloStatus::Complete);
        assert_eq!(obs.hello.unwrap().tcp_segments, 3);
    }

    #[test]
    fn hello_split_across_records_and_segments() {
        let stream = records(&hello_msg("records.example", 0), 20);
        let mut t = tracker_with_syn(77);
        assert_eq!(t.observe(client_seg(78, &stream[..30])).status, HelloStatus::Pending);
        let obs = t.observe(client_seg(78 + 30, &stream[30..]));
        let hello = obs.hello.unwrap();
        assert_eq!(hello.sni_str(), Some("records.example"));
        assert!(hello.record_count > 1);
    }

    #[test]
    fn out_of_order_segments() {
        let stream = records(&hello_msg("ooo.example", 0), 1 << 14);
        let mut t = tracker_with_syn(100);
        let obs = t.observe(client_seg(101 + 40, &stream[40..]));
        assert_eq!(obs.status, HelloStatus::Pending);
        let obs = t.observe(client_seg(101, &stream[..40]));
        assert_eq!(obs.status, HelloStatus::Complete);
        let hello = obs.hello.unwrap();
        assert_eq!(hello.sni_str(), Some("ooo.example"));
        assert_eq!(hello.tcp_segments, 2);
    }

    #[test]
    fn identical_retransmission_is_accepted() {
        let stream = records(&hello_msg("rexmit.example", 0), 1 << 14);
        let mut t = tracker_with_syn(100);
        assert_eq!(t.observe(client_seg(101, &stream[..50])).status, HelloStatus::Pending);
        // Exact and partially overlapping retransmissions.
        assert_eq!(t.observe(client_seg(101, &stream[..50])).status, HelloStatus::Pending);
        assert_eq!(t.observe(client_seg(111, &stream[10..30])).status, HelloStatus::Pending);
        let obs = t.observe(client_seg(101 + 20, &stream[20..]));
        assert_eq!(obs.status, HelloStatus::Complete);
        assert_eq!(obs.hello.unwrap().tcp_segments, 2);
    }

    #[test]
    fn conflicting_overlap_is_ambiguous() {
        let stream = records(&hello_msg("blocked.example", 0), 1 << 14);
        let mut forged = stream.clone();
        let pos = forged.windows(7).position(|w| w == b"blocked").unwrap();
        forged[pos..pos + 7].copy_from_slice(b"allowed");
        // Out-of-order tail, then two conflicting copies of the SNI region.
        let mut t = tracker_with_syn(100);
        assert_eq!(
            t.observe(client_seg(101 + 80, &stream[80..])).status,
            HelloStatus::Pending
        );
        let obs = t.observe(client_seg(101 + pos as u32, &forged[pos..80]));
        assert_eq!(obs.status, HelloStatus::Pending);
        let obs = t.observe(client_seg(101, &stream[..80]));
        assert_eq!(obs.status, HelloStatus::Ambiguous);
        assert!(obs.hello.is_none());
        // Stays ambiguous.
        let obs = t.observe(client_seg(101, &stream));
        assert_eq!(obs.status, HelloStatus::Ambiguous);
        assert!(obs.hello.is_none());
    }

    #[test]
    fn declared_length_beyond_window_fails_early() {
        let stream = records(&hello_msg("huge.example", 0), 1 << 14);
        let mut patched = stream.clone();
        // Declare a 20000-byte body in the handshake header.
        patched[6..9].copy_from_slice(&20000u32.to_be_bytes()[1..]);
        let mut t = tracker_with_syn(1);
        let obs = t.observe(client_seg(2, &patched[..20]));
        assert_eq!(obs.status, HelloStatus::Failed);
        assert_eq!(obs.error, Some(TlsParseError::TooLarge(20000)));
    }

    #[test]
    fn buffer_limit_reached() {
        // A ~4 KiB hello in one-byte records occupies ~24 KiB of stream.
        let stream = records(&hello_msg("tiny.records", 4000), 1);
        assert!(stream.len() > STREAM_WINDOW);
        let mut t = tracker_with_syn(1);
        let mut obs = TlsHelloObservation::default();
        for (i, chunk) in stream.chunks(1400).enumerate() {
            obs = t.observe(client_seg(2 + (i * 1400) as u32, chunk));
            if obs.status != HelloStatus::Pending {
                break;
            }
        }
        assert_eq!(obs.status, HelloStatus::Failed);
        assert_eq!(obs.error, Some(TlsParseError::BufferLimit));
    }

    #[test]
    fn sequence_number_wraparound() {
        let stream = records(&hello_msg("wrap.example", 0), 1 << 14);
        let isn = u32::MAX - 20;
        let mut t = tracker_with_syn(isn);
        let first = isn.wrapping_add(1);
        let second = first.wrapping_add(40); // wraps past zero
        assert!(second < first);
        assert_eq!(t.observe(client_seg(second, &stream[40..])).status, HelloStatus::Pending);
        let obs = t.observe(client_seg(first, &stream[..40]));
        assert_eq!(obs.status, HelloStatus::Complete);
        assert_eq!(obs.hello.unwrap().sni_str(), Some("wrap.example"));
    }

    #[test]
    fn midstream_pickup_without_syn() {
        let stream = records(&hello_msg("mid.example", 0), 1 << 14);
        let mut t = ClientHelloTracker::new();
        assert_eq!(t.observe(client_seg(9000, &stream[..10])).status, HelloStatus::Pending);
        let obs = t.observe(client_seg(9010, &stream[10..]));
        assert_eq!(obs.hello.unwrap().sni_str(), Some("mid.example"));
    }

    #[test]
    fn server_data_is_ignored() {
        let stream = records(&hello_msg("srv.example", 0), 1 << 14);
        let mut t = tracker_with_syn(10);
        let server = Segment {
            src: SERVER,
            dst: CLIENT,
            seq: TcpSeqNumber(555),
            from_wan: true,
            ..client_seg(0, b"\x16\x03\x03\x00\x01\x02")
        };
        assert_eq!(t.observe(server).status, HelloStatus::Idle);
        let obs = t.observe(client_seg(11, &stream));
        assert_eq!(obs.status, HelloStatus::Complete);
    }

    #[test]
    fn syn_ack_establishes_client_and_isn() {
        let stream = records(&hello_msg("synack.example", 0), 1 << 14);
        let mut t = ClientHelloTracker::new();
        let synack = Segment {
            src: SERVER,
            dst: CLIENT,
            seq: TcpSeqNumber(4242),
            ack_number: TcpSeqNumber(301),
            syn: true,
            ack: true,
            from_wan: true,
            payload: &[],
        };
        t.observe(synack);
        // Second segment first; the base comes from the SYN-ACK's ack number.
        assert_eq!(t.observe(client_seg(311, &stream[10..])).status, HelloStatus::Pending);
        assert_eq!(t.observe(client_seg(301, &stream[..10])).status, HelloStatus::Complete);
    }

    #[test]
    fn non_tls_stream_fails() {
        let mut t = tracker_with_syn(10);
        let obs = t.observe(client_seg(11, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert_eq!(obs.status, HelloStatus::Failed);
        assert_eq!(obs.error, Some(TlsParseError::NotHandshake(b'G')));
    }

    #[test]
    fn bytes_before_stream_start_are_trimmed() {
        let stream = records(&hello_msg("trim.example", 0), 1 << 14);
        let mut t = tracker_with_syn(1000);
        // Segment claims to start 3 bytes before ISN+1; those bytes are dropped.
        let mut payload = b"XYZ".to_vec();
        payload.extend_from_slice(&stream);
        let obs = t.observe(client_seg(998, &payload));
        assert_eq!(obs.hello.unwrap().sni_str(), Some("trim.example"));
    }
}
