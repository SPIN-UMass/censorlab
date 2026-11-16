use std::path::Path;

/// Builds a legacy PCAP file (libpcap format).
///
/// File layout:
///   - 24-byte global header
///   - Per-packet: 16-byte record header + frame bytes
pub struct PcapBuilder {
    /// (capture timestamp in seconds, frame bytes)
    frames: Vec<(u32, Vec<u8>)>,
}

impl PcapBuilder {
    pub fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Append a raw Ethernet frame to the capture, timestamped one second
    /// after the previous frame (the first frame is at t=0).
    pub fn add_frame(self, frame: &[u8]) -> Self {
        let ts_sec = self.frames.last().map(|(ts, _)| ts + 1).unwrap_or(0);
        self.add_frame_at(ts_sec, frame)
    }

    /// Append a raw Ethernet frame with an explicit capture timestamp (seconds).
    #[allow(dead_code)]
    pub fn add_frame_at(mut self, ts_sec: u32, frame: &[u8]) -> Self {
        self.frames.push((ts_sec, frame.to_vec()));
        self
    }

    /// Write the PCAP file to disk.
    pub fn write_to(&self, path: &Path) {
        let mut buf: Vec<u8> = Vec::new();

        // Global header (24 bytes)
        buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
        buf.extend_from_slice(&2u16.to_le_bytes()); // version major
        buf.extend_from_slice(&4u16.to_le_bytes()); // version minor
        buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes()); // network (LINKTYPE_ETHERNET)

        // Packet records
        for (ts_sec, frame) in self.frames.iter() {
            let ts_sec = *ts_sec;
            let ts_usec = 0u32;
            let incl_len = frame.len() as u32;
            let orig_len = frame.len() as u32;

            buf.extend_from_slice(&ts_sec.to_le_bytes());
            buf.extend_from_slice(&ts_usec.to_le_bytes());
            buf.extend_from_slice(&incl_len.to_le_bytes());
            buf.extend_from_slice(&orig_len.to_le_bytes());
            buf.extend_from_slice(frame);
        }

        std::fs::write(path, buf).expect("failed to write pcap file");
    }
}
