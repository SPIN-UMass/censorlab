//! Buffered decision output for PCAP mode.
//!
//! PCAP mode prints one line per decision. Writing each line with `println!`
//! costs a `write` system call per line (Rust's stdout is line-buffered), which
//! dominates when most packets get a decision. Decision lines are therefore
//! collected here and written in blocks.
//!
//! Everything else on stdout must keep its place relative to the decisions:
//! * log events are written through [`OrderedStdout`], which flushes pending
//!   decisions before each event;
//! * censor scripts may write too (e.g. from `__del__`), so connection
//!   tracking calls [`flush`] before running any Python code;
//! * [`FlushGuard`] flushes whatever is pending when PCAP mode ends, however
//!   it ends.
use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use tracing_subscriber::fmt::MakeWriter;

/// Pending output is written once it reaches this many bytes
const CAPACITY: usize = 64 * 1024;

static PENDING: Mutex<Vec<u8>> = Mutex::new(Vec::new());
/// Whether `PENDING` is non-empty (checked without taking the lock)
static HAS_PENDING: AtomicBool = AtomicBool::new(false);

fn pending() -> MutexGuard<'static, Vec<u8>> {
    // A panic while holding the lock leaves at worst a partial line behind
    PENDING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Queue one line (without its newline) for stdout
pub fn line(args: fmt::Arguments<'_>) -> io::Result<()> {
    let mut pending = pending();
    pending.write_fmt(args)?;
    pending.push(b'\n');
    HAS_PENDING.store(true, Ordering::Relaxed);
    if pending.len() >= CAPACITY {
        write_out(&mut pending)?;
    }
    Ok(())
}

/// Write all queued lines to stdout
pub fn flush() -> io::Result<()> {
    if !HAS_PENDING.load(Ordering::Relaxed) {
        return Ok(());
    }
    write_out(&mut pending())
}

fn write_out(pending: &mut Vec<u8>) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    // Clear even on failure, so a broken stdout fails once, not on every flush
    let result = stdout.write_all(pending).and_then(|()| stdout.flush());
    pending.clear();
    HAS_PENDING.store(false, Ordering::Relaxed);
    result
}

/// Flushes queued lines when dropped
#[must_use = "pending lines are only flushed when the guard is dropped"]
pub struct FlushGuard;
impl Drop for FlushGuard {
    fn drop(&mut self) {
        // Nothing to report the error to while unwinding or returning
        let _ = flush();
    }
}

/// Log writer: stdout, after flushing queued lines so they keep their order
#[derive(Clone, Copy, Debug, Default)]
pub struct OrderedStdout;
impl<'a> MakeWriter<'a> for OrderedStdout {
    type Writer = io::Stdout;
    fn make_writer(&'a self) -> Self::Writer {
        // Write errors are ignored, like tracing ignores those of the log write
        let _ = flush();
        io::stdout()
    }
}
