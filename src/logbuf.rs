//! In-memory log ring buffer for the TUI.
//!
//! In TUI mode stderr is owned by the terminal, so tracing can't write there
//! without corrupting the display. Instead we point the `tracing_subscriber`
//! formatter at a [`MakeLogWriter`], which appends each formatted log line into
//! a bounded shared deque the TUI's log pane renders. This is how the TUI still
//! shows errors, reconnects, and bootstrap progress.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

/// How many recent log lines to retain.
const CAPACITY: usize = 1000;

/// Shared, cheaply-clonable handle to the captured log lines (oldest first).
pub type LogBuffer = Arc<Mutex<VecDeque<String>>>;

/// Create an empty log buffer.
pub fn new_buffer() -> LogBuffer {
    Arc::new(Mutex::new(VecDeque::with_capacity(CAPACITY)))
}

/// `io::Write` sink that splits incoming bytes on newlines and pushes complete
/// lines into the shared buffer, dropping the oldest past [`CAPACITY`].
pub struct LogWriter {
    buf: LogBuffer,
    /// Partial line carried across writes until its terminating newline.
    pending: Vec<u8>,
}

impl io::Write for LogWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for &byte in data {
            if byte == b'\n' {
                let line = String::from_utf8_lossy(&self.pending)
                    .trim_end()
                    .to_string();
                self.pending.clear();
                let mut buf = self.buf.lock().unwrap();
                if buf.len() == CAPACITY {
                    buf.pop_front();
                }
                buf.push_back(line);
            } else {
                self.pending.push(byte);
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `MakeWriter` factory handed to the tracing formatter.
#[derive(Clone)]
pub struct MakeLogWriter {
    buf: LogBuffer,
}

impl MakeLogWriter {
    pub fn new(buf: LogBuffer) -> Self {
        MakeLogWriter { buf }
    }
}

impl<'a> MakeWriter<'a> for MakeLogWriter {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            buf: self.buf.clone(),
            pending: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn splits_lines_and_bounds_capacity() {
        let buf = new_buffer();
        let mut w = MakeLogWriter::new(buf.clone()).make_writer();
        // Deliberately split a line across writes to exercise the pending buffer.
        w.write_all(b"first line\nsecond ").unwrap();
        w.write_all(b"line\n").unwrap();
        let lines = buf.lock().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "first line");
        assert_eq!(lines[1], "second line");
    }

    #[test]
    fn drops_oldest_past_capacity() {
        let buf = new_buffer();
        let mut w = MakeLogWriter::new(buf.clone()).make_writer();
        for i in 0..(CAPACITY + 5) {
            writeln!(w, "line {i}").unwrap();
        }
        let lines = buf.lock().unwrap();
        assert_eq!(lines.len(), CAPACITY);
        assert_eq!(lines.front().unwrap(), "line 5");
        assert_eq!(lines.back().unwrap(), &format!("line {}", CAPACITY + 4));
    }
}
