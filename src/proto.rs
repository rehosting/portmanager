//! On-the-wire stream framing and the TCP<->QUIC splice.
//!
//! Each forwarded TCP connection maps to one QUIC bidirectional stream. The
//! client opens the stream and writes a small [`StreamHeader`] naming the target
//! (and optionally the namespace to dial it from); the agent reads it, connects,
//! and then bytes are spliced both ways until either side closes.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Current stream-protocol version (ALPN also gates this at the TLS layer).
const VERSION: u8 = 1;
/// Defensive bound on the variable-length header fields.
const MAX_FIELD: usize = 255;

/// Per-stream target descriptor written by the client at stream open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    /// Namespace selector in wire form (empty = agent's host namespace).
    pub ns: String,
    /// Target host the agent should connect to.
    pub host: String,
    /// Target port the agent should connect to.
    pub port: u16,
}

impl StreamHeader {
    /// Serialize and write the header to a send stream (any `AsyncWrite`).
    ///
    /// Layout: `version:u8 | port:u16_be | host_len:u8 | host | ns_len:u8 | ns`.
    pub async fn write<W: AsyncWrite + Unpin>(&self, send: &mut W) -> io::Result<()> {
        if self.host.len() > MAX_FIELD || self.ns.len() > MAX_FIELD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "header field exceeds 255 bytes",
            ));
        }
        let mut buf = Vec::with_capacity(5 + self.host.len() + self.ns.len());
        buf.push(VERSION);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.push(self.host.len() as u8);
        buf.extend_from_slice(self.host.as_bytes());
        buf.push(self.ns.len() as u8);
        buf.extend_from_slice(self.ns.as_bytes());
        send.write_all(&buf).await?;
        Ok(())
    }

    /// Read and parse a header from a recv stream (any `AsyncRead`).
    pub async fn read<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<Self> {
        let mut fixed = [0u8; 3];
        recv.read_exact(&mut fixed)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        if fixed[0] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported stream protocol version {}", fixed[0]),
            ));
        }
        let port = u16::from_be_bytes([fixed[1], fixed[2]]);
        let host = read_lp_string(recv).await?;
        let ns = read_lp_string(recv).await?;
        Ok(StreamHeader { ns, host, port })
    }
}

/// Read a `len:u8`-prefixed UTF-8 string.
async fn read_lp_string<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<String> {
    let mut len = [0u8; 1];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
    let mut bytes = vec![0u8; len[0] as usize];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Splice a TCP connection to a transport bidi stream, both directions, until
/// close. Works over any send/recv pair (QUIC streams or a TCP-tunnel stream's
/// halves).
///
/// TCP read -> stream send, and stream recv -> TCP write run concurrently with
/// independent half-close: an EOF on one direction finishes that half (via
/// `shutdown`, which finishes a QUIC send stream) without tearing down the
/// other.
///
/// `bytes_up`/`bytes_down` are bumped live as bytes flow (client->agent and
/// agent->client respectively), driving the TUI's per-forward throughput
/// display. Counting wraps the TCP halves so it reflects the application's own
/// payload, independent of the transport framing.
pub async fn splice<W, R>(
    tcp: TcpStream,
    mut send: W,
    mut recv: R,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (tcp_read, tcp_write) = tcp.into_split();
    let mut tcp_read = Counted::new(tcp_read, bytes_up);
    let mut tcp_write = Counted::new(tcp_write, bytes_down);

    let upstream = async {
        tokio::io::copy(&mut tcp_read, &mut send).await?;
        let _ = send.shutdown().await;
        Ok::<(), io::Error>(())
    };
    let downstream = async {
        tokio::io::copy(&mut recv, &mut tcp_write).await?;
        tcp_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    tokio::try_join!(upstream, downstream)?;
    Ok(())
}

/// Wraps an `AsyncRead`/`AsyncWrite`, adding each transferred byte to a shared
/// counter. Used per direction in [`splice`] for live throughput accounting.
/// Requires `S: Unpin` (the owned TCP halves are), so it can poll the inner
/// handle without pin-projection.
struct Counted<S> {
    inner: S,
    count: Arc<AtomicU64>,
}

impl<S> Counted<S> {
    fn new(inner: S, count: Arc<AtomicU64>) -> Self {
        Counted { inner, count }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len() - before;
            this.count.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            this.count.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_is_stable() {
        // Spot-check the byte layout for a known header.
        let h = StreamHeader {
            ns: String::new(),
            host: "127.0.0.1".into(),
            port: 8888,
        };
        let mut buf = Vec::new();
        buf.push(VERSION);
        buf.extend_from_slice(&h.port.to_be_bytes());
        buf.push(h.host.len() as u8);
        buf.extend_from_slice(h.host.as_bytes());
        buf.push(0); // empty ns
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[1..3], &[0x22, 0xb8]); // 8888
        assert_eq!(buf[3], 9); // len("127.0.0.1")
    }

    #[tokio::test]
    async fn counted_tallies_bytes_in_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Writer side: every written byte lands in the counter.
        let (a, b) = tokio::io::duplex(64);
        let wc = Arc::new(AtomicU64::new(0));
        let mut writer = Counted::new(a, wc.clone());
        writer.write_all(b"hello world").await.unwrap();
        writer.flush().await.unwrap();
        assert_eq!(wc.load(Ordering::Relaxed), 11);

        // Reader side: every byte read through the wrapper is tallied.
        let rc = Arc::new(AtomicU64::new(0));
        let mut reader = Counted::new(b.take(11), rc.clone());
        let mut sink = Vec::new();
        reader.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink, b"hello world");
        assert_eq!(rc.load(Ordering::Relaxed), 11);
        drop(writer);
    }
}
