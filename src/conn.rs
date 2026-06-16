//! Transport-agnostic connection handle.
//!
//! The forward set, discovery, and supervisor all open bidirectional streams
//! without caring whether the data plane is QUIC (direct UDP) or the SSH-carried
//! TCP tunnel (`--via-ssh`, for hosts reachable only through a jump host with no
//! direct UDP path). [`Conn`] unifies the two; each forwarded TCP connection
//! becomes one logical bidi stream either way.
//!
//! ## SSH-tunnel data protocol
//!
//! In tunnel mode the data plane rides `ssh -L` (see [`crate::tunnel`]): each
//! logical stream is a fresh TCP connection to a client-local forwarded port
//! that SSH carries to the agent's loopback listener. SSH already authenticates
//! and encrypts the channel (it is portmanager's trust anchor), so there is no
//! TLS here. To keep another local user on the target from speaking to the
//! agent's loopback listener, every connection opens with the 32-byte session
//! [`Token`] followed by a one-byte opcode:
//!
//! - [`OP_STREAM`] — a forwarded connection: a [`crate::proto::StreamHeader`]
//!   and spliced bytes follow.
//! - [`OP_KEEPALIVE`] — the supervisor's persistent liveness connection. The
//!   agent holds it open and counts it as a client (so an idle session with no
//!   active forwards isn't reaped); its closure is how the client detects loss.
//! - [`OP_SHUTDOWN`] — ask the agent to end the session now (client Ctrl-C),
//!   mirroring QUIC's shutdown close code.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::handshake::Token;

/// Boxed write half of a logical bidi stream.
pub type SendHalf = Box<dyn AsyncWrite + Send + Unpin>;
/// Boxed read half of a logical bidi stream.
pub type RecvHalf = Box<dyn AsyncRead + Send + Unpin>;

/// First opcode byte (after the token) on an SSH-tunnel connection.
pub const OP_STREAM: u8 = 0x01;
pub const OP_KEEPALIVE: u8 = 0x02;
pub const OP_SHUTDOWN: u8 = 0x03;

/// How long [`SshConn::send_shutdown`] waits for the agent to acknowledge (by
/// closing the connection) before giving up — bounds graceful shutdown.
const SHUTDOWN_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// A live data-plane connection to the agent. Cheaply clonable.
#[derive(Clone)]
pub enum Conn {
    /// Direct QUIC connection (the default transport).
    Quic(quinn::Connection),
    /// SSH-carried TCP tunnel (`--via-ssh`).
    Ssh(Arc<SshConn>),
}

impl Conn {
    /// Open a new bidirectional stream to the agent.
    pub async fn open_bi(&self) -> Result<(SendHalf, RecvHalf)> {
        match self {
            Conn::Quic(c) => {
                let (send, recv) = c.open_bi().await.context("opening QUIC stream")?;
                Ok((Box::new(send), Box::new(recv)))
            }
            Conn::Ssh(s) => s.open_stream().await,
        }
    }
}

/// An SSH-tunnel data-plane connection: the local forwarded port to dial, the
/// session token to present, and a liveness signal fed by a persistent
/// keepalive connection.
pub struct SshConn {
    local: SocketAddr,
    token: Token,
    dead: watch::Receiver<bool>,
    keepalive: tokio::task::JoinHandle<()>,
}

impl SshConn {
    /// Establish the connection: open the persistent keepalive stream (which the
    /// agent counts as the client) and start watching it for closure. `local` is
    /// the client-local `ssh -L` port carrying traffic to the agent listener.
    pub async fn connect(local: SocketAddr, token: Token) -> Result<Arc<SshConn>> {
        let mut ka = TcpStream::connect(local)
            .await
            .context("opening keepalive connection through the SSH tunnel")?;
        write_preamble(&mut ka, &token, OP_KEEPALIVE)
            .await
            .context("sending keepalive preamble")?;

        let (dead_tx, dead_rx) = watch::channel(false);
        let keepalive = tokio::spawn(async move {
            // The keepalive carries no payload; any read returning 0/err means
            // the tunnel or the agent is gone.
            let mut buf = [0u8; 64];
            loop {
                match ka.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = dead_tx.send(true);
        });

        Ok(Arc::new(SshConn {
            local,
            token,
            dead: dead_rx,
            keepalive,
        }))
    }

    /// Open one forwarded-stream connection (token + `OP_STREAM`). The caller
    /// writes the [`crate::proto::StreamHeader`] next.
    async fn open_stream(&self) -> Result<(SendHalf, RecvHalf)> {
        let mut tcp = TcpStream::connect(self.local)
            .await
            .context("opening stream through the SSH tunnel")?;
        write_preamble(&mut tcp, &self.token, OP_STREAM)
            .await
            .context("sending stream preamble")?;
        let (read, write) = tcp.into_split();
        Ok((Box::new(write), Box::new(read)))
    }

    /// Resolve once the keepalive connection has died (tunnel or agent gone).
    pub async fn wait_closed(&self) {
        let mut rx = self.dead.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Best-effort: tell the agent to end the session now (client Ctrl-C).
    ///
    /// Waits for the agent to process the opcode and close the connection before
    /// returning — otherwise the caller may drop the `ssh -L` tunnel (killing the
    /// forward) before the bytes are delivered, and the agent would linger until
    /// its grace window instead of exiting now.
    pub async fn send_shutdown(&self) {
        let Ok(mut tcp) = TcpStream::connect(self.local).await else {
            return;
        };
        if write_preamble(&mut tcp, &self.token, OP_SHUTDOWN)
            .await
            .is_err()
        {
            return;
        }
        let mut buf = [0u8; 8];
        let _ = tokio::time::timeout(SHUTDOWN_ACK_TIMEOUT, async {
            loop {
                match tcp.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
    }
}

impl Drop for SshConn {
    fn drop(&mut self) {
        self.keepalive.abort();
    }
}

/// Write the per-connection preamble: 32 token bytes then a one-byte opcode.
async fn write_preamble(tcp: &mut TcpStream, token: &Token, opcode: u8) -> std::io::Result<()> {
    tcp.write_all(token.as_bytes()).await?;
    tcp.write_u8(opcode).await?;
    tcp.flush().await?;
    Ok(())
}
