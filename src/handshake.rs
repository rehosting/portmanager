//! Bootstrap handshake exchanged over the (authenticated) SSH pipe.
//!
//! The client writes a [`Hello`] to the agent's stdin; the agent replies with a
//! [`Ready`] on its stdout. Secrets (the session token) ride the SSH channel,
//! never argv, so they aren't exposed via `/proc/<pid>/cmdline`.
//!
//! Wire format is one newline-terminated ASCII line per message:
//! ```text
//! PM-HELLO v2 <client_fp_hex> <token_hex>
//! PM-READY v2 <udp_port> <agent_fp_hex> <session_id_hex> <agent_version>
//! PM-ERROR <message...>
//! ```

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::Fingerprint;

/// Handshake/wire protocol version.
pub const PROTO_VERSION: u32 = 2;

const HELLO_TAG: &str = "PM-HELLO";
const READY_TAG: &str = "PM-READY";
const ERROR_TAG: &str = "PM-ERROR";

/// 32-byte shared secret used to authorize SSH-less re-attach to a live agent.
#[derive(Clone, PartialEq, Eq)]
pub struct Token([u8; 32]);

/// 16-byte logical session identifier (decoupled from any QUIC connection).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId([u8; 16]);

macro_rules! hex_newtype {
    ($t:ty, $n:expr) => {
        impl $t {
            /// Generate from the OS CSPRNG.
            pub fn random() -> Result<Self> {
                let mut buf = [0u8; $n];
                getrandom::fill(&mut buf).context("reading OS randomness")?;
                Ok(Self(buf))
            }
            /// Lowercase hex encoding.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
            /// Parse from hex.
            pub fn from_hex(s: &str) -> Result<Self> {
                let bytes = hex::decode(s.trim()).context("value is not valid hex")?;
                let arr: [u8; $n] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!(concat!("expected ", $n, " bytes")))?;
                Ok(Self(arr))
            }
            /// Constant-time equality.
            pub fn ct_eq(&self, other: &Self) -> bool {
                let mut diff = 0u8;
                for (a, b) in self.0.iter().zip(other.0.iter()) {
                    diff |= a ^ b;
                }
                diff == 0
            }
        }
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($t), self.to_hex())
            }
        }
    };
}

hex_newtype!(Token, 32);
hex_newtype!(SessionId, 16);

/// Client -> agent: client identity + session secret.
#[derive(Debug, Clone)]
pub struct Hello {
    pub client_fp: Fingerprint,
    pub token: Token,
}

/// Agent -> client: where to reach the QUIC listener and how to pin it.
#[derive(Debug, Clone)]
pub struct Ready {
    pub udp_port: u16,
    pub agent_fp: Fingerprint,
    pub session_id: SessionId,
    /// Agent binary version (`CARGO_PKG_VERSION`), so the client can detect skew.
    pub version: String,
}

impl Hello {
    /// Serialize to the one-line wire form (newline-terminated).
    pub fn to_line(&self) -> String {
        format!(
            "{HELLO_TAG} v{PROTO_VERSION} {} {}\n",
            self.client_fp.to_hex(),
            self.token.to_hex()
        )
    }

    /// Parse from a wire line (sync; used by the pre-runtime agent handshake).
    pub fn parse_line(line: &str) -> Result<Self> {
        let parts = check_tagged_line(line, HELLO_TAG)?;
        if parts.len() != 4 {
            bail!("malformed HELLO: wrong field count");
        }
        Ok(Hello {
            client_fp: Fingerprint::from_hex(&parts[2])?,
            token: Token::from_hex(&parts[3])?,
        })
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(self.to_line().as_bytes()).await?;
        w.flush().await?;
        Ok(())
    }

    pub async fn read<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<Self> {
        let line = read_nonempty_line(r, HELLO_TAG).await?;
        Self::parse_line(&line)
    }
}

impl Ready {
    /// Serialize to the one-line wire form (newline-terminated).
    pub fn to_line(&self) -> String {
        format!(
            "{READY_TAG} v{PROTO_VERSION} {} {} {} {}\n",
            self.udp_port,
            self.agent_fp.to_hex(),
            self.session_id.to_hex(),
            self.version,
        )
    }

    /// Parse from a wire line (sync).
    pub fn parse_line(line: &str) -> Result<Self> {
        let parts = check_tagged_line(line, READY_TAG)?;
        if parts.len() != 6 {
            bail!("malformed READY: wrong field count");
        }
        let udp_port = parts[2].parse::<u16>().context("invalid udp port")?;
        Ok(Ready {
            udp_port,
            agent_fp: Fingerprint::from_hex(&parts[3])?,
            session_id: SessionId::from_hex(&parts[4])?,
            version: parts[5].clone(),
        })
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(self.to_line().as_bytes()).await?;
        w.flush().await?;
        Ok(())
    }

    pub async fn read<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<Self> {
        let line = read_nonempty_line(r, READY_TAG).await?;
        Self::parse_line(&line)
    }
}

/// Write a `PM-ERROR <message>` line.
pub async fn write_error<W: AsyncWrite + Unpin>(w: &mut W, message: &str) -> Result<()> {
    w.write_all(error_line(message).as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

/// Read one non-empty line (skipping blanks, e.g. stray shell output).
async fn read_nonempty_line<R: AsyncBufReadExt + Unpin>(
    r: &mut R,
    expected_tag: &str,
) -> Result<String> {
    loop {
        let mut line = String::new();
        let n = r
            .read_line(&mut line)
            .await
            .context("reading handshake line")?;
        if n == 0 {
            bail!("connection closed before {expected_tag}");
        }
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
}

/// Split a line and verify the expected tag and version. A `PM-ERROR` line is
/// surfaced as an error carrying its message.
fn check_tagged_line(line: &str, expected_tag: &str) -> Result<Vec<String>> {
    let line = line.trim();
    let parts: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    match parts.first().map(String::as_str) {
        Some(t) if t == ERROR_TAG => {
            let msg = line
                .strip_prefix(ERROR_TAG)
                .unwrap_or(line)
                .trim()
                .to_string();
            bail!("agent reported: {msg}");
        }
        Some(t) if t == expected_tag => {}
        other => bail!("expected {expected_tag}, got {other:?}"),
    }
    let version = parts.get(1).map(String::as_str).unwrap_or("");
    if version != format!("v{PROTO_VERSION}") {
        bail!("protocol version mismatch: agent sent {version:?}");
    }
    Ok(parts)
}

/// Format a `PM-ERROR` line (sync).
pub fn error_line(message: &str) -> String {
    format!("{ERROR_TAG} {message}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, Identity};
    use tokio::io::BufReader;

    #[tokio::test]
    async fn hello_roundtrip() {
        crypto::init();
        let id = Identity::generate().unwrap();
        let hello = Hello {
            client_fp: id.fingerprint,
            token: Token::random().unwrap(),
        };
        let mut buf = Vec::new();
        hello.write(&mut buf).await.unwrap();
        let mut r = BufReader::new(&buf[..]);
        let got = Hello::read(&mut r).await.unwrap();
        assert_eq!(got.client_fp, hello.client_fp);
        assert!(got.token.ct_eq(&hello.token));
    }

    #[tokio::test]
    async fn ready_roundtrip() {
        crypto::init();
        let id = Identity::generate().unwrap();
        let ready = Ready {
            udp_port: 51820,
            agent_fp: id.fingerprint,
            session_id: SessionId::random().unwrap(),
            version: "0.1.0".to_string(),
        };
        let mut buf = Vec::new();
        ready.write(&mut buf).await.unwrap();
        let mut r = BufReader::new(&buf[..]);
        let got = Ready::read(&mut r).await.unwrap();
        assert_eq!(got.udp_port, 51820);
        assert_eq!(got.version, "0.1.0");
        assert!(got.session_id.ct_eq(&ready.session_id));
    }

    #[tokio::test]
    async fn error_line_surfaces_message() {
        let mut buf = Vec::new();
        write_error(&mut buf, "inbound UDP blocked").await.unwrap();
        let mut r = BufReader::new(&buf[..]);
        let err = Ready::read(&mut r).await.unwrap_err();
        assert!(err.to_string().contains("inbound UDP blocked"));
    }

    #[tokio::test]
    async fn skips_blank_lines_before_tag() {
        crypto::init();
        let id = Identity::generate().unwrap();
        let ready = Ready {
            udp_port: 1234,
            agent_fp: id.fingerprint,
            session_id: SessionId::random().unwrap(),
            version: "9.9.9".to_string(),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\n\n");
        ready.write(&mut buf).await.unwrap();
        let mut r = BufReader::new(&buf[..]);
        assert_eq!(Ready::read(&mut r).await.unwrap().udp_port, 1234);
    }
}
