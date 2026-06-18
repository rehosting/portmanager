//! Minimal SOCKS5 (RFC 1928) server handshake for the dynamic-proxy forward.
//!
//! A `socks` forward binds a local listener whose target isn't fixed: each
//! accepted connection first speaks the SOCKS5 greeting + CONNECT request, which
//! names the real destination. We parse just enough of that to learn the
//! `(host, port)`, then hand it to the same per-stream path a direct forward
//! uses (`StreamHeader` -> agent dial -> splice). Domain targets are passed
//! through verbatim so DNS resolves on the *remote* side, like `ssh -D`.
//!
//! Only no-auth CONNECT is supported; `BIND` and `UDP ASSOCIATE` are rejected
//! with the appropriate reply code.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS protocol version byte.
const VERSION: u8 = 0x05;
/// "No authentication required" method.
const METHOD_NO_AUTH: u8 = 0x00;
/// "No acceptable methods" sentinel returned to the client.
const METHOD_NONE: u8 = 0xFF;
/// CONNECT command (the only one we support).
const CMD_CONNECT: u8 = 0x01;

// Address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Reply codes (RFC 1928 §6).
pub mod rep {
    pub const SUCCESS: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Run the SOCKS5 greeting and CONNECT request on a freshly accepted stream,
/// returning the requested `(host, port)`. Sends the method-selection reply and,
/// for unsupported commands/address types, the corresponding error reply before
/// returning `Err`. The *success* reply is the caller's job (sent only once the
/// upstream QUIC stream is open) — see [`reply`].
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<(String, u16)> {
    // Greeting: VER, NMETHODS, METHODS[NMETHODS].
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        bail!("unsupported SOCKS version {:#x} (only SOCKS5)", head[0]);
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VERSION, METHOD_NONE]).await?;
        bail!("client offered no no-auth method");
    }
    stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;

    // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != VERSION {
        bail!("bad SOCKS version in request: {:#x}", req[0]);
    }
    if req[1] != CMD_CONNECT {
        reply(stream, rep::COMMAND_NOT_SUPPORTED).await?;
        bail!("unsupported SOCKS command {:#x} (only CONNECT)", req[1]);
    }

    let host = match req[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|e| anyhow::anyhow!("invalid domain name: {e}"))?
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        other => {
            reply(stream, rep::ADDRESS_TYPE_NOT_SUPPORTED).await?;
            bail!("unsupported SOCKS address type {other:#x}");
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    Ok((host, port))
}

/// Write a SOCKS5 reply with code `rep`. The bound address is reported as
/// `0.0.0.0:0` — we proxy over QUIC, so there's no meaningful local bind to
/// surface, and clients accept this.
pub async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, rep: u8) -> Result<()> {
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0.
    let frame = [VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a negotiation against an in-memory peer that plays the SOCKS client.
    /// Returns the parsed target plus the bytes the server sent back.
    async fn run(client_to_server: Vec<u8>) -> Result<((String, u16), Vec<u8>)> {
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(&client_to_server).await.unwrap();
        let target = negotiate(&mut server).await?;
        // Read whatever the server wrote back (method-selection here; the success
        // reply is the caller's responsibility).
        let mut buf = vec![0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        Ok((target, buf))
    }

    #[tokio::test]
    async fn connect_ipv4() {
        // greeting: v5, 1 method, no-auth. request: connect, ipv4 127.0.0.1:8080.
        let bytes = vec![
            0x05, 0x01, 0x00, // greeting
            0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90, // connect 127.0.0.1:8080
        ];
        let ((host, port), reply) = run(bytes).await.unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
        assert_eq!(reply, vec![VERSION, METHOD_NO_AUTH]);
    }

    #[tokio::test]
    async fn connect_domain_passes_name_through() {
        let name = b"db.internal";
        let mut bytes = vec![
            0x05,
            0x01,
            0x00,
            0x05,
            0x01,
            0x00,
            ATYP_DOMAIN,
            name.len() as u8,
        ];
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&5432u16.to_be_bytes());
        let ((host, port), _) = run(bytes).await.unwrap();
        assert_eq!(
            host, "db.internal",
            "domain must pass through for remote DNS"
        );
        assert_eq!(port, 5432);
    }

    #[tokio::test]
    async fn connect_ipv6() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, ATYP_IPV6];
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let ((host, port), _) = run(bytes).await.unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn rejects_non_connect_command() {
        // BIND (0x02) must be refused with command-not-supported.
        let bytes = vec![0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(&bytes).await.unwrap();
        assert!(negotiate(&mut server).await.is_err());
        // First two bytes are the method selection, then the 10-byte error reply.
        let mut buf = vec![0u8; 12];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[0..2], &[VERSION, METHOD_NO_AUTH]);
        assert_eq!(buf[3], rep::COMMAND_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn rejects_no_acceptable_method() {
        // Greeting offers only GSSAPI (0x01), no no-auth.
        let bytes = vec![0x05, 0x01, 0x01];
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(&bytes).await.unwrap();
        assert!(negotiate(&mut server).await.is_err());
        let mut buf = vec![0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, vec![VERSION, METHOD_NONE]);
    }
}
