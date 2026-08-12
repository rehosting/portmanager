//! Per-session ephemeral identities and pinned mutual-TLS for the QUIC channel.
//!
//! There is no PKI. At bootstrap each side generates a throwaway self-signed
//! cert; the SHA-256 fingerprints are swapped over the (already authenticated)
//! SSH channel and pinned here. Both the client's [`ServerCertVerifier`] and the
//! agent's [`ClientCertVerifier`] accept *only* the one pinned fingerprint, via a
//! constant-time compare — effectively bidirectional certificate pinning.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};

/// ALPN protocol id; doubles as a wire-protocol version gate.
pub const ALPN: &[u8] = b"portmanager/1";

/// Default QUIC keep-alive interval (the mosh-style heartbeat).
pub const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(3);
/// Default QUIC idle timeout — kept finite for fast death detection; its expiry
/// triggers session re-attach, not session death (see plan).
pub const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(20);

/// A SHA-256 certificate fingerprint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute the fingerprint of a DER-encoded certificate.
    pub fn of(cert: &CertificateDer<'_>) -> Self {
        let digest = Sha256::digest(cert.as_ref());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Fingerprint(out)
    }

    /// Lowercase hex encoding, for exchange over the SSH channel.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a hex string (as produced by [`Fingerprint::to_hex`]).
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).context("fingerprint is not valid hex")?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("fingerprint must be 32 bytes (64 hex chars)"))?;
        Ok(Fingerprint(arr))
    }

    /// Constant-time equality, to avoid leaking match progress via timing.
    fn ct_eq(&self, other: &Fingerprint) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

/// A throwaway per-session identity: a self-signed cert + its private key.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: Fingerprint,
}

impl Identity {
    /// Generate a fresh ephemeral self-signed identity.
    pub fn generate() -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec!["portmanager".to_string()])
            .context("generating self-signed certificate")?;
        let cert = ck.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let fingerprint = Fingerprint::of(&cert);
        Ok(Identity {
            cert,
            key,
            fingerprint,
        })
    }
}

/// Install the ring crypto provider as the process default. Idempotent.
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a quinn client config that authenticates with `identity` and accepts
/// only a server presenting `peer` as its end-entity cert fingerprint.
pub fn client_config(
    identity: &Identity,
    peer: Fingerprint,
    timing: &Timing,
) -> Result<quinn::ClientConfig> {
    let provider = provider();
    let verifier = Arc::new(PinnedVerifier::new(peer, &provider));

    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("installing client auth certificate")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("converting rustls config for QUIC")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
    cfg.transport_config(Arc::new(timing.transport_config()?));
    Ok(cfg)
}

/// Build a quinn server config that authenticates with `identity` and accepts
/// only a client presenting `peer` as its end-entity cert fingerprint.
pub fn server_config(
    identity: &Identity,
    peer: Fingerprint,
    timing: &Timing,
) -> Result<quinn::ServerConfig> {
    let provider = provider();
    let verifier = Arc::new(PinnedVerifier::new(peer, &provider));

    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .context("installing server certificate")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("converting rustls config for QUIC")?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    cfg.transport_config(Arc::new(timing.transport_config()?));
    Ok(cfg)
}

/// QUIC keep-alive / idle timing knobs.
#[derive(Debug, Clone)]
pub struct Timing {
    pub keep_alive: Duration,
    pub max_idle: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            keep_alive: DEFAULT_KEEP_ALIVE,
            max_idle: DEFAULT_MAX_IDLE,
        }
    }
}

impl Timing {
    fn transport_config(&self) -> Result<quinn::TransportConfig> {
        let mut tc = quinn::TransportConfig::default();
        tc.keep_alive_interval(Some(self.keep_alive));
        let idle = quinn::IdleTimeout::try_from(self.max_idle).context("idle timeout too large")?;
        tc.max_idle_timeout(Some(idle));

        // Congestion control: BBR, not quinn's default Cubic.
        //
        // portmanager's whole premise is links that lose packets — Wi-Fi
        // roaming, VPNs, cellular. Cubic treats every loss as congestion and
        // backs off, so its throughput falls off roughly as 1/sqrt(loss_rate)
        // regardless of how much bandwidth is actually free. On a measured path
        // carrying ~1.2 MB/s with ~6% loss at saturation, Cubic delivered
        // 0.21 MB/s — about a sixth of the link. BBR models the bottleneck's
        // bandwidth and RTT instead of reading loss as a stop sign, which is
        // the right trade for exactly these links.
        tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

        Ok(tc)
    }
}

/// A rustls verifier that pins one peer certificate fingerprint, used for both
/// the server-cert (client side) and client-cert (server side) checks.
#[derive(Debug)]
struct PinnedVerifier {
    expected: Fingerprint,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    fn new(expected: Fingerprint, provider: &rustls::crypto::CryptoProvider) -> Self {
        PinnedVerifier {
            expected,
            algs: provider.signature_verification_algorithms,
        }
    }

    fn check_pin(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        if Fingerprint::of(end_entity).ct_eq(&self.expected) {
            Ok(())
        } else {
            Err(rustls::Error::General(
                "peer certificate fingerprint does not match pinned value".into(),
            ))
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check_pin(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for PinnedVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check_pin(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip_and_match() {
        super::init();
        let id = Identity::generate().unwrap();
        let hex = id.fingerprint.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = Fingerprint::from_hex(&hex).unwrap();
        assert!(parsed.ct_eq(&id.fingerprint));
    }

    #[test]
    fn distinct_identities_differ() {
        super::init();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert!(!a.fingerprint.ct_eq(&b.fingerprint));
    }

    #[test]
    fn from_hex_rejects_bad_length() {
        assert!(Fingerprint::from_hex("abcd").is_err());
        assert!(Fingerprint::from_hex("zz").is_err());
    }

    #[test]
    fn configs_build_with_cross_pinning() {
        super::init();
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let timing = Timing::default();
        // Client pins the server's fingerprint and vice versa.
        client_config(&client, server.fingerprint, &timing).unwrap();
        server_config(&server, client.fingerprint, &timing).unwrap();
    }
}
