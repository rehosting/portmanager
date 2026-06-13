//! portmanager — resilient QUIC port forwarder with SSH auto-bootstrap.
//!
//! Modules are public so the binary and integration tests can drive them.

pub mod agent;
pub mod bootstrap;
pub mod cli;
pub mod client;
pub mod config;
pub mod control;
pub mod crypto;
pub mod discovery;
pub mod doctor;
pub mod error;
pub mod firewall;
pub mod forward;
pub mod handshake;
pub mod netns;
pub mod netwatch;
pub mod proto;
pub mod supervisor;
pub mod transport;
