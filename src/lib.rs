//! portmanager — resilient QUIC port forwarder with SSH auto-bootstrap.
//!
//! Modules are public so the binary and integration tests can drive them.

pub mod agent;
pub mod bootstrap;
pub mod cli;
pub mod client;
pub mod config;
pub mod conn;
pub mod control;
pub mod crypto;
pub mod discovery;
pub mod doctor;
pub mod error;
pub mod firewall;
pub mod forward;
pub mod handshake;
pub mod logbuf;
pub mod netns;
pub mod netwatch;
pub mod proto;
pub mod socks;
pub mod supervisor;
pub mod transport;
pub mod tui;
pub mod tunnel;
