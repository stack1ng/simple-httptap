//! A log of TLS and QUIC secrets in the NSS key log format clients write to `SSLKEYLOGFILE`.
//!
//! https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/

use std::path::Path;

/// A keeper of key logs in files, each shared with other writers of the file.
pub trait Keylog: Default {
    /// The handle to one open log.
    type Keys: Keys;

    /// Opens the file's log, creating the file if missing, and keeps reading what others append.
    fn open(&self, file: &Path) -> std::io::Result<Self::Keys>;
}

/// An open key log that records secrets and returns any written to its file.
pub trait Keys: Send + Sync + 'static {
    /// Appends a labelled secret for the connection whose ClientHello had the client random.
    fn record(&self, label: &str, client_random: &[u8], secret: &[u8]) -> std::io::Result<()>;

    /// Returns the labelled secret of the client random once anything wrote it to the file.
    fn secret(&self, label: &str, client_random: &[u8]) -> Option<Vec<u8>>;
}

pub const CLIENT_EARLY_TRAFFIC_SECRET: &str = "CLIENT_EARLY_TRAFFIC_SECRET";

pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";

pub const CLIENT_RANDOM: &str = "CLIENT_RANDOM";

pub const CLIENT_TRAFFIC_SECRET_0: &str = "CLIENT_TRAFFIC_SECRET_0";

pub const EXPORTER_SECRET: &str = "EXPORTER_SECRET";

pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";

pub const SERVER_TRAFFIC_SECRET_0: &str = "SERVER_TRAFFIC_SECRET_0";
