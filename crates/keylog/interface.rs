//! A log of the secrets TLS and QUIC connections used, in the NSS key log format clients write to `SSLKEYLOGFILE`.
//!
//! https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/

use std::path::Path;

/// A keeper of key logs in files, each shared with whatever else writes the same file.
pub trait Keylog: Default {
    /// The handle to one open log.
    type Keys: Keys;

    /// Opens the log in the file, making the file if none, and keeps reading what others append to it.
    fn open(&self, file: &Path) -> std::io::Result<Self::Keys>;
}

/// An open key log, which takes secrets and gives back every secret written to its file.
pub trait Keys: Send + Sync + 'static {
    /// Appends a secret under its label for the connection whose ClientHello had the client random.
    fn record(&self, label: &str, client_random: &[u8], secret: &[u8]) -> std::io::Result<()>;

    /// Returns the secret under the label for the client random, once anything wrote it to the file.
    fn secret(&self, label: &str, client_random: &[u8]) -> Option<Vec<u8>>;
}

/// The label of a TLS 1.2 connection's master secret.
pub const CLIENT_RANDOM: &str = "CLIENT_RANDOM";
/// The label of the secret a TLS 1.3 client sends 0-RTT data under.
pub const CLIENT_EARLY_TRAFFIC_SECRET: &str = "CLIENT_EARLY_TRAFFIC_SECRET";
/// The label of the secret a TLS 1.3 client sends the rest of its handshake under.
pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
/// The label of the secret a TLS 1.3 server sends its handshake after the ServerHello under.
pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
/// The label of the first secret a TLS 1.3 client sends application data under.
pub const CLIENT_TRAFFIC_SECRET_0: &str = "CLIENT_TRAFFIC_SECRET_0";
/// The label of the first secret a TLS 1.3 server sends application data under.
pub const SERVER_TRAFFIC_SECRET_0: &str = "SERVER_TRAFFIC_SECRET_0";
/// The label of a TLS 1.3 connection's exporter secret, which no decrypter needs.
pub const EXPORTER_SECRET: &str = "EXPORTER_SECRET";
