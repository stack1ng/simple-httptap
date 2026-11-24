//! A certificate authority that the proxy signs each host's certificate with.

use std::path::Path;

/// A keeper of authorities in folders, each trusted once.
pub trait Authority: Default {
    /// The handle to an authority in a folder.
    type Signer: Signer;

    /// Opens the folder's authority, making it if none; racing processes share one.
    fn open(&self, folder: &Path) -> std::io::Result<Self::Signer>;
}

/// An opened authority, which issues host certificates under its root.
pub trait Signer: Send + Sync + 'static {
    /// Returns the root certificate to trust, in PEM.
    fn root_certificate(&self) -> String;

    /// Issues a certificate for a DNS name or an IP address.
    fn issue_certificate(&self, host: &str) -> std::io::Result<Issued>;
}

/// A host certificate's DER chain, root last, and its PKCS #8 DER key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
}
