//! The operating system's store of trusted roots, which a person adds the proxy's root to once.

/// A store of trusted root certificates.
pub trait Trust {
    /// Adds a PEM root certificate, asking the person if the system does.
    ///
    /// An error of kind `PermissionDenied` means the store needs more privileges.
    fn add_trusted_root(&self, certificate: &str) -> std::io::Result<Outcome>;
}

/// The result of adding a root: newly trusted, or trusted before and left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Trusted,
    AlreadyTrusted,
}
