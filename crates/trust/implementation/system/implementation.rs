//! The user's trust store: the login keychain through `security` on macOS, and os-truststore elsewhere.
//!
//! On macOS the person has as long as they need for the password prompt; Linux has only the system's store.

use std::io::ErrorKind;

use simple_httptap_trust::{Outcome, Trust};

/// The trust store of the system the program runs on.
#[derive(Debug)]
pub struct SystemTrust;

impl Trust for SystemTrust {
    fn add_trusted_root(&self, certificate: &str) -> std::io::Result<Outcome> {
        let parsed = pem::parse(certificate).map_err(|fault| std::io::Error::new(ErrorKind::InvalidInput, fault))?;
        if parsed.tag() != CERTIFICATE_TAG {
            return Err(std::io::Error::new(ErrorKind::InvalidInput, "the PEM block is no certificate"));
        }
        add_to_store(certificate)
    }
}

/// The label of a PEM certificate block.
const CERTIFICATE_TAG: &str = "CERTIFICATE";

/// The macOS tool that manages keychains and trust settings.
#[cfg(target_os = "macos")]
const SECURITY: &str = "security";
/// The `security` arguments that check whether a certificate file is trusted.
#[cfg(target_os = "macos")]
const VERIFY_CERTIFICATE: &[&str] = &["verify-cert", "-c"];
/// The `security` arguments that add a certificate file to the login keychain as a trusted root.
#[cfg(target_os = "macos")]
const ADD_TRUSTED_ROOT: &[&str] = &["add-trusted-cert", "-r", "trustRoot"];
/// The extension `security` reads a PEM certificate file by.
#[cfg(target_os = "macos")]
const PEM_SUFFIX: &str = ".pem";

/// Adds the certificate to the login keychain as a trusted root, unless macOS trusts it already.
#[cfg(target_os = "macos")]
fn add_to_store(certificate: &str) -> std::io::Result<Outcome> {
    use std::io::Write;
    use std::process::Command;

    let mut file = tempfile::Builder::new().suffix(PEM_SUFFIX).tempfile()?;
    file.write_all(certificate.as_bytes())?;
    let path = file.path();
    let is_trusted = || -> std::io::Result<bool> {
        Ok(Command::new(SECURITY).args(VERIFY_CERTIFICATE).arg(path).output()?.status.success())
    };
    if is_trusted()? {
        return Ok(Outcome::AlreadyTrusted);
    }
    let added = Command::new(SECURITY).args(ADD_TRUSTED_ROOT).arg(path).status()?;
    if !added.success() {
        return Err(std::io::Error::new(ErrorKind::PermissionDenied, format!("`{SECURITY}` failed with {added}")));
    }
    if !is_trusted()? {
        return Err(std::io::Error::other("the certificate was added, but macOS does not trust it"));
    }
    Ok(Outcome::Trusted)
}

/// Adds the certificate to the store os-truststore uses: the user's on Windows, the system's on Linux.
#[cfg(not(target_os = "macos"))]
fn add_to_store(certificate: &str) -> std::io::Result<Outcome> {
    use os_truststore::{Cert, Install, Report, Scope, TrustError};

    let parsed = Cert::from_pem(certificate.as_bytes())
        .map_err(|fault| std::io::Error::new(ErrorKind::InvalidInput, fault.to_string()))?;
    match Install::new(&parsed).scope(Scope::CurrentUser).run() {
        Ok(Report::Installed) => Ok(Outcome::Trusted),
        Ok(Report::AlreadyInstalled) => Ok(Outcome::AlreadyTrusted),
        Ok(report) => Err(std::io::Error::other(format!("the certificate is not trusted: {report:?}"))),
        Err(fault @ TrustError::NeedsElevation { .. }) => {
            Err(std::io::Error::new(ErrorKind::PermissionDenied, fault.to_string()))
        }
        Err(fault) => Err(std::io::Error::other(fault.to_string())),
    }
}
