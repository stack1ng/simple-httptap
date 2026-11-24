//! The trust store: the login keychain's trust settings on macOS, and os-truststore elsewhere.
//!
//! On macOS the system's own prompt asks once, by password or Touch ID, and waits as long as needed.

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
const SECURITY: &str = "/usr/bin/security";
/// The `security` arguments that add a certificate file as a root the user trusts for every purpose.
///
/// The user's trust settings need no administrator, and macOS itself asks the person to confirm them.
#[cfg(target_os = "macos")]
const ADD_TRUSTED_ROOT: &[&str] = &["add-trusted-cert", "-r", "trustRoot"];
/// The extension `security` reads a PEM certificate file by.
#[cfg(target_os = "macos")]
const PEM_SUFFIX: &str = ".pem";

/// Adds the certificate to the login keychain as a root the user trusts, after macOS's own prompt.
///
/// Adding it again is harmless, so it never reports `AlreadyTrusted`; the caller checks trust itself.
#[cfg(target_os = "macos")]
fn add_to_store(certificate: &str) -> std::io::Result<Outcome> {
    use std::io::Write;
    use std::process::Command;

    let mut file = tempfile::Builder::new().suffix(PEM_SUFFIX).tempfile()?;
    file.write_all(certificate.as_bytes())?;
    file.as_file().sync_all()?;
    let output = Command::new(SECURITY).args(ADD_TRUSTED_ROOT).arg(file.path()).output()?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(std::io::Error::new(ErrorKind::PermissionDenied, detail));
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
