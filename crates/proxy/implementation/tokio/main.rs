//! The `simple-httptap` program: a proxy on an ephemeral port that writes what it sees to standard output.
//!
//! `simple-httptap trust` adds the root to the user's trust store; both keep it in the system's data folder.

use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use base64::Engine;
use simple_httptap_authority::{Authority, Signer};
use simple_httptap_authority_rcgen::{RcgenAuthority, RcgenSigner};
use simple_httptap_proxy::{Listener, Proxy, Upstream};
use simple_httptap_proxy_tokio::TokioProxy;
use simple_httptap_sink_ndjson::NdJson;
use simple_httptap_trust::{Outcome, Trust};
use simple_httptap_trust_system::SystemTrust;
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// The program's name, which also names its data folder.
const PROGRAM: &str = "simple-httptap";
/// The command that adds the root certificate to the user's trust store.
const TRUST_COMMAND: &str = "trust";
/// The variable with the upstream HTTP proxy, as `http://[user:password@]host:port`.
const UPSTREAM_VARIABLE: &str = "SIMPLE_HTTPTAP_UPSTREAM_PROXY";
/// The host the startup check asks the system to trust a certificate for.
const CHECKED_HOST: &str = "localhost";
/// The only scheme an upstream proxy's URL may have.
const UPSTREAM_SCHEME: &str = "http";
/// The separator between a host and its port, and between a user and a password.
///
/// https://www.rfc-editor.org/rfc/rfc7617#section-2
const COLON: &str = ":";
/// The faults an upstream proxy's URL can have.
const NOT_UTF8: &str = "not UTF-8";
const NOT_HTTP: &str = "only http:// proxies are supported";
const NO_HOST: &str = "no host";
const NO_PORT: &str = "no port";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = match arguments.as_slice() {
        [] => serve(),
        [command] if command == TRUST_COMMAND => trust(),
        _ => {
            eprintln!(
                "usage: {PROGRAM}          serve on an ephemeral port, writing every request and response to stdout as JSON lines\n       \
                 {PROGRAM} {TRUST_COMMAND}    add the root certificate to your trust store\n\n\
                 The first line on stdout is the listening event with the proxy's address.\n\
                 Set {UPSTREAM_VARIABLE}=http://[user:password@]host:port to go out through another HTTP proxy."
            );
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(fault) if fault.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(fault) => {
            eprintln!("{PROGRAM}: {fault}");
            ExitCode::FAILURE
        }
    }
}

/// Serves on an ephemeral port until standard output closes, warning first if the root is not trusted.
fn serve() -> std::io::Result<()> {
    let signer = RcgenAuthority.open(&data_folder()?)?;
    if !is_root_trusted(&signer) {
        eprintln!("{PROGRAM}: the root certificate is not trusted yet; run `{PROGRAM} {TRUST_COMMAND}` once");
    }
    let listener = TokioProxy.bind(signer, NdJson, upstream_proxy()?)?;
    eprintln!("proxy started at http://{}", listener.local_address());
    listener.serve()
}

/// Adds the root certificate to the user's trust store, making it first if there is none.
fn trust() -> std::io::Result<()> {
    let folder = data_folder()?;
    let signer = RcgenAuthority.open(&folder)?;
    match SystemTrust.add_trusted_root(&signer.root_certificate()) {
        Ok(Outcome::Trusted) => eprintln!("trusted the root certificate in {}", folder.display()),
        Ok(Outcome::AlreadyTrusted) => eprintln!("the root certificate in {} was trusted already", folder.display()),
        Err(fault) if fault.kind() == ErrorKind::PermissionDenied && cfg!(target_os = "linux") => {
            let program = std::env::current_exe()?;
            eprintln!("{fault}\nrun: sudo --preserve-env=HOME,XDG_DATA_HOME {} {TRUST_COMMAND}", program.display());
            return Err(fault);
        }
        Err(fault) => return Err(fault),
    }
    Ok(())
}

/// Returns the operating system's data folder for the program, where the authority is kept.
fn data_folder() -> std::io::Result<PathBuf> {
    directories::ProjectDirs::from("", "", PROGRAM)
        .map(|folders| folders.data_dir().to_path_buf())
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no home folder to keep the root certificate in"))
}

/// Returns the upstream proxy the variable names, with any credentials as basic authorization, or none if unset.
fn upstream_proxy() -> std::io::Result<Option<Upstream>> {
    let Some(value) = std::env::var_os(UPSTREAM_VARIABLE).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let invalid = |detail: &str| std::io::Error::new(ErrorKind::InvalidInput, format!("{UPSTREAM_VARIABLE}: {detail}"));
    let value = value.into_string().map_err(|_| invalid(NOT_UTF8))?;
    let url = url::Url::parse(&value).map_err(|fault| invalid(&fault.to_string()))?;
    if url.scheme() != UPSTREAM_SCHEME {
        return Err(invalid(NOT_HTTP));
    }
    let host = url.host_str().ok_or_else(|| invalid(NO_HOST))?;
    let port = url.port_or_known_default().ok_or_else(|| invalid(NO_PORT))?;
    let decode = |text: &str| percent_encoding::percent_decode_str(text).decode_utf8_lossy().into_owned();
    let authorization = (!url.username().is_empty()).then(|| {
        let credentials = [decode(url.username()), decode(url.password().unwrap_or_default())].join(COLON);
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(credentials))
    });
    Ok(Some(Upstream { address: [host, &port.to_string()].join(COLON), authorization }))
}

/// Returns whether the operating system trusts a certificate the signer issues, checked as clients check it.
fn is_root_trusted(signer: &RcgenSigner) -> bool {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let Ok(verifier) = rustls_platform_verifier::Verifier::new(provider) else { return false };
    let Ok(issued) = signer.issue_certificate(CHECKED_HOST) else { return false };
    let Some((host_certificate, _)) = issued.chain.split_first() else { return false };
    let Ok(name) = ServerName::try_from(CHECKED_HOST) else { return false };
    verifier
        .verify_server_cert(&CertificateDer::from(host_certificate.as_slice()), &[], &name, &[], UnixTime::now())
        .is_ok()
}
