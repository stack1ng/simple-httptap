//! The `httptap` program: runs a program with its traffic sent through a proxy that writes what it sees to standard output.
//!
//! With `SSLKEYLOGFILE` set, the program logs its own TLS and QUIC secrets there and every byte passes untouched;
//! without it, the proxy ends TLS itself and logs its own. `httptap trust` adds the root to the user's trust store.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use simple_httptap_authority::{Authority, Signer};
use simple_httptap_authority_rcgen::{RcgenAuthority, RcgenSigner};
use simple_httptap_keylog::Keylog;
use simple_httptap_keylog_file::FileKeylog;
use simple_httptap_proxy::{Credentials, Listener, Mode, Proxy, Upstream};
use simple_httptap_proxy_tokio::TokioProxy;
use simple_httptap_redirector::{Capture, Program, Redirector};
use simple_httptap_sink_ndjson::NdJson;
use simple_httptap_trust::{Outcome, Trust};
use simple_httptap_trust_system::SystemTrust;
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};

#[cfg(target_os = "linux")]
use simple_httptap_redirector_linux::NamespaceRedirector as SystemRedirector;
#[cfg(target_os = "macos")]
use simple_httptap_redirector_macos::ExtensionRedirector as SystemRedirector;
#[cfg(windows)]
use simple_httptap_redirector_windows::DivertRedirector as SystemRedirector;

/// The command's name.
const PROGRAM: &str = "httptap";
/// The name of the data folder that keeps the root certificate, the project's name.
const DATA_FOLDER: &str = "simple-httptap";
/// The command that adds the root certificate to the user's trust store.
const TRUST_COMMAND: &str = "trust";
/// The argument that may come before the program, so a program named like a command still runs.
const END_OF_OPTIONS: &str = "--";
/// The variable naming the key log a program writes its TLS and QUIC secrets to, which NSS, BoringSSL and OpenSSL read.
const KEYLOG_VARIABLE: &str = "SSLKEYLOGFILE";
/// The variable with the upstream SOCKS5 proxy, as `socks5://[user:password@]host:port`.
const UPSTREAM_VARIABLE: &str = "HTTPTAP_UPSTREAM_PROXY";
/// The schemes an upstream proxy's URL may have; `socks5h` is the same, as names always go to the proxy.
const UPSTREAM_SCHEMES: &[&str] = &["socks5", "socks5h"];
/// The port of a SOCKS5 proxy whose URL names none.
///
/// https://www.rfc-editor.org/rfc/rfc1928#section-3
const SOCKS_PORT: u16 = 1080;
/// The separator between a host and its port.
const COLON: &str = ":";
/// The name of the key log the proxy writes when it intercepts, in the system's temporary folder.
const OWN_KEYLOG_PREFIX: &str = "httptap-keys-";
/// The end of the proxy's own key log name, after the process ID, which marks the file as a log.
const KEYLOG_EXTENSION: &str = ".log";
/// How long the proxy keeps writing after the program exited, for the last bytes of its connections.
///
/// https://doc.rust-lang.org/std/thread/fn.sleep.html
const DRAIN: Duration = Duration::from_millis(500);
/// The exit code of a program a signal ended, before the signal's number is added, as shells report it.
///
/// https://www.gnu.org/software/bash/manual/html_node/Exit-Status.html
const SIGNALLED: i32 = 128;
/// The host the startup check asks the system to trust a certificate for.
const CHECKED_HOST: &str = "localhost";
/// The program that runs a command as root after asking for the person's password.
const SUDO: &str = "sudo";
/// The `sudo` option that keeps the variables the data folder is found by, so root opens the same authority.
const SUDO_KEEPING_FOLDERS: &[&str] = &["--preserve-env=HOME,XDG_DATA_HOME"];
/// The variable `sudo` sets in the command it runs, which stops a second round of asking.
const SUDO_MARKER: &str = "SUDO_UID";
/// The error when the store took the root but a host certificate still fails verification.
const NOT_TRUSTED_AFTER_ADDING: &str = "the root was added, but the system still does not trust its certificates";
/// The faults an upstream proxy's URL can have.
const NOT_UTF8: &str = "not UTF-8";
const NOT_SOCKS: &str = "only socks5:// proxies are supported";
const NO_HOST: &str = "no host";

/// The start of the help printed for a call without a program, before the end-of-options argument.
const USAGE_START: &str = "usage: httptap [";
/// The help's commands and its text up to the key log variable.
const USAGE_COMMANDS: &str =
    "] <program> [arguments...]   run the program, writing every request and response it makes to stdout as JSON lines
       httptap trust                            add the root certificate to your trust store, for when httptap intercepts

All the program's TCP and UDP traffic, and its children's, goes through httptap, so HTTP/3 is seen too.
With ";
/// The help's text from the key log variable to the upstream variable.
const USAGE_KEYLOG: &str = " set, the program logs its own TLS secrets there (Chrome, Firefox, curl, Python, Node with
--tls-keylog do) and httptap decrypts its traffic without touching it. Without it, httptap intercepts TLS with its
own root certificate, which the program must trust, and the server sees httptap's TLS instead of the program's.
Set ";
/// The help's text after the upstream variable.
const USAGE_UPSTREAM: &str = "=socks5://[user:password@]host:port to go out through another SOCKS5 proxy.";

fn main() -> ExitCode {
    let mut arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.first().and_then(|first| first.to_str()) {
        None => {
            print_usage();
            return ExitCode::FAILURE;
        }
        Some(TRUST_COMMAND) if arguments.len() == 1 => trust().map(|()| ExitCode::SUCCESS),
        Some(END_OF_OPTIONS) => {
            arguments.remove(usize::MIN);
            if arguments.is_empty() {
                print_usage();
                return ExitCode::FAILURE;
            }
            run(arguments)
        }
        Some(_) => run(arguments),
    };
    match result {
        Ok(code) => code,
        Err(fault) if fault.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(fault) => {
            eprintln!("{PROGRAM}: {fault}");
            ExitCode::FAILURE
        }
    }
}

/// Prints the help to standard error.
fn print_usage() {
    eprintln!("{USAGE_START}{END_OF_OPTIONS}{USAGE_COMMANDS}{KEYLOG_VARIABLE}{USAGE_KEYLOG}{UPSTREAM_VARIABLE}{USAGE_UPSTREAM}");
}

/// Runs the program with its traffic through the proxy until it exits, then exits as it did.
fn run(mut arguments: Vec<OsString>) -> std::io::Result<ExitCode> {
    let path = arguments.remove(usize::MIN);
    let (mode, keylog) = match std::env::var_os(KEYLOG_VARIABLE).filter(|value| !value.is_empty()) {
        Some(file) => (Mode::PassThrough, PathBuf::from(file)),
        None => (Mode::Intercept, create_own_keylog()?),
    };
    let keys = FileKeylog.open(&keylog)?;
    let signer = RcgenAuthority.open(&data_folder()?)?;
    match mode {
        Mode::PassThrough => eprintln!("{PROGRAM}: reading the program's secrets from {}; its traffic passes untouched", keylog.display()),
        Mode::Intercept => {
            eprintln!("{PROGRAM}: {KEYLOG_VARIABLE} is not set, so httptap intercepts TLS and logs its secrets to {}", keylog.display());
            if !is_root_trusted(&signer) {
                eprintln!("{PROGRAM}: the root certificate is not trusted yet; run `{PROGRAM} {TRUST_COMMAND}` once");
            }
        }
    }
    let listener = TokioProxy.bind(signer, NdJson, keys, mode, upstream_proxy()?)?;
    let address = listener.local_address();
    std::thread::spawn(move || {
        match listener.serve() {
            Err(fault) if fault.kind() != ErrorKind::BrokenPipe => eprintln!("{PROGRAM}: {fault}"),
            _ => {}
        }
        std::process::exit(i32::from(u8::MIN));
    });
    let program = Program { path, arguments, environment: Vec::new() };
    let capture = SystemRedirector.launch(&program, address)?;
    let status = capture.wait()?;
    std::thread::sleep(DRAIN);
    Ok(ExitCode::from(exit_code(status)))
}

/// Returns the exit code that tells how the program exited, 128 plus the signal for one a signal ended.
fn exit_code(status: std::process::ExitStatus) -> u8 {
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    let code = status.code().or(signal.map(|signal| SIGNALLED + signal)).unwrap_or(i32::from(u8::MAX));
    u8::try_from(code).unwrap_or(u8::MAX)
}

/// Makes the key log the proxy writes when it intercepts, readable only by its owner, and returns its path.
fn create_own_keylog() -> std::io::Result<PathBuf> {
    let file = std::env::temp_dir().join(format!("{OWN_KEYLOG_PREFIX}{}{KEYLOG_EXTENSION}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, OWNER_ONLY);
    options.open(&file)?;
    Ok(file)
}

/// The permissions of a file only its owner may read and write.
///
/// https://doc.rust-lang.org/std/os/unix/fs/trait.OpenOptionsExt.html#tymethod.mode
#[cfg(unix)]
const OWNER_ONLY: u32 = 0o600;

/// Adds the root certificate to the system's trust store unless TLS clients trust it already, then checks they do.
fn trust() -> std::io::Result<()> {
    let folder = data_folder()?;
    let signer = RcgenAuthority.open(&folder)?;
    if is_root_trusted(&signer) {
        eprintln!("the root certificate in {} is trusted already", folder.display());
        return Ok(());
    }
    match SystemTrust.add_trusted_root(&signer.root_certificate()) {
        Ok(_) if !is_root_trusted(&signer) => {
            return Err(std::io::Error::other(NOT_TRUSTED_AFTER_ADDING));
        }
        Ok(Outcome::Trusted) => eprintln!("trusted the root certificate in {}; restart browsers that were open", folder.display()),
        Ok(Outcome::AlreadyTrusted) => eprintln!("the root certificate in {} was trusted already", folder.display()),
        Err(fault)
            if fault.kind() == ErrorKind::PermissionDenied && cfg!(target_os = "linux") && std::env::var_os(SUDO_MARKER).is_none() =>
        {
            eprintln!("{PROGRAM}: the system trust store needs root, so this asks sudo");
            let status =
                std::process::Command::new(SUDO).args(SUDO_KEEPING_FOLDERS).arg(std::env::current_exe()?).arg(TRUST_COMMAND).status()?;
            if !status.success() {
                return Err(std::io::Error::new(ErrorKind::PermissionDenied, format!("{SUDO} {TRUST_COMMAND} failed with {status}")));
            }
        }
        Err(fault) => return Err(fault),
    }
    Ok(())
}

/// Returns the operating system's data folder for the program, where the authority is kept.
fn data_folder() -> std::io::Result<PathBuf> {
    directories::ProjectDirs::from("", "", DATA_FOLDER)
        .map(|folders| folders.data_dir().to_path_buf())
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no home folder to keep the root certificate in"))
}

/// Returns the upstream SOCKS5 proxy the variable names, with any credentials, or none if unset.
fn upstream_proxy() -> std::io::Result<Option<Upstream>> {
    let Some(value) = std::env::var_os(UPSTREAM_VARIABLE).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let invalid = |detail: &str| std::io::Error::new(ErrorKind::InvalidInput, format!("{UPSTREAM_VARIABLE}: {detail}"));
    let value = value.into_string().map_err(|_| invalid(NOT_UTF8))?;
    let url = url::Url::parse(&value).map_err(|fault| invalid(&fault.to_string()))?;
    if !UPSTREAM_SCHEMES.contains(&url.scheme()) {
        return Err(invalid(NOT_SOCKS));
    }
    let host = url.host_str().ok_or_else(|| invalid(NO_HOST))?;
    let port = url.port().unwrap_or(SOCKS_PORT);
    let decode = |text: &str| percent_encoding::percent_decode_str(text).decode_utf8_lossy().into_owned();
    let credentials = (!url.username().is_empty())
        .then(|| Credentials { user: decode(url.username()), password: decode(url.password().unwrap_or_default()) });
    Ok(Some(Upstream { address: [host, &port.to_string()].join(COLON), credentials }))
}

/// Returns whether the operating system trusts a certificate the signer issues, checked as clients check it.
fn is_root_trusted(signer: &RcgenSigner) -> bool {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let Ok(verifier) = rustls_platform_verifier::Verifier::new(provider) else {
        return false;
    };
    let Ok(issued) = signer.issue_certificate(CHECKED_HOST) else {
        return false;
    };
    let Some((host_certificate, _)) = issued.chain.split_first() else {
        return false;
    };
    let Ok(name) = ServerName::try_from(CHECKED_HOST) else {
        return false;
    };
    verifier.verify_server_cert(&CertificateDer::from(host_certificate.as_slice()), &[], &name, &[], UnixTime::now()).is_ok()
}
