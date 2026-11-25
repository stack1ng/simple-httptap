//! Sending a program tree's TCP and UDP through a SOCKS5 proxy.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::process::ExitStatus;

/// A launcher of redirected programs.
pub trait Redirector {
    type Capture: Capture;

    /// Starts the program, sending its and its descendants' traffic through the SOCKS5 proxy at the address.
    ///
    /// Its stdout goes to our stderr; stdin and stderr are ours. `Unsupported` errors say what we lack.
    fn launch(&self, program: &Program, proxy: SocketAddr) -> std::io::Result<Self::Capture>;
}

/// A running redirected program.
pub trait Capture: Send + 'static {
    fn id(&self) -> u32;

    /// Waits for the exit, stops redirecting, and returns the status.
    ///
    /// Never silent: if redirecting breaks first, it kills the program tree and errs; if we die, so does the tree.
    fn wait(self) -> std::io::Result<ExitStatus>;
}

/// A program to start, found on `PATH` as a shell would, with its arguments.
///
/// `environment` sets variables over ours, removing `None` ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub path: OsString,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, Option<OsString>)>,
}
