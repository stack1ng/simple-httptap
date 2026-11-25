//! A way to send one program's TCP and UDP traffic, and that of every process it starts, through a SOCKS5 proxy.
//!
//! The program is not told: it connects as it always does, so a browser keeps HTTP/3, which no proxy setting carries.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::process::ExitStatus;

/// A way of redirecting the traffic of the programs it starts.
pub trait Redirector {
    /// A started program whose traffic goes through the proxy.
    type Capture: Capture;

    /// Starts the program with its traffic, and its descendants', going through the SOCKS5 proxy at the address.
    ///
    /// An error of kind `Unsupported` means this system cannot redirect, and says what it lacks.
    fn launch(&self, program: &Program, proxy: SocketAddr) -> std::io::Result<Self::Capture>;
}

/// A program started with its traffic redirected.
pub trait Capture: Send + 'static {
    /// Returns the started process's identifier.
    fn id(&self) -> u32;

    /// Waits for the started process to exit, stops redirecting, and returns how it exited.
    fn wait(self) -> std::io::Result<ExitStatus>;
}

/// A program to start: its path or name, found on `PATH` as a shell would, and its arguments.
///
/// `environment` holds the variables to set on top of this process's, or to remove where the value is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub path: OsString,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, Option<OsString>)>,
}
