//! A redirector through WinDivert, which sends the outbound packets of a job object's processes to a userspace stack speaking SOCKS5.
//!
//! WinDivert's socket layer names the process that opened each flow.
//!
//! httptap must run elevated; it carries WinDivert's DLL and driver and writes them beside itself. See README.md.

use std::net::SocketAddr;
use std::process::ExitStatus;

use simple_httptap_redirector::{Capture, Program, Redirector};

#[cfg(windows)]
mod capture;
#[cfg(windows)]
mod divert;
#[cfg(any(windows, test))]
mod packet;
#[cfg(windows)]
mod process;
#[cfg(any(windows, test))]
mod socks5;
#[cfg(any(windows, test))]
mod stack;
#[cfg(any(windows, test))]
mod table;

/// The redirector through WinDivert, which diverts the packets of the program's processes to the proxy.
#[derive(Debug)]
pub struct DivertRedirector;

impl Redirector for DivertRedirector {
    type Capture = DivertCapture;

    #[cfg(windows)]
    fn launch(&self, program: &Program, proxy: SocketAddr) -> std::io::Result<DivertCapture> {
        capture::launch(program, proxy).map(|running| DivertCapture { running })
    }

    #[cfg(not(windows))]
    fn launch(&self, _program: &Program, _proxy: SocketAddr) -> std::io::Result<DivertCapture> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "WinDivert redirects traffic only on Windows",
        ))
    }
}

/// A program started in a job object, with its processes' packets diverted until it exits.
#[derive(Debug)]
pub struct DivertCapture {
    #[cfg(windows)]
    running: capture::Running,
    #[cfg(not(windows))]
    running: std::convert::Infallible,
}

impl Capture for DivertCapture {
    #[cfg(windows)]
    fn id(&self) -> u32 {
        self.running.id()
    }

    #[cfg(windows)]
    fn wait(self) -> std::io::Result<ExitStatus> {
        self.running.wait()
    }

    #[cfg(not(windows))]
    fn id(&self) -> u32 {
        match self.running {}
    }

    #[cfg(not(windows))]
    fn wait(self) -> std::io::Result<ExitStatus> {
        match self.running {}
    }
}
