//! A redirector through WinDivert, which diverts the packets of the program's processes to the proxy; for now it redirects nothing.

use std::net::SocketAddr;
use std::process::ExitStatus;

use simple_httptap_redirector::{Capture, Program, Redirector};

/// The redirector through WinDivert, which diverts the packets of the program's processes to the proxy.
#[derive(Debug)]
pub struct DivertRedirector;

impl Redirector for DivertRedirector {
    type Capture = DivertCapture;

    fn launch(&self, _program: &Program, _proxy: SocketAddr) -> std::io::Result<DivertCapture> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "not written yet"))
    }
}

/// A program started with its traffic redirected.
#[derive(Debug)]
pub struct DivertCapture {
    child: std::process::Child,
}

impl Capture for DivertCapture {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }
}
