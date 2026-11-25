//! A redirector through the httptap app's network extension, which hands the program's flows to the proxy; for now it redirects nothing.

use std::net::SocketAddr;
use std::process::ExitStatus;

use simple_httptap_redirector::{Capture, Program, Redirector};

/// The redirector through the httptap app's network extension, which hands the program's flows to the proxy.
#[derive(Debug)]
pub struct ExtensionRedirector;

impl Redirector for ExtensionRedirector {
    type Capture = ExtensionCapture;

    fn launch(&self, _program: &Program, _proxy: SocketAddr) -> std::io::Result<ExtensionCapture> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "not written yet"))
    }
}

/// A program started with its traffic redirected.
#[derive(Debug)]
pub struct ExtensionCapture {
    child: std::process::Child,
}

impl Capture for ExtensionCapture {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }
}
