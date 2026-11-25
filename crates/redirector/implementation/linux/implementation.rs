//! A redirector through a user and network namespace whose only route is a TUN device this process reads; for now it redirects nothing.

use std::net::SocketAddr;
use std::process::ExitStatus;

use simple_httptap_redirector::{Capture, Program, Redirector};

/// The redirector through a user and network namespace whose only route is a TUN device this process reads.
#[derive(Debug)]
pub struct NamespaceRedirector;

impl Redirector for NamespaceRedirector {
    type Capture = NamespaceCapture;

    fn launch(&self, _program: &Program, _proxy: SocketAddr) -> std::io::Result<NamespaceCapture> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "not written yet"))
    }
}

/// A program started with its traffic redirected.
#[derive(Debug)]
pub struct NamespaceCapture {
    child: std::process::Child,
}

impl Capture for NamespaceCapture {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }
}
