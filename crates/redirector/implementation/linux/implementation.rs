//! A redirector that starts the program in new namespaces whose only route is a TUN device, needing no privilege if allowed.
//!
//! A userspace stack on the device sends each TCP connection through a SOCKS5 CONNECT and each UDP source through an
//! ASSOCIATE. Loopback name servers, which the namespace cannot reach, get stand-in addresses the stack maps back.

#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod socks;
#[cfg(target_os = "linux")]
mod stack;

use std::net::SocketAddr;
use std::process::{Child, ExitStatus};

use simple_httptap_redirector::{Capture, Program, Redirector};

/// A redirector that gives each program a network namespace of its own, with a TUN device as its only way out.
#[derive(Debug)]
pub struct NamespaceRedirector;

impl Redirector for NamespaceRedirector {
    type Capture = NamespaceCapture;

    #[cfg(target_os = "linux")]
    fn launch(&self, program: &Program, proxy: SocketAddr) -> std::io::Result<NamespaceCapture> {
        let namespace::Started {
            mut child,
            tun,
            names,
        } = namespace::start(program)?;
        match Stack::start(tun, proxy, names, child.id()) {
            Ok(stack) => Ok(NamespaceCapture { child, stack }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn launch(&self, _program: &Program, _proxy: SocketAddr) -> std::io::Result<NamespaceCapture> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the namespace redirector needs Linux's network namespaces and TUN devices",
        ))
    }
}

/// A started program with the stack that carries its traffic until it exits.
#[derive(Debug)]
pub struct NamespaceCapture {
    child: Child,
    #[cfg(target_os = "linux")]
    stack: Stack,
}

impl Capture for NamespaceCapture {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait();
        // The program's descendants still running lose the network.
        #[cfg(target_os = "linux")]
        {
            self.stack.stop();
            if let Some(cause) = self.stack.lost() {
                return Err(std::io::Error::other(cause));
            }
        }
        status
    }
}

/// The stack's thread and the sender that stops it, which it does when dropped.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Stack {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Why the stack ended on its own while the program ran, if it did.
    lost: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

#[cfg(target_os = "linux")]
impl Stack {
    /// Starts the stack on the TUN device on a thread of its own, with a runtime of its own.
    fn start(
        tun: std::os::fd::OwnedFd,
        proxy: SocketAddr,
        names: stack::NameServers,
        program: u32,
    ) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let tun = {
            let _entered = runtime.enter();
            // SAFETY: the file owns the descriptor, which stays open and the same while the AsyncFd holds the file.
            unsafe { tokio::io::unix::AsyncFd::register(std::fs::File::from(tun)) }?
        };
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let lost = std::sync::Arc::new(std::sync::Mutex::new(None));
        let thread_lost = std::sync::Arc::clone(&lost);
        let thread = std::thread::Builder::new()
            .name(STACK_THREAD.into())
            .spawn(move || {
                runtime.block_on(stack::serve(tun, proxy, names, &mut stopped));
                // Ending without being asked loses the program's network: it is stopped, and `wait` says why.
                if stopped.try_recv() == Err(tokio::sync::oneshot::error::TryRecvError::Empty) {
                    if let Ok(mut lost) = thread_lost.lock() {
                        *lost = Some(STACK_LOST.to_owned());
                    }
                    if let Ok(program) = libc::pid_t::try_from(program) {
                        // SAFETY: sending a signal has no memory effects; the process is this process's child.
                        unsafe { libc::kill(program, libc::SIGKILL) };
                    }
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
            lost,
        })
    }

    /// Returns why the stack ended while the program ran, if it did.
    fn lost(&self) -> Option<String> {
        self.lost.lock().ok().and_then(|lost| lost.clone())
    }

    /// Stops the stack, dropping every connection, and waits for its thread to end.
    fn stop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The error of a capture whose stack ended while the program ran.
#[cfg(target_os = "linux")]
const STACK_LOST: &str = "the network stack carrying the program's traffic stopped; httptap stopped the program, whose namespace had no network left";
/// The name of the stack's thread, which runs its runtime.
#[cfg(target_os = "linux")]
const STACK_THREAD: &str = "httptap-redirector";

#[cfg(target_os = "linux")]
impl Drop for Stack {
    fn drop(&mut self) {
        self.stop();
    }
}
