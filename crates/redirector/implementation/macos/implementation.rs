//! A redirector through the httptap app's network extension, which hands the flows of a program's processes to the proxy.
//!
//! The extension keeps a control socket; each capture registers the program's process there, and the extension sends
//! every TCP and UDP flow of that process and its descendants to the proxy over SOCKS5. The program starts suspended
//! and runs only once it is registered, so none of its traffic goes past the proxy.

use std::net::SocketAddr;
use std::process::ExitStatus;

use simple_httptap_redirector::{Capture, Program, Redirector};

/// The redirector through the httptap app's network extension.
#[derive(Debug)]
pub struct ExtensionRedirector;

impl Redirector for ExtensionRedirector {
    type Capture = ExtensionCapture;

    fn launch(&self, program: &Program, proxy: SocketAddr) -> std::io::Result<ExtensionCapture> {
        #[cfg(target_os = "macos")]
        {
            macos::launch(program, proxy)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (program, proxy);
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "the network extension redirector runs only on macOS"))
        }
    }
}

/// A program started with its traffic going through the extension, and the registration that keeps it so.
#[derive(Debug)]
pub struct ExtensionCapture {
    pid: u32,
    #[cfg(target_os = "macos")]
    _control: std::os::unix::net::UnixStream,
}

impl Capture for ExtensionCapture {
    fn id(&self) -> u32 {
        self.pid
    }

    fn wait(self) -> std::io::Result<ExitStatus> {
        #[cfg(target_os = "macos")]
        {
            macos::wait(self.pid)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "the network extension redirector runs only on macOS"))
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, OsStr, OsString};
    use std::io::{BufRead, BufReader, ErrorKind, Write};
    use std::net::SocketAddr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::{Command, ExitStatus};
    use std::time::{Duration, Instant};

    use simple_httptap_redirector::Program;

    use super::ExtensionCapture;

    /// The extension's control socket, where each capture registers its program.
    const CONTROL_SOCKET: &str = "/var/run/com.stack1ng.simplehttptap.redirector.sock";
    /// The line the extension greets each client with: the protocol and the version this crate speaks.
    const GREETING: &str = "httptap-redirector 1";
    /// The answer to a registration the extension accepted.
    const ACCEPTED: &str = "ok";
    /// Where the app that installs the extension must be, as macOS installs system extensions only from there.
    const APP: &str = "/Applications/httptap.app";
    /// The app's executable inside its bundle.
    const APP_EXECUTABLE: &str = "Contents/MacOS/httptap";
    /// The argument that tells the app to install the extension and start the proxy.
    const ACTIVATE: &str = "--activate";
    /// How long the extension may take to answer once the app started it, approval in System Settings included.
    const START_WAIT: Duration = Duration::from_secs(120);
    /// How long the control socket is tried after the app failed, in case another httptap started the extension.
    const RACE_WAIT: Duration = Duration::from_secs(5);
    /// How often the control socket is tried while the extension starts.
    const START_POLL: Duration = Duration::from_millis(100);
    /// The flag of Apple's `posix_spawn` that starts the process stopped.
    const POSIX_SPAWN_START_SUSPENDED: libc::c_short = 0x0080;

    /// Registers the program with the extension, starting the extension first if it is not running, then runs it.
    pub(super) fn launch(program: &Program, proxy: SocketAddr) -> std::io::Result<ExtensionCapture> {
        let mut control = connect_control()?;
        let pid = spawn_suspended(program)?;
        let registered = register(&mut control, proxy, pid);
        if let Err(fault) = registered {
            // SAFETY: the process was started by this process and is stopped, so killing it is all that happens.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait(u32::try_from(pid).unwrap_or_default());
            return Err(fault);
        }
        // SAFETY: the process was started stopped by this process; this lets it run.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        Ok(ExtensionCapture { pid: u32::try_from(pid).unwrap_or_default(), _control: control })
    }

    /// Connects to the extension's control socket and checks its greeting, starting the extension if it does not answer.
    ///
    /// Another httptap may be starting the extension at the same time, so the socket is what counts, not the app's
    /// exit status, which only names the cause when the socket never answers.
    fn connect_control() -> std::io::Result<UnixStream> {
        if let Ok(stream) = UnixStream::connect(CONTROL_SOCKET) {
            return greeted(stream);
        }
        let started = start_extension();
        let wait = if started.is_ok() { START_WAIT } else { RACE_WAIT };
        let since = Instant::now();
        loop {
            match UnixStream::connect(CONTROL_SOCKET) {
                Ok(stream) => return greeted(stream),
                Err(fault) if since.elapsed() > wait => {
                    let cause = started.err().map_or_else(|| fault.to_string(), |cause| cause.to_string());
                    return Err(std::io::Error::new(ErrorKind::Unsupported, format!("the httptap network extension did not start: {cause}")));
                }
                Err(_) => std::thread::sleep(START_POLL),
            }
        }
    }

    /// Returns the stream once the extension greeted it with the protocol version this crate speaks.
    fn greeted(stream: UnixStream) -> std::io::Result<UnixStream> {
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        if line.trim_end() != GREETING {
            return Err(std::io::Error::new(
                ErrorKind::Unsupported,
                format!("the installed httptap network extension speaks {:?}, not {GREETING:?}; install the httptap.app that came with this httptap", line.trim_end()),
            ));
        }
        Ok(stream)
    }

    /// Runs the app, which installs the extension if needed and starts the proxy, and waits for it.
    fn start_extension() -> std::io::Result<()> {
        let app = Path::new(APP);
        if !app.exists() {
            super::embedded::install(app)?;
        }
        let status = Command::new(app.join(APP_EXECUTABLE)).arg(ACTIVATE).status()?;
        if !status.success() {
            return Err(std::io::Error::new(ErrorKind::Unsupported, format!("{APP} could not start the network extension ({status})")));
        }
        Ok(())
    }

    /// Asks the extension to send the process's flows, and its descendants', to the proxy.
    fn register(control: &mut UnixStream, proxy: SocketAddr, pid: libc::pid_t) -> std::io::Result<()> {
        writeln!(control, "intercept {} {} {pid}", proxy.ip(), proxy.port())?;
        let mut answer = String::new();
        BufReader::new(&*control).read_line(&mut answer)?;
        if answer.trim_end() == ACCEPTED {
            return Ok(());
        }
        Err(std::io::Error::new(ErrorKind::PermissionDenied, format!("the network extension refused: {}", answer.trim_end())))
    }

    /// Starts the program stopped, found on `PATH`, with its environment changes, and returns its process identifier.
    fn spawn_suspended(program: &Program) -> std::io::Result<libc::pid_t> {
        let path = c_string(&program.path)?;
        let mut arguments = vec![path.clone()];
        for argument in &program.arguments {
            arguments.push(c_string(argument)?);
        }
        let mut environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        for (name, value) in &program.environment {
            environment.retain(|(existing, _)| existing != name);
            if let Some(value) = value {
                environment.push((name.clone(), value.clone()));
            }
        }
        let environment: Vec<CString> = environment
            .into_iter()
            .map(|(name, value)| {
                let mut pair = name;
                pair.push("=");
                pair.push(value);
                c_string(&pair)
            })
            .collect::<std::io::Result<_>>()?;
        let mut argv: Vec<*mut libc::c_char> = arguments.iter().map(|argument| argument.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        let mut envp: Vec<*mut libc::c_char> = environment.iter().map(|pair| pair.as_ptr().cast_mut()).collect();
        envp.push(std::ptr::null_mut());
        let mut pid: libc::pid_t = 0;
        // SAFETY: the attributes are initialised before use and destroyed after; every pointer passed points into a
        // CString or a null-terminated array that lives until posix_spawnp returns.
        let spawned = unsafe {
            let mut attributes: libc::posix_spawnattr_t = std::ptr::null_mut();
            let initialised = libc::posix_spawnattr_init(&mut attributes);
            if initialised != 0 {
                return Err(std::io::Error::from_raw_os_error(initialised));
            }
            libc::posix_spawnattr_setflags(&mut attributes, POSIX_SPAWN_START_SUSPENDED);
            let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
            libc::posix_spawn_file_actions_init(&mut actions);
            libc::posix_spawn_file_actions_adddup2(&mut actions, libc::STDERR_FILENO, libc::STDOUT_FILENO);
            let spawned = libc::posix_spawnp(&mut pid, path.as_ptr(), &actions, &attributes, argv.as_ptr(), envp.as_ptr());
            libc::posix_spawn_file_actions_destroy(&mut actions);
            libc::posix_spawnattr_destroy(&mut attributes);
            spawned
        };
        if spawned != 0 {
            let fault = std::io::Error::from_raw_os_error(spawned);
            return Err(std::io::Error::new(fault.kind(), format!("starting {}: {fault}", program.path.to_string_lossy())));
        }
        Ok(pid)
    }

    /// Returns the text as a C string, or an error if it holds a NUL byte.
    fn c_string(text: &OsStr) -> std::io::Result<CString> {
        CString::new(text.as_bytes()).map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, format!("{text:?} holds a NUL byte")))
    }

    /// Waits for the process to exit and returns how it did.
    pub(super) fn wait(pid: u32) -> std::io::Result<ExitStatus> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "no such process"))?;
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: status points to a live integer; the process is this process's child.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                return Ok(ExitStatus::from_raw(status));
            }
            let fault = std::io::Error::last_os_error();
            if fault.kind() != ErrorKind::Interrupted {
                return Err(fault);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod embedded {
    use std::io::ErrorKind;
    use std::path::Path;

    /// The notarized httptap.app, zipped, when the build was given one in `HTTPTAP_REDIRECTOR_APP_ZIP`.
    #[cfg(httptap_embedded_app)]
    const APP_ZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/httptap-app.zip"));

    /// Unpacks the app this build carries into the folder macOS installs system extensions from.
    pub(super) fn install(app: &Path) -> std::io::Result<()> {
        #[cfg(httptap_embedded_app)]
        {
            let folder = app.parent().ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no Applications folder"))?;
            let zip = std::env::temp_dir().join(format!("httptap-app-{}.zip", std::process::id()));
            std::fs::write(&zip, APP_ZIP)?;
            let status = std::process::Command::new("/usr/bin/ditto").arg("-x").arg("-k").arg(&zip).arg(folder).status();
            let _ = std::fs::remove_file(&zip);
            if status?.success() && app.exists() {
                return Ok(());
            }
            Err(std::io::Error::new(ErrorKind::PermissionDenied, format!("could not unpack httptap.app into {}", folder.display())))
        }
        #[cfg(not(httptap_embedded_app))]
        {
            Err(std::io::Error::new(
                ErrorKind::Unsupported,
                format!("{} is not installed, and this build of httptap does not carry it; build it from crates/redirector/implementation/macos/extension", app.display()),
            ))
        }
    }
}
