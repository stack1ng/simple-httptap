//! A redirector through the httptap app's network extension, which hands the flows of a program's processes to the proxy.
//!
//! Each capture registers a suspended program on the extension's control socket, then lets it run, so the extension
//! sends all its and its descendants' TCP and UDP to the proxy.

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

/// The handle to a program whose traffic goes through the extension, holding the registration that keeps it so.
#[derive(Debug)]
pub struct ExtensionCapture {
    pid: u32,
    #[cfg(target_os = "macos")]
    watch: macos::Watch,
}

impl Capture for ExtensionCapture {
    fn id(&self) -> u32 {
        self.pid
    }

    fn wait(self) -> std::io::Result<ExitStatus> {
        #[cfg(target_os = "macos")]
        {
            macos::finish(self.pid, self.watch)
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};

    use simple_httptap_redirector::Program;

    use super::ExtensionCapture;

    /// The extension's control socket, where each capture registers its program.
    const CONTROL_SOCKET: &str = "/var/run/com.stack1ng.simplehttptap.redirector.sock";
    /// The line the extension greets each client with: the protocol and the version this crate speaks.
    const GREETING: &str = "httptap-redirector 2";
    /// The answer to a registration the extension accepted.
    const ACCEPTED: &str = "ok";
    /// Where the app that installs the extension must be, as macOS installs system extensions only from there.
    const APP: &str = "/Applications/httptap.app";
    /// The app's executable inside its bundle.
    const APP_EXECUTABLE: &str = "Contents/MacOS/httptap";
    /// The argument that tells the app to install the extension and start the proxy.
    const ACTIVATE: &str = "--activate";
    /// How long the extension may take to answer once the app started it, approval in System Settings included.
    ///
    /// https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers
    const START_WAIT: Duration = Duration::from_secs(120);
    /// How long the control socket is tried after the app failed, in case another httptap started the extension.
    ///
    /// https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html#method.connect
    const RACE_WAIT: Duration = Duration::from_secs(5);
    /// How long to sleep between tries of the control socket while the extension starts.
    ///
    /// https://doc.rust-lang.org/std/thread/fn.sleep.html
    const START_POLL: Duration = Duration::from_millis(100);
    /// Why capture was lost when the extension closed the connection without an error.
    const CLOSED: &str = "it closed the connection";
    /// The error `finish` returns when the extension never answered `END` within `END_WAIT`, as when it stopped meanwhile.
    const UNCONFIRMED: &str = "the network extension did not confirm the capture ended; processes the program left running may have gone uncaptured";
    /// The size and flavor argument of a `proc_*` call that asks only for a count, or for the default flavor.
    ///
    /// https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/wrappers/libproc/libproc.h
    const NOTHING: libc::c_int = 0;
    /// The line that asks the extension to stop what remains of the program once it exited.
    const END: &str = "end";
    /// The start of the extension's answer to `END`, which the identifiers of the processes it stopped follow.
    const ENDED: &str = "ended";
    /// The start of a line saying a flow of the program could not reach the proxy, which the reason follows.
    const FLOW_FAILED: &str = "flow-failed ";
    /// How long the extension may take to answer `END`.
    ///
    /// https://doc.rust-lang.org/std/sync/mpsc/struct.Receiver.html#method.recv_timeout
    const END_WAIT: Duration = Duration::from_secs(5);
    /// The process group `posix_spawn` makes the program lead: a new one, which its descendants keep when orphaned.
    ///
    /// https://pubs.opengroup.org/onlinepubs/9799919799/functions/posix_spawnattr_setpgroup.html
    const NEW_GROUP: libc::pid_t = 0;
    /// The most ancestors followed up from a process, which no real process tree reaches.
    ///
    /// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getppid.2.html
    const LINEAGE_LIMIT: usize = 64;
    /// The separator between a variable's name and value in an environment entry.
    const ENVIRONMENT_SEPARATOR: &str = "=";
    /// The `waitpid` options that block until the child exits, with no other behaviour.
    ///
    /// https://pubs.opengroup.org/onlinepubs/9799919799/functions/waitpid.html
    const WAIT_FOR_EXIT: libc::c_int = 0;

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
        let watch = Watch::start(control, pid)?;
        hand_terminal_to(pid);
        // SAFETY: the process was started stopped by this process; this lets it run.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        Ok(ExtensionCapture { pid: u32::try_from(pid).unwrap_or_default(), watch })
    }

    /// The watching of a registration: why capture was lost, if it was, and the extension's answers.
    #[derive(Debug)]
    pub(super) struct Watch {
        control: UnixStream,
        ending: Arc<AtomicBool>,
        lost: Arc<Mutex<Option<String>>>,
        answers: mpsc::Receiver<String>,
    }

    impl Watch {
        /// Starts a thread reading the extension's lines; the connection ending while the program runs stops its tree.
        ///
        /// Flow failures go to stderr and answers to `finish`, as the program's traffic would otherwise go uncaptured.
        fn start(control: UnixStream, pid: libc::pid_t) -> std::io::Result<Self> {
            let reader = control.try_clone()?;
            let ending = Arc::new(AtomicBool::new(false));
            let lost = Arc::new(Mutex::new(None));
            let (answer, answers) = mpsc::channel();
            let (thread_ending, thread_lost) = (Arc::clone(&ending), Arc::clone(&lost));
            std::thread::spawn(move || {
                let mut lines = BufReader::new(reader).lines();
                let cause = loop {
                    match lines.next() {
                        Some(Ok(line)) => match line.strip_prefix(FLOW_FAILED) {
                            Some(detail) => eprintln!("httptap: a flow of the program could not reach httptap, so it failed: {detail}"),
                            None => {
                                let _ = answer.send(line);
                            }
                        },
                        Some(Err(fault)) => break fault.to_string(),
                        None => break CLOSED.to_owned(),
                    }
                };
                if thread_ending.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(mut lost) = thread_lost.lock() {
                    *lost = Some(format!("the network extension stopped capturing the program ({cause}); httptap stopped the program so none of its traffic went uncaptured"));
                }
                stop_tree(pid);
            });
            Ok(Self { control, ending, lost, answers })
        }
    }

    /// Waits for the program, then has the extension stop what it left running; errs if capture was lost on the way.
    pub(super) fn finish(pid: u32, mut watch: Watch) -> std::io::Result<ExitStatus> {
        let status = wait(pid);
        take_terminal_back();
        let status = status?;
        let lost = || watch.lost.lock().ok().and_then(|lost| lost.clone());
        if let Some(cause) = lost() {
            return Err(std::io::Error::other(cause));
        }
        watch.ending.store(true, Ordering::SeqCst);
        let answered = writeln!(watch.control, "{END}").ok().and_then(|()| watch.answers.recv_timeout(END_WAIT).ok());
        let Some(answer) = answered.filter(|answer| answer.starts_with(ENDED)) else {
            let cause = lost().unwrap_or_else(|| UNCONFIRMED.to_owned());
            return Err(std::io::Error::other(cause));
        };
        let stopped = answer[ENDED.len()..].trim();
        if !stopped.is_empty() {
            eprintln!("httptap: the program left processes running whose traffic would have gone uncaptured, so they were stopped: {stopped}");
        }
        Ok(status)
    }

    /// Gives the program's group the terminal's foreground, if this process has it, so typing and Ctrl-C reach the program.
    fn hand_terminal_to(group: libc::pid_t) {
        // SAFETY: these calls only read and set the terminal's foreground group; SIGTTOU is ignored so this process
        // may set it while in the background.
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) == 1 && libc::tcgetpgrp(libc::STDIN_FILENO) == libc::getpgrp() {
                libc::signal(libc::SIGTTOU, libc::SIG_IGN);
                libc::tcsetpgrp(libc::STDIN_FILENO, group);
            }
        }
    }

    /// Makes this process's group the terminal's foreground again, if the terminal is still the program's.
    fn take_terminal_back() {
        // SAFETY: as in `hand_terminal_to`.
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) == 1 && libc::tcgetpgrp(libc::STDIN_FILENO) != libc::getpgrp() {
                libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp());
            }
        }
    }

    /// Stops, with SIGKILL, the process and every process descended from it.
    fn stop_tree(pid: libc::pid_t) {
        let doomed: Vec<libc::pid_t> = all_processes().into_iter().filter(|&other| lineage(other).contains(&pid)).collect();
        // SAFETY: sending signals has no memory effects; the group and the processes are the program's own.
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
            for other in doomed {
                libc::kill(other, libc::SIGKILL);
            }
        }
    }

    /// Returns the identifiers of every running process.
    fn all_processes() -> Vec<libc::pid_t> {
        // SAFETY: a null buffer asks only for the count.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), NOTHING) };
        let Ok(count) = usize::try_from(count) else { return Vec::new() };
        let mut pids = vec![libc::pid_t::default(); count * 2];
        let size = i32::try_from(pids.len() * size_of::<libc::pid_t>()).unwrap_or(i32::MAX);
        // SAFETY: the buffer holds `size` bytes, which is what is passed.
        let filled = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), size) };
        pids.truncate(usize::try_from(filled).unwrap_or_default());
        pids.retain(|&pid| pid > libc::pid_t::default());
        pids
    }

    /// Returns the process and its ancestors, nearest first, up to but not including launchd.
    fn lineage(pid: libc::pid_t) -> Vec<libc::pid_t> {
        let mut lineage = Vec::new();
        let mut current = pid;
        while current > 1 && lineage.len() < LINEAGE_LIMIT {
            lineage.push(current);
            // SAFETY: proc_bsdinfo is plain data, for which all zeroes is a valid value.
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            let size = i32::try_from(size_of::<libc::proc_bsdinfo>()).unwrap_or(i32::MAX);
            // SAFETY: info is a live proc_bsdinfo of `size` bytes.
            let read = unsafe { libc::proc_pidinfo(current, libc::PROC_PIDTBSDINFO, u64::MIN, (&raw mut info).cast(), size) };
            if read != size {
                break;
            }
            current = libc::pid_t::try_from(info.pbi_ppid).unwrap_or_default();
        }
        lineage
    }

    /// Connects to the extension's control socket and checks its greeting, starting the extension if it does not answer.
    ///
    /// Another httptap may be starting the extension at the same time, so the socket is what counts, not the app's
    /// exit status, which only names the cause when the socket never answers.
    fn connect_control() -> std::io::Result<UnixStream> {
        if super::embedded::replace_if_other_build(Path::new(APP))? {
            return start_and_connect();
        }
        if let Ok(stream) = UnixStream::connect(CONTROL_SOCKET) {
            return greeted(stream);
        }
        start_and_connect()
    }

    /// Runs the app, which starts the extension, and connects to its control socket once it answers.
    fn start_and_connect() -> std::io::Result<UnixStream> {
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
                pair.push(ENVIRONMENT_SEPARATOR);
                pair.push(value);
                c_string(&pair)
            })
            .collect::<std::io::Result<_>>()?;
        let mut argv: Vec<*mut libc::c_char> = arguments.iter().map(|argument| argument.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        let mut envp: Vec<*mut libc::c_char> = environment.iter().map(|pair| pair.as_ptr().cast_mut()).collect();
        envp.push(std::ptr::null_mut());
        let mut pid = libc::pid_t::default();
        // SAFETY: the attributes are initialised before use and destroyed after; every pointer passed points into a
        // CString or a null-terminated array that lives until posix_spawnp returns.
        let spawned = unsafe {
            let mut attributes: libc::posix_spawnattr_t = std::ptr::null_mut();
            let initialised = libc::posix_spawnattr_init(&mut attributes);
            if initialised != 0 {
                return Err(std::io::Error::from_raw_os_error(initialised));
            }
            let flags = libc::POSIX_SPAWN_START_SUSPENDED | libc::POSIX_SPAWN_SETPGROUP;
            libc::posix_spawnattr_setflags(&mut attributes, flags as libc::c_short);
            libc::posix_spawnattr_setpgroup(&mut attributes, NEW_GROUP);
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
        let mut status = libc::c_int::default();
        loop {
            // SAFETY: status points to a live integer; the process is this process's child.
            let waited = unsafe { libc::waitpid(pid, &mut status, WAIT_FOR_EXIT) };
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
    /// The start of the name of the temporary copy of the zipped app, which the process ID follows.
    #[cfg(httptap_embedded_app)]
    const TEMPORARY_ZIP_PREFIX: &str = "httptap-app-";
    /// The end of the name of the temporary copy of the zipped app.
    #[cfg(httptap_embedded_app)]
    const ZIP_EXTENSION: &str = ".zip";
    /// The information property list of the app this build carries, which differs between any two builds of it.
    #[cfg(httptap_embedded_app)]
    const EMBEDDED_INFO_PLIST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/Info.plist"));
    /// The app's information property list inside its bundle.
    #[cfg(httptap_embedded_app)]
    const INFO_PLIST: &str = "Contents/Info.plist";
    /// The tool that unpacks the zipped app, keeping the bundle's signature and extended attributes.
    #[cfg(httptap_embedded_app)]
    const DITTO: &str = "/usr/bin/ditto";
    /// The `ditto` flags that extract a PKZip archive rather than copy files.
    ///
    /// https://keith.github.io/xcode-man-pages/ditto.1.html
    #[cfg(httptap_embedded_app)]
    const DITTO_EXTRACT_ZIP: [&str; 2] = ["-x", "-k"];

    /// Replaces an installed app whose build differs from the one this build carries, returning whether it did.
    ///
    /// The replaced app's extension is then replaced when the app next starts it, which ends running captures loudly.
    pub(super) fn replace_if_other_build(app: &Path) -> std::io::Result<bool> {
        #[cfg(httptap_embedded_app)]
        {
            let installed = std::fs::read(app.join(INFO_PLIST)).ok();
            if installed.as_deref() == Some(EMBEDDED_INFO_PLIST) {
                return Ok(false);
            }
            if installed.is_some() {
                eprintln!("httptap: replacing {} with the one this httptap carries", app.display());
                std::fs::remove_dir_all(app)?;
            }
            install(app)?;
            Ok(true)
        }
        #[cfg(not(httptap_embedded_app))]
        {
            let _ = app;
            Ok(false)
        }
    }

    /// Unpacks the app this build carries into the folder macOS installs system extensions from.
    pub(super) fn install(app: &Path) -> std::io::Result<()> {
        #[cfg(httptap_embedded_app)]
        {
            let folder = app.parent().ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no Applications folder"))?;
            let pid = std::process::id();
            let zip = std::env::temp_dir().join(format!("{TEMPORARY_ZIP_PREFIX}{pid}{ZIP_EXTENSION}"));
            std::fs::write(&zip, APP_ZIP)?;
            let status = std::process::Command::new(DITTO).args(DITTO_EXTRACT_ZIP).arg(&zip).arg(folder).status();
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
