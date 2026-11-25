//! The tests every implementation of simple-httptap-redirector runs, written against its traits alone.
//!
//! A system that cannot redirect, for want of an approval or a privilege, refuses with `Unsupported` and passes.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};

use simple_httptap_redirector::{Capture, Program, Redirector};

/// An absolute path inside a folder that does not exist, so neither the system nor `PATH` finds a program there.
const MISSING_PROGRAM: &str = "/nonexistent/simple-httptap/no-such-program";
/// The exit code the test's program exits with, which no shell gives of its own accord.
///
/// https://pubs.opengroup.org/onlinepubs/9799919799/functions/exit.html
const EXIT_CODE: i32 = 3;
/// The shell that runs the test's program, and the flag that hands it a command.
const SHELL: (&str, &str) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
/// A loopback address with no proxy behind it, which a program that sends nothing never reaches.
const NO_PROXY: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), u16::MAX);

/// Returns a program that exits with the exit code and sends nothing.
fn exiting_program() -> Program {
    let (shell, flag) = SHELL;
    Program { path: shell.into(), arguments: vec![OsString::from(flag), OsString::from(format!("exit {EXIT_CODE}"))], environment: Vec::new() }
}

/// Checks that launching a missing program returns an error rather than a capture.
pub fn refuses_a_program_that_is_not_there<T: Redirector>(redirector: T) {
    let program = Program { path: MISSING_PROGRAM.into(), arguments: Vec::new(), environment: Vec::new() };
    assert!(redirector.launch(&program, NO_PROXY).is_err());
}

/// Checks that a started program has an identifier and that its exit code comes back, where the system can redirect.
pub fn reports_how_the_program_exited<T: Redirector>(redirector: T) {
    let capture = match redirector.launch(&exiting_program(), NO_PROXY) {
        Err(fault) if fault.kind() == ErrorKind::Unsupported => return,
        launched => launched.expect("the program starts"),
    };
    assert_ne!(capture.id(), u32::MIN);
    assert_eq!(capture.wait().expect("the program exits").code(), Some(EXIT_CODE));
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn refuses_a_program_that_is_not_there() {
            $crate::refuses_a_program_that_is_not_there($value);
        }

        #[test]
        fn reports_how_the_program_exited() {
            $crate::reports_how_the_program_exited($value);
        }
    };
}
