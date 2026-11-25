//! Starting the program in a job object, which every process it starts joins, so its processes are known by their job.

use std::io::Error;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread,
    THREAD_SUSPEND_RESUME,
};
use windows_sys::core::BOOL;

use simple_httptap_redirector::Program;

/// A job object with no limits, whose processes are the program and its descendants.
#[derive(Debug)]
pub(crate) struct Job(OwnedHandle);

impl Job {
    /// Makes an unnamed job with no processes.
    pub(crate) fn new() -> std::io::Result<Self> {
        // SAFETY: no security attributes and no name are asked for.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        owned(raw).map(Self)
    }

    /// Starts the program suspended, puts it in the job, then lets it run, so it starts nothing outside the job.
    pub(crate) fn start(&self, program: &Program) -> std::io::Result<Child> {
        let mut command = Command::new(&program.path);
        command
            .args(&program.arguments)
            .creation_flags(CREATE_SUSPENDED);
        for (name, value) in &program.environment {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
        let mut child = command.spawn()?;
        // SAFETY: both handles are open: the job's own, and the child's, which `child` holds.
        let assigned =
            unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) };
        let resumed = if assigned == BOOL::default() {
            Err(Error::last_os_error())
        } else {
            resume(child.id())
        };
        if let Err(fault) = resumed {
            let _ = child.kill();
            let _ = child.wait();
            return Err(fault);
        }
        Ok(child)
    }

    /// Returns whether the process with the identifier is in the job; a process gone or out of reach is not.
    pub(crate) fn contains(&self, process_id: u32) -> bool {
        // SAFETY: opening a process by identifier has no preconditions; a failure returns null.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                BOOL::default(),
                process_id,
            )
        };
        let Ok(process) = owned(process) else {
            return false;
        };
        let mut inside = BOOL::default();
        // SAFETY: both handles are open, and `inside` is a writable local.
        let asked =
            unsafe { IsProcessInJob(process.as_raw_handle(), self.0.as_raw_handle(), &mut inside) };
        asked != BOOL::default() && inside != BOOL::default()
    }
}

/// Resumes the one thread of a process started suspended.
fn resume(process_id: u32) -> std::io::Result<()> {
    // SAFETY: a snapshot of every thread has no preconditions.
    let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, u32::MIN) })?;
    // SAFETY: THREADENTRY32 is plain data, valid when zeroed.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    // SAFETY: the snapshot is open and the entry's size is set.
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    while more != BOOL::default() {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: opening a thread by identifier has no preconditions; a failure returns null.
            let thread = owned(unsafe {
                OpenThread(THREAD_SUSPEND_RESUME, BOOL::default(), entry.th32ThreadID)
            })?;
            // SAFETY: the thread handle is open with the right to resume.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                return Err(Error::last_os_error());
            }
            return Ok(());
        }
        // SAFETY: as for `Thread32First`.
        more = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    Err(Error::other(format!(
        "process {process_id} had no thread to resume"
    )))
}

/// Takes ownership of a handle a call returned, or returns the call's error if it returned none.
fn owned(raw: HANDLE) -> std::io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }
    // SAFETY: the handle is valid and nothing else owns it.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exit code the test's program takes from its environment.
    const EXIT_CODE: i32 = 7;
    /// The variable that carries the exit code.
    const VARIABLE: &str = "HTTPTAP_EXIT_CODE";

    /// Checks that the program starts in the job with its environment, this process is not in the job, and the exit code comes back.
    #[test]
    fn starts_the_program_in_the_job() {
        let job = Job::new().unwrap();
        let script = format!("ping -n 2 127.0.0.1 > NUL & exit %{VARIABLE}%");
        let environment = vec![(VARIABLE.into(), Some(EXIT_CODE.to_string().into()))];
        let program = Program {
            path: "cmd".into(),
            arguments: vec!["/C".into(), script.into()],
            environment,
        };
        let mut child = job.start(&program).unwrap();
        assert!(job.contains(child.id()));
        assert!(!job.contains(std::process::id()));
        assert_eq!(child.wait().unwrap().code(), Some(EXIT_CODE));
    }
}
