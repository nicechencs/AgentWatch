//! Windows Job Object scope PoC (P0-DAEMON-01 / SPIKE-05).
//!
//! A normal user creates an unnamed Job, starts `cmd.exe /c ping.exe` suspended,
//! assigns that child, resumes it, and writes one JSONL line per member
//! (`pid`, `parent`, `image`).
//! `JOB_OBJECT_LIMIT_BREAKAWAY_OK` and `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` are
//! never set. Nothing is launched through Task Scheduler or WMI. A failed API is
//! printed once with `GetLastError` and is not retried elevated.
//!
//! This binary is not a workspace member. `aw-daemon` forbids `unsafe_code`, so
//! `cargo run -p aw-daemon --example win_job_scope` builds and runs this file.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::process::ExitCode;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FALSE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION,
    STARTUPINFOW,
};

const PID_CAP: usize = 64;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("win_job_poc: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let job = create_job()?;
    // KILL_ON_JOB_CLOSE only cleans up this PoC's own child. It is not breakaway.
    if let Err(err) = set_kill_on_close_only(job) {
        let _ = unsafe { CloseHandle(job) };
        return Err(err);
    }

    let mut child = match spawn_timeout_suspended() {
        Ok(child) => child,
        Err(err) => {
            let _ = unsafe { CloseHandle(job) };
            return Err(err);
        }
    };

    let assigned = unsafe { AssignProcessToJobObject(job, child.process) };
    if assigned == FALSE {
        let err = last_error("AssignProcessToJobObject");
        let _ = unsafe { TerminateJobObject(job, 1) };
        close_child(&mut child);
        let _ = unsafe { CloseHandle(job) };
        return Err(err);
    }

    // Query while the child is still suspended. A console program such as
    // `timeout.exe` exits immediately when stdin is not a console ("Input
    // redirection is not supported"), which empties the job before a later query.
    let members = match query_job_pids(job) {
        Ok(members) => members,
        Err(err) => {
            let _ = unsafe { TerminateJobObject(job, 1) };
            close_child(&mut child);
            let _ = unsafe { CloseHandle(job) };
            return Err(err);
        }
    };
    let child_in_job = members.contains(&child.pid);
    let resumed = unsafe { ResumeThread(child.thread) };
    if resumed == u32::MAX {
        let err = last_error("ResumeThread");
        let _ = unsafe { TerminateJobObject(job, 1) };
        close_child(&mut child);
        let _ = unsafe { CloseHandle(job) };
        return Err(err);
    }
    // cmd.exe needs time to CreateProcess its ping grandchild. 300 ms was not
    // enough on this machine: the job still held only cmd.exe.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let after = match query_job_pids(job) {
        Ok(members) => members,
        Err(err) => {
            let _ = unsafe { TerminateJobObject(job, 1) };
            close_child(&mut child);
            let _ = unsafe { CloseHandle(job) };
            return Err(err);
        }
    };
    let still_in_job = after.contains(&child.pid);
    let parents = match parent_map() {
        Ok(parents) => parents,
        Err(err) => {
            let _ = unsafe { TerminateJobObject(job, 1) };
            close_child(&mut child);
            let _ = unsafe { CloseHandle(job) };
            return Err(err);
        }
    };

    let images = match image_map() {
        Ok(images) => images,
        Err(err) => {
            let _ = unsafe { TerminateJobObject(job, 1) };
            close_child(&mut child);
            let _ = unsafe { CloseHandle(job) };
            return Err(err);
        }
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for pid in &after {
        let parent = match parents.get(pid).copied() {
            Some(value) => value.to_string(),
            None => "null".to_owned(),
        };
        writeln!(
            out,
            "{{\"pid\":{pid},\"parent\":{parent},\"image\":\"{}\"}}",
            json_escape(images.get(pid).map(String::as_str).unwrap_or(""))
        )
        .map_err(|err| format!("write stdout: {err}"))?;
    }
    out.flush().map_err(|err| format!("flush stdout: {err}"))?;

    eprintln!(
        "summary child_pid={} child_in_job_while_suspended={} suspended_member_count={} still_in_job_after_resume={} member_count_after_resume={} breakaway_ok=false silent_breakaway_ok=false",
        child.pid,
        child_in_job,
        members.len(),
        still_in_job,
        after.len()
    );

    let _ = unsafe { TerminateJobObject(job, 0) };
    close_child(&mut child);
    let _ = unsafe { CloseHandle(job) };

    if child_in_job && still_in_job {
        Ok(())
    } else if child_in_job {
        Err("child was in the job while suspended but left after ResumeThread".to_owned())
    } else {
        Err("child pid was assigned but was absent from JobObjectBasicProcessIdList".to_owned())
    }
}

struct Child {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
}

fn create_job() -> Result<HANDLE, String> {
    // Unnamed. This PoC does not duplicate the handle into a service.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(last_error("CreateJobObjectW"));
    }
    Ok(job)
}

fn set_kill_on_close_only(job: HANDLE) -> Result<(), String> {
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&info).cast(),
            size_u32::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
        )
    };
    if ok == FALSE {
        return Err(last_error("SetInformationJobObject(KILL_ON_JOB_CLOSE)"));
    }
    let flags = info.BasicLimitInformation.LimitFlags;
    if flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0 {
        return Err(format!(
            "refusing to continue: breakaway bits are set (LimitFlags={flags:#x})"
        ));
    }
    Ok(())
}

fn spawn_timeout_suspended() -> Result<Child, String> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    // ping waits on the network stack, so it does not exit just because stdin
    // is not a console. timeout.exe does ("Input redirection is not supported").
    // The second ping is a grandchild: cmd.exe is the assigned child.
    let mut cmdline = wide(&format!(
        "{system_root}\\System32\\cmd.exe /c {system_root}\\System32\\ping.exe 127.0.0.1 -n 30"
    ));
    let mut startup: STARTUPINFOW = zeroed();
    startup.cb = size_u32::<STARTUPINFOW>();
    let mut process: PROCESS_INFORMATION = zeroed();
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut process,
        )
    };
    if ok == FALSE {
        return Err(last_error("CreateProcessW(ping.exe, CREATE_SUSPENDED)"));
    }
    Ok(Child {
        process: process.hProcess,
        thread: process.hThread,
        pid: process.dwProcessId,
    })
}

fn query_job_pids(job: HANDLE) -> Result<Vec<u32>, String> {
    // windows-sys declares ProcessIdList as `[usize; 1]`. The kernel writes a
    // flexible array of ULONG_PTR pids after the two counters. The byte length
    // passed below is the real buffer size.
    #[repr(C)]
    struct ProcessIdList {
        assigned: u32,
        listed: u32,
        ids: [usize; PID_CAP],
    }

    let mut list = ProcessIdList {
        assigned: 0,
        listed: 0,
        ids: [0; PID_CAP],
    };
    let mut returned = 0u32;
    let ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicProcessIdList,
            std::ptr::from_mut(&mut list).cast(),
            size_u32::<ProcessIdList>(),
            &mut returned,
        )
    };
    if ok == FALSE {
        return Err(last_error(
            "QueryInformationJobObject(JobObjectBasicProcessIdList)",
        ));
    }
    let n = usize::try_from(list.listed).unwrap_or(0);
    if list.assigned > list.listed || n > PID_CAP {
        return Err(format!(
            "JobObjectBasicProcessIdList assigned={} listed={n} buffer={PID_CAP}",
            list.assigned
        ));
    }
    let mut pids = Vec::with_capacity(n);
    for slot in list.ids.iter().take(n) {
        let pid = u32::try_from(*slot)
            .map_err(|_| format!("job member pid {slot} does not fit in u32"))?;
        pids.push(pid);
    }
    Ok(pids)
}

fn parent_map() -> Result<std::collections::HashMap<u32, u32>, String> {
    Ok(snapshot()?.0)
}

fn image_map() -> Result<std::collections::HashMap<u32, String>, String> {
    Ok(snapshot()?.1)
}

fn snapshot() -> Result<
    (
        std::collections::HashMap<u32, u32>,
        std::collections::HashMap<u32, String>,
    ),
    String,
> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateToolhelp32Snapshot"));
    }
    let mut entry: PROCESSENTRY32W = zeroed();
    entry.dwSize = size_u32::<PROCESSENTRY32W>();
    if unsafe { Process32FirstW(snap, &mut entry) } == FALSE {
        let err = last_error("Process32FirstW");
        let _ = unsafe { CloseHandle(snap) };
        return Err(err);
    }
    let mut parents = std::collections::HashMap::new();
    let mut images = std::collections::HashMap::new();
    loop {
        parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
        images.insert(entry.th32ProcessID, exe_name(&entry.szExeFile));
        entry.dwSize = size_u32::<PROCESSENTRY32W>();
        if unsafe { Process32NextW(snap, &mut entry) } == FALSE {
            break;
        }
    }
    let _ = unsafe { CloseHandle(snap) };
    Ok((parents, images))
}

fn exe_name(buf: &[u16]) -> String {
    let end = buf.iter().position(|unit| *unit == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn close_child(child: &mut Child) {
    if !child.thread.is_null() {
        let _ = unsafe { CloseHandle(child.thread) };
        child.thread = std::ptr::null_mut();
    }
    if !child.process.is_null() {
        let _ = unsafe { CloseHandle(child.process) };
        child.process = std::ptr::null_mut();
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error(api: &str) -> String {
    let code = unsafe { GetLastError() };
    let os = i32::try_from(code).unwrap_or(i32::MAX);
    format!(
        "{api} failed: GetLastError={code} ({})",
        io::Error::from_raw_os_error(os)
    )
}

fn size_u32<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
}

fn zeroed<T>() -> T {
    // SAFETY: every T passed here is a windows-sys `#[repr(C)]` struct of
    // integers and pointers. All-zero is the initial value before the caller
    // fills `cb` / `dwSize` / `LimitFlags`.
    unsafe { std::mem::zeroed() }
}
