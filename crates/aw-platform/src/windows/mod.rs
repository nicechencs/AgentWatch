//! Windows process identity.  FFI stays in the smallest functions that need it.

use crate::{
    Capability, CapabilityStatus, IdentifiedCaller, IntegrityLevel, Owner, PeerIdentity, Platform,
    PlatformError, ProcessEntry, ProcessKey, SamplingProcess, SpawnRequest, UnsupportedKind,
};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use windows::core::{Error, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, FILETIME, HANDLE, HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, RevertToSelf, TokenElevation,
    TokenIntegrityLevel, TokenUser, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
    SECURITY_MANDATORY_SYSTEM_RID,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentThread, GetExitCodeProcess, GetProcessTimes, OpenProcess,
    OpenProcessToken, OpenThreadToken, QueryFullProcessImageNameW, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};

pub(crate) struct CurrentPlatform;

fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "windows",
        kind: UnsupportedKind::NotInThisBuild,
    }
}

fn io_error(error: Error) -> PlatformError {
    PlatformError::Io(std::io::Error::from_raw_os_error(error.code().0 & 0xffff))
}

fn close(handle: HANDLE) {
    if !handle.is_invalid() {
        // SAFETY: each owned handle is passed here at most once.
        #[allow(unsafe_code)]
        let _ = unsafe { CloseHandle(handle) };
    }
}

fn creation_time(process: HANDLE) -> Result<u64, PlatformError> {
    // SAFETY: FILETIME is plain writable output storage.
    #[allow(unsafe_code)]
    let (mut created, mut exited, mut kernel, mut user): (
        FILETIME,
        FILETIME,
        FILETIME,
        FILETIME,
    ) = unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    // SAFETY: `process` is a query handle and all output pointers are valid.
    #[allow(unsafe_code)]
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(io_error)?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn sid_for_token(token: HANDLE) -> Result<String, PlatformError> {
    let mut bytes = 0_u32;
    // SAFETY: this is the documented TokenUser sizing query.
    #[allow(unsafe_code)]
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut bytes) };
    if bytes == 0 {
        return Err(io_error(Error::from_win32()));
    }
    let mut storage = vec![0_u64; (bytes as usize).div_ceil(size_of::<u64>())];
    // SAFETY: storage is aligned and contains at least `bytes` writable bytes.
    #[allow(unsafe_code)]
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }
    .map_err(io_error)?;
    // SAFETY: successful TokenUser writes TOKEN_USER at the beginning of storage.
    #[allow(unsafe_code)]
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    // SAFETY: the SID points into live TokenUser storage; Windows allocates text.
    #[allow(unsafe_code)]
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(io_error)?;
    // SAFETY: successful conversion returns a NUL-terminated LocalAlloc string.
    #[allow(unsafe_code)]
    let result = unsafe { text.to_string() }.map_err(|_| PlatformError::Invalid {
        capability: "process_owner",
        detail: "SID was not valid UTF-16",
    });
    // SAFETY: ConvertSidToStringSidW allocated text with LocalAlloc.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(text.0.cast())) };
    result
}

fn elevated_for_token(token: HANDLE) -> Result<bool, PlatformError> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut bytes = 0_u32;
    // SAFETY: elevation is the documented output structure and size.
    #[allow(unsafe_code)]
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut bytes,
        )
    }
    .map_err(io_error)?;
    Ok(elevation.TokenIsElevated != 0)
}

fn integrity_for_token(token: HANDLE) -> Option<IntegrityLevel> {
    let mut bytes = 0_u32;
    // SAFETY: documented TokenIntegrityLevel sizing query.
    #[allow(unsafe_code)]
    let _ = unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut bytes) };
    if bytes == 0 {
        return None;
    }
    let mut storage = vec![0_u64; (bytes as usize).div_ceil(size_of::<u64>())];
    // SAFETY: storage is aligned and contains at least `bytes` writable bytes.
    #[allow(unsafe_code)]
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(storage.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }
    .ok()?;
    // SAFETY: successful query writes TOKEN_MANDATORY_LABEL at storage start.
    #[allow(unsafe_code)]
    let label = unsafe { &*storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    // SAFETY: label contains a valid SID owned by the live storage buffer.
    #[allow(unsafe_code)]
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    if count == 0 {
        return None;
    }
    // SAFETY: `count - 1` is a valid subauthority index for this SID.
    #[allow(unsafe_code)]
    let rid = unsafe { *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1)) };
    Some(match rid as i32 {
        SECURITY_MANDATORY_LOW_RID => IntegrityLevel::Low,
        SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel::Medium,
        SECURITY_MANDATORY_HIGH_RID => IntegrityLevel::High,
        SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel::System,
        _ => IntegrityLevel::Other(rid),
    })
}

fn owner_for_process(process: HANDLE) -> Option<Owner> {
    let mut token = HANDLE::default();
    // SAFETY: process is a valid query handle and token is writable output.
    #[allow(unsafe_code)]
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let result = match (sid_for_token(token), elevated_for_token(token)) {
        (Ok(sid), Ok(elevated)) => Some(Owner::Windows {
            sid,
            elevated,
            integrity: integrity_for_token(token),
        }),
        _ => None,
    };
    close(token);
    result
}

fn owner_for_token(token: HANDLE) -> Option<Owner> {
    Some(Owner::Windows {
        sid: sid_for_token(token).ok()?,
        elevated: elevated_for_token(token).ok()?,
        integrity: integrity_for_token(token),
    })
}

fn image_for_process(process: HANDLE) -> Option<PathBuf> {
    let mut capacity = 260_usize;
    while capacity <= 32_768 {
        let mut buffer = vec![0_u16; capacity];
        let mut length = capacity as u32;
        // SAFETY: buffer is writable UTF-16 output storage, with matching length.
        #[allow(unsafe_code)]
        if unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .is_ok()
        {
            buffer.truncate(length as usize);
            return Some(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity *= 2;
    }
    None
}

fn entry(pid: u32, ppid: Option<u32>) -> Result<Option<ProcessEntry>, PlatformError> {
    // SAFETY: opens only limited query access and the resulting handle is closed below.
    #[allow(unsafe_code)]
    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => handle,
        Err(_) => return Ok(None),
    };
    let start_time = match creation_time(process) {
        Ok(value) => value,
        Err(_) => {
            close(process);
            return Ok(None);
        }
    };
    let row = ProcessEntry {
        key: ProcessKey { pid, start_time },
        ppid,
        exe: image_for_process(process),
        // A table scan does not inspect PEB command lines: unavailable is not "".
        argv: None,
        owner: owner_for_process(process),
    };
    close(process);
    Ok(Some(row))
}

fn command_line(command: &[String]) -> Result<Vec<u16>, PlatformError> {
    let Some(program) = command.first() else {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "empty command",
        });
    };
    if program.is_empty() {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "empty program",
        });
    }
    let quote = |arg: &str| {
        if !arg.is_empty() && !arg.chars().any(|ch| matches!(ch, ' ' | '\t' | '"')) {
            return arg.to_owned();
        }
        let mut out = String::from("\"");
        let mut slashes = 0_usize;
        for ch in arg.chars() {
            match ch {
                '\\' => slashes += 1,
                '"' => {
                    out.push_str(&"\\".repeat(slashes * 2 + 1));
                    out.push('"');
                    slashes = 0;
                }
                _ => {
                    out.push_str(&"\\".repeat(slashes));
                    slashes = 0;
                    out.push(ch);
                }
            }
        }
        out.push_str(&"\\".repeat(slashes * 2));
        out.push('"');
        out
    };
    Ok(command
        .iter()
        .map(|arg| quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
        .encode_utf16()
        .chain(Some(0))
        .collect())
}

/// Build an environment block for the target only.  This buffer is never
/// sent to a daemon, logged, or persisted.
fn environment(extra: &[(String, String)]) -> Vec<u16> {
    let mut vars: BTreeMap<String, String> = std::env::vars().collect();
    for (key, value) in extra {
        vars.insert(key.clone(), value.clone());
    }
    let mut block = Vec::new();
    for (key, value) in vars {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

fn set_kill_on_close(job: HANDLE, enabled: bool) -> Result<(), PlatformError> {
    // SAFETY: the job structure is documented POD output input storage.
    #[allow(unsafe_code)]
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    if enabled {
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
    // SAFETY: the type and byte count exactly match JobObjectExtendedLimitInformation.
    #[allow(unsafe_code)]
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(io_error)
}

struct WindowsHeldChild {
    job: HANDLE,
    process: HANDLE,
    thread: HANDLE,
    key: ProcessKey,
}

impl WindowsHeldChild {
    fn kill_reap_close(&mut self) {
        if !self.process.is_invalid() {
            // SAFETY: process is the owned handle returned by CreateProcessW.
            #[allow(unsafe_code)]
            let _ = unsafe { TerminateProcess(self.process, 1) };
            // SAFETY: wait uses that still-owned process handle before it closes.
            #[allow(unsafe_code)]
            let _ = unsafe { WaitForSingleObject(self.process, u32::MAX) };
        }
        close(self.thread);
        close(self.process);
        close(self.job);
        self.thread = HANDLE::default();
        self.process = HANDLE::default();
        self.job = HANDLE::default();
    }
}

impl Drop for WindowsHeldChild {
    fn drop(&mut self) {
        self.kill_reap_close();
    }
}

struct WindowsReleasedChild {
    process: HANDLE,
    pid: u32,
}

impl WindowsReleasedChild {
    fn outcome_after_exit(&mut self) -> Result<crate::ReapOutcome, PlatformError> {
        let mut code = 0_u32;
        // SAFETY: the process has signalled and this is its owned handle.
        #[allow(unsafe_code)]
        unsafe { GetExitCodeProcess(self.process, &mut code) }.map_err(io_error)?;
        close(self.process);
        self.process = HANDLE::default();
        Ok(crate::ReapOutcome::Exited(code as i32))
    }
}

impl Drop for WindowsReleasedChild {
    fn drop(&mut self) {
        // Released programs survive their holder. Only the handle is closed.
        close(self.process);
    }
}

impl crate::HeldChild for WindowsHeldChild {
    fn pid(&self) -> u32 {
        self.key.pid
    }

    fn release(mut self: Box<Self>) -> Result<Box<dyn crate::ReleasedChild>, PlatformError> {
        #[cfg(feature = "test-hold-delay")]
        if let Some(delay) = hold_delay() {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        // The limit must be removed before ResumeThread: after release, no
        // holder death is allowed to terminate the program.
        if let Err(error) = set_kill_on_close(self.job, false) {
            self.kill_reap_close();
            return Err(error);
        }
        // SAFETY: this retained primary thread is resumed exactly once here.
        #[allow(unsafe_code)]
        if unsafe { ResumeThread(self.thread) } == u32::MAX {
            let error = io_error(Error::from_win32());
            self.kill_reap_close();
            return Err(error);
        }
        close(self.thread);
        close(self.job);
        self.thread = HANDLE::default();
        self.job = HANDLE::default();
        let released = WindowsReleasedChild {
            process: self.process,
            pid: self.key.pid,
        };
        self.process = HANDLE::default();
        Ok(Box::new(released))
    }

    fn abort(&mut self) -> Result<(), PlatformError> {
        self.kill_reap_close();
        Ok(())
    }
}

impl crate::ReleasedChild for WindowsReleasedChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn try_reap(&mut self) -> Result<crate::ReapOutcome, PlatformError> {
        if self.process.is_invalid() {
            return Err(PlatformError::Invalid {
                capability: "reap_child",
                detail: "released child was already reaped",
            });
        }
        // SAFETY: process is the released child's owned handle.
        #[allow(unsafe_code)]
        match unsafe { WaitForSingleObject(self.process, 0) } {
            WAIT_TIMEOUT => Ok(crate::ReapOutcome::StillRunning),
            WAIT_OBJECT_0 => self.outcome_after_exit(),
            WAIT_FAILED => Err(io_error(Error::from_win32())),
            _ => Err(PlatformError::Invalid {
                capability: "reap_child",
                detail: "unexpected wait result",
            }),
        }
    }

    fn wait(mut self: Box<Self>) -> Result<crate::ReapOutcome, PlatformError> {
        if self.process.is_invalid() {
            return Err(PlatformError::Invalid {
                capability: "reap_child",
                detail: "released child was already reaped",
            });
        }
        // SAFETY: process is the released child's owned handle.
        #[allow(unsafe_code)]
        match unsafe { WaitForSingleObject(self.process, u32::MAX) } {
            WAIT_OBJECT_0 => self.outcome_after_exit(),
            WAIT_FAILED => Err(io_error(Error::from_win32())),
            _ => Err(PlatformError::Invalid {
                capability: "reap_child",
                detail: "unexpected wait result",
            }),
        }
    }
}

#[cfg(feature = "test-hold-delay")]
fn hold_delay() -> Option<u64> {
    std::env::var("AW_TEST_HOLD_DELAY_MS")
        .ok()?
        .parse::<u64>()
        .ok()
        .map(|delay| delay.min(10_000))
}

pub fn identify_pipe_peer(
    handle: std::os::windows::io::RawHandle,
) -> Result<PeerIdentity, PlatformError> {
    let pipe = HANDLE(handle as isize);
    let mut pid = 0_u32;
    // SAFETY: `handle` is supplied by the live server end of a named pipe.
    #[allow(unsafe_code)]
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.map_err(|_| {
        PlatformError::PeerNotIdentified {
            reason: "named-pipe client process id is unavailable",
        }
    })?;
    // Use the pipe server's impersonation rather than a daemon account token.
    // SAFETY: the pipe is connected; RevertToSelf below always ends this scope.
    #[allow(unsafe_code)]
    unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(|_| PlatformError::PeerNotIdentified {
        reason: "named-pipe client impersonation failed",
    })?;
    let mut token = HANDLE::default();
    // SAFETY: while impersonating, the current thread has the client token.
    #[allow(unsafe_code)]
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    // SAFETY: paired with the successful impersonation above, regardless of token open result.
    #[allow(unsafe_code)]
    let reverted = unsafe { RevertToSelf() };
    if opened.is_err() || reverted.is_err() {
        if opened.is_ok() {
            close(token);
        }
        return Err(PlatformError::PeerNotIdentified {
            reason: "named-pipe client token is unavailable",
        });
    }
    let owner = owner_for_token(token);
    close(token);
    owner
        .map(|owner| PeerIdentity::new(owner, Some(pid)))
        .ok_or(PlatformError::PeerNotIdentified {
            reason: "named-pipe client token ownership is unavailable",
        })
}

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "windows"
    }

    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            Capability::SpawnSuspended
            | Capability::ProcessIdentity
            | Capability::ProcessTable
            | Capability::PeerIdentity
            | Capability::ExitCode => CapabilityStatus::Available,
            // The platform primitive can validate a pipe peer's token, but the
            // daemon has not wired its launch API to that primitive yet.
            Capability::SpawnAsCaller | Capability::SecureDataDir => {
                CapabilityStatus::NotInThisBuild
            }
        }
    }

    fn spawn_suspended(
        &self,
        _: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn crate::HeldChild>, PlatformError> {
        let mut command = command_line(&request.command)?;
        let mut env = environment(&request.env);
        // SAFETY: STARTUPINFOW is documented as zero-initialized before cb is set.
        #[allow(unsafe_code)]
        let mut startup: STARTUPINFOW = unsafe { zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        // SAFETY: CreateProcessW fills this output structure.
        #[allow(unsafe_code)]
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        let cwd = request.cwd.as_ref().map(|path| {
            use std::os::windows::ffi::OsStrExt;
            path.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        });
        let flags = PROCESS_CREATION_FLAGS(CREATE_SUSPENDED.0 | CREATE_UNICODE_ENVIRONMENT.0);
        // SAFETY: command/environment/cwd buffers are live for the synchronous
        // call; direct CLI launch inherits no handles and starts suspended.
        #[allow(unsafe_code)]
        let created = unsafe {
            CreateProcessW(
                windows::core::PCWSTR::null(),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                false,
                flags,
                Some(env.as_mut_ptr().cast()),
                cwd.as_ref().map_or(windows::core::PCWSTR::null(), |value| {
                    windows::core::PCWSTR(value.as_ptr())
                }),
                &startup,
                &mut info,
            )
        };
        created.map_err(io_error)?;
        let key = match creation_time(info.hProcess) {
            Ok(start_time) => ProcessKey {
                pid: info.dwProcessId,
                start_time,
            },
            Err(error) => {
                let mut child = WindowsHeldChild {
                    job: HANDLE::default(),
                    process: info.hProcess,
                    thread: info.hThread,
                    key: ProcessKey {
                        pid: info.dwProcessId,
                        start_time: 0,
                    },
                };
                child.kill_reap_close();
                return Err(error);
            }
        };
        // SAFETY: creates an unnamed job owned by WindowsHeldChild.
        #[allow(unsafe_code)]
        let job = match unsafe { CreateJobObjectW(None, windows::core::PCWSTR::null()) } {
            Ok(job) => job,
            Err(error) => {
                let mut child = WindowsHeldChild {
                    job: HANDLE::default(),
                    process: info.hProcess,
                    thread: info.hThread,
                    key,
                };
                child.kill_reap_close();
                return Err(io_error(error));
            }
        };
        let mut child = WindowsHeldChild {
            job,
            process: info.hProcess,
            thread: info.hThread,
            key,
        };
        if let Err(error) = set_kill_on_close(child.job, true) {
            child.kill_reap_close();
            return Err(error);
        }
        // SAFETY: this owned suspended process is assigned to this owned job.
        #[allow(unsafe_code)]
        if let Err(error) =
            unsafe { AssignProcessToJobObject(child.job, child.process) }.map_err(io_error)
        {
            child.kill_reap_close();
            return Err(error);
        }
        Ok(Box::new(child))
    }

    fn process_identity(&self, pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
        entry(pid, None)
    }

    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        // SAFETY: snapshot is an owned handle that is closed before return.
        #[allow(unsafe_code)]
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(io_error)?;
        let mut raw = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut rows = Vec::new();
        // SAFETY: snapshot and output structure are valid.
        #[allow(unsafe_code)]
        let mut next = unsafe { Process32FirstW(snapshot, &mut raw) };
        while next.is_ok() {
            if let Some(row) = entry(raw.th32ProcessID, Some(raw.th32ParentProcessID))? {
                rows.push(row);
            }
            raw = PROCESSENTRY32W {
                dwSize: size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            // SAFETY: same valid snapshot/output contract as Process32FirstW.
            #[allow(unsafe_code)]
            {
                next = unsafe { Process32NextW(snapshot, &mut raw) };
            }
        }
        close(snapshot);
        Ok(rows)
    }

    fn sampling_process(&self, _: u32) -> Result<Option<SamplingProcess>, PlatformError> {
        Err(no("sampling_process"))
    }
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError> {
        Err(no("sampling_process_table"))
    }
    fn secure_data_dir(&self, _: &Path) -> Result<(), PlatformError> {
        Err(no("secure_data_dir"))
    }
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError> {
        std::env::var_os("ProgramData")
            .map(|v| PathBuf::from(v).join("AgentWatch"))
            .ok_or(PlatformError::Invalid {
                capability: "default_data_dir",
                detail: "ProgramData is unset",
            })
    }
    fn default_config_path(&self) -> Result<PathBuf, PlatformError> {
        Ok(self.default_data_dir()?.join("config.toml"))
    }
    fn is_privileged(&self) -> Option<bool> {
        aw_collector_windows::privilege::is_privileged()
    }
    fn current_user_id(&self) -> Option<String> {
        self.current_owner().ok().and_then(|owner| match owner {
            Owner::Windows { sid, .. } => Some(sid),
            Owner::Unix { .. } => None,
        })
    }
    fn current_owner(&self) -> Result<Owner, PlatformError> {
        entry(std::process::id(), None)?
            .and_then(|process| process.owner)
            .ok_or(PlatformError::PeerNotIdentified {
                reason: "current process ownership is unavailable",
            })
    }
}

/// Not read in this build. The caller prints 「不可得」.
pub fn os_version() -> Option<String> {
    None
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::CurrentPlatform;
    use crate::{
        platform, Capability, CapabilityStatus, IdentifiedCaller, Platform, ReapOutcome,
        SpawnRequest,
    };

    #[test]
    fn process_capabilities_are_honest() {
        assert_eq!(
            CurrentPlatform.capability(Capability::ProcessIdentity),
            CapabilityStatus::Available
        );
        assert_eq!(
            CurrentPlatform.capability(Capability::ProcessTable),
            CapabilityStatus::Available
        );
        assert_eq!(
            CurrentPlatform.capability(Capability::SpawnSuspended),
            CapabilityStatus::Available
        );
        assert_eq!(
            CurrentPlatform.capability(Capability::SpawnAsCaller),
            CapabilityStatus::NotInThisBuild
        );
    }

    #[test]
    fn release_transfers_the_only_reap_handle_and_keeps_exit_7() {
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["cmd".to_owned(), "/c".to_owned(), "exit 7".to_owned()],
            cwd: None,
            env: Vec::new(),
        };
        let held = platform()
            .spawn_suspended(&caller, &request)
            .expect("held Windows child");
        let released = held.release().expect("released Windows child");
        assert_eq!(released.wait().expect("reap child"), ReapOutcome::Exited(7));
    }
}
