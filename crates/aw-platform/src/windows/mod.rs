//! Windows process boundary. Win32 handles created here never escape as PIDs.
#![allow(unsafe_code)]

use crate::{
    test_hold_delay, HeldChild, IdentifiedCaller, Owner, Platform, PlatformError, ProcessEntry,
    ProcessKey, ReapOutcome, SpawnRequest,
};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_void, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use windows::core::{Error, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, FILETIME, HANDLE, HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    DuplicateTokenEx, GetSecurityDescriptorDacl, GetTokenInformation, SecurityImpersonation,
    TokenElevation, TokenPrimary, TokenUser, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_ALL_ACCESS,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, GetProcessTimes,
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};

pub(crate) struct CurrentPlatform;

/// Raw process handles retained after release. The raw representation avoids
/// making a Win32 handle part of the platform-neutral API.
fn children() -> &'static Mutex<HashMap<ProcessKey, isize>> {
    static CHILDREN: OnceLock<Mutex<HashMap<ProcessKey, isize>>> = OnceLock::new();
    CHILDREN.get_or_init(|| Mutex::new(HashMap::new()))
}
fn io_error(error: Error) -> PlatformError {
    PlatformError::Io(std::io::Error::from_raw_os_error(error.code().0 & 0xffff))
}
fn close(handle: HANDLE) {
    if !handle.is_invalid() {
        /* SAFETY: each owned handle is passed here once. */
        let _ = unsafe { CloseHandle(handle) };
    }
}

fn creation_time(process: HANDLE) -> Result<u64, PlatformError> {
    // SAFETY: FILETIME is plain writable output storage.
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    // SAFETY: the queried process handle and four output pointers are valid.
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(io_error)?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
fn sid_for_token(token: HANDLE) -> Result<String, PlatformError> {
    let mut bytes = 0_u32;
    // SAFETY: documented TokenUser sizing query.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut bytes) };
    if bytes == 0 {
        return Err(io_error(Error::from_win32()));
    }
    let mut buf = vec![0_u64; (bytes as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `buf` has at least `bytes` bytes and stays live while its TOKEN_USER is read.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }
    .map_err(io_error)?;
    // SAFETY: successful TokenUser query writes TOKEN_USER at the start of buf.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    // SAFETY: SID belongs to the live token buffer; Windows allocates `text`.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(io_error)?;
    // SAFETY: successful conversion returns a NUL-terminated LocalAlloc string.
    let result = unsafe { text.to_string() }.map_err(|_| PlatformError::Invalid {
        capability: "process_owner",
        detail: "SID was not valid UTF-16",
    });
    // SAFETY: ConvertSidToStringSidW allocated this value with LocalAlloc.
    let _ = unsafe { LocalFree(HLOCAL(text.0.cast())) };
    result
}
fn elevated_for_token(token: HANDLE) -> Result<bool, PlatformError> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut bytes = 0_u32;
    // SAFETY: output has the exact documented TOKEN_ELEVATION layout and size.
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
fn owner_for_process(process: HANDLE) -> Option<Owner> {
    let mut token = HANDLE::default();
    // SAFETY: process is a valid query handle; token becomes owned on success.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let result = match (sid_for_token(token), elevated_for_token(token)) {
        (Ok(sid), Ok(elevated)) => Some(Owner::Windows { sid, elevated }),
        _ => None,
    };
    close(token);
    result
}
fn owner_for_token(token: HANDLE) -> Option<Owner> {
    Some(Owner::Windows {
        sid: sid_for_token(token).ok()?,
        elevated: elevated_for_token(token).ok()?,
    })
}
fn primary_token_for(
    caller: &IdentifiedCaller,
    current: &Owner,
) -> Result<Option<HANDLE>, PlatformError> {
    if caller.owner() == current {
        return Ok(None);
    }
    let Some(pid) = caller.pid() else {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "identified peer PID unavailable",
        });
    };
    // SAFETY: limited query access only; closed immediately after opening its token.
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.map_err(io_error)?;
    let mut token = HANDLE::default();
    // SAFETY: process is valid; token receives an owned handle on success.
    let opened = unsafe {
        OpenProcessToken(
            process,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        )
    };
    close(process);
    opened.map_err(io_error)?;
    // Re-check the token SID/elevation at use time. A numeric PID alone never authorizes launch.
    if owner_for_token(token).as_ref() != Some(caller.owner()) {
        close(token);
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "peer token no longer matches identified caller",
        });
    }
    let mut primary = HANDLE::default();
    // SAFETY: token is a validated client token; primary receives ownership on success.
    let duplicated = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    };
    close(token);
    duplicated.map_err(io_error)?;
    Ok(Some(primary))
}
fn image_for_process(process: HANDLE) -> Option<PathBuf> {
    let mut capacity = 260_usize;
    while capacity <= 32_768 {
        let mut buffer = vec![0_u16; capacity];
        let mut length = capacity as u32;
        // SAFETY: buffer is writable UTF-16 storage and length declares its capacity.
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
    // SAFETY: opens read-only limited query access; closed below on every success path.
    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => handle,
        Err(_) => return Ok(None),
    };
    let key = match creation_time(process) {
        Ok(start_time) => ProcessKey { pid, start_time },
        Err(_) => {
            close(process);
            return Ok(None);
        }
    };
    let row = ProcessEntry {
        key,
        ppid,
        exe: image_for_process(process),
        argv: None,
        argv_na_reason: Some("collector_unavailable"),
        owner: owner_for_process(process),
    };
    close(process);
    Ok(Some(row))
}

fn command_line(command: &[String]) -> Result<Vec<u16>, PlatformError> {
    if command.is_empty() || command.first().is_some_and(String::is_empty) {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "empty command",
        });
    }
    let quote = |arg: &str| {
        if !arg.is_empty() && !arg.chars().any(|ch| matches!(ch, ' ' | '\t' | '"')) {
            return arg.to_owned();
        }
        let mut output = String::from("\"");
        let mut slashes = 0_usize;
        for ch in arg.chars() {
            match ch {
                '\\' => slashes += 1,
                '"' => {
                    output.push_str(&"\\".repeat(slashes * 2 + 1));
                    output.push('"');
                    slashes = 0;
                }
                _ => {
                    output.push_str(&"\\".repeat(slashes));
                    slashes = 0;
                    output.push(ch);
                }
            }
        }
        output.push_str(&"\\".repeat(slashes * 2));
        output.push('"');
        output
    };
    Ok(command
        .iter()
        .map(|value| quote(value))
        .collect::<Vec<_>>()
        .join(" ")
        .encode_utf16()
        .chain(Some(0))
        .collect())
}
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
    // SAFETY: documented POD job information starts as zero and is live for the call.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    if enabled {
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
    // SAFETY: the type and byte length exactly match JobObjectExtendedLimitInformation.
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

fn secure_directory_acl(path: &Path) -> Result<(), PlatformError> {
    // Protected DACL: do not inherit permissive ACEs from ProgramData.  The
    // SDDL grants full control only to LocalSystem and Builtin Administrators.
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated; Windows allocates `descriptor` on success.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io_error)?;
    let result = (|| {
        let mut present = false.into();
        let mut defaulted = false.into();
        let mut dacl = std::ptr::null_mut();
        // SAFETY: descriptor is a valid self-relative descriptor from the conversion call.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .map_err(io_error)?;
        if !present.as_bool() || dacl.is_null() {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "protected directory DACL was absent",
            });
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: path is NUL-terminated and dacl points into the live security descriptor.
        unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        }
        .ok()
        .map_err(io_error)
    })();
    // SAFETY: conversion allocated this descriptor with LocalAlloc exactly once.
    let _ = unsafe { LocalFree(HLOCAL(descriptor.0)) };
    result
}

struct WindowsHeldChild {
    job: HANDLE,
    process: HANDLE,
    thread: HANDLE,
    key: ProcessKey,
    released: bool,
}
impl WindowsHeldChild {
    fn kill_reap_close(&mut self) {
        // SAFETY: this process handle was returned by CreateProcessW and remains owned here.
        let _ = unsafe { TerminateProcess(self.process, 1) };
        // SAFETY: wait uses the owned process handle and reaps the deliberately aborted child.
        let _ = unsafe { WaitForSingleObject(self.process, u32::MAX) };
        close(self.thread);
        close(self.process);
        close(self.job);
        self.thread = HANDLE::default();
        self.process = HANDLE::default();
        self.job = HANDLE::default();
    }
}
impl HeldChild for WindowsHeldChild {
    fn pid(&self) -> u32 {
        self.key.pid
    }
    fn key(&self) -> ProcessKey {
        self.key
    }
    fn release(&mut self) -> Result<(), PlatformError> {
        if self.released {
            return Err(PlatformError::Invalid {
                capability: "release",
                detail: "child was already released",
            });
        }
        if let Some(delay) = test_hold_delay() {
            std::thread::sleep(delay);
        }
        if let Err(error) = set_kill_on_close(self.job, false) {
            self.kill_reap_close();
            return Err(error);
        }
        // SAFETY: retained primary thread is resumed exactly once here.
        if unsafe { ResumeThread(self.thread) } == u32::MAX {
            self.kill_reap_close();
            return Err(io_error(Error::from_win32()));
        }
        let mut map = children().lock().map_err(|_| PlatformError::Invalid {
            capability: "reap_child",
            detail: "child handle registry poisoned",
        })?;
        if map.insert(self.key, self.process.0).is_some() {
            self.kill_reap_close();
            return Err(PlatformError::Invalid {
                capability: "reap_child",
                detail: "duplicate child process key",
            });
        }
        close(self.thread);
        close(self.job);
        self.thread = HANDLE::default();
        self.process = HANDLE::default();
        self.job = HANDLE::default();
        self.released = true;
        Ok(())
    }
    fn abort(&mut self) -> Result<(), PlatformError> {
        if !self.released {
            self.kill_reap_close();
        }
        Ok(())
    }
}
impl Drop for WindowsHeldChild {
    fn drop(&mut self) {
        if !self.released {
            self.kill_reap_close();
        }
    }
}

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "windows"
    }
    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn HeldChild>, PlatformError> {
        // Direct CLI launches use the current token. A service launch obtains
        // and validates the named-pipe client's token, then creates with that
        // token; there is no service-account fallback.
        // SAFETY: GetCurrentProcess returns the pseudo-handle for this process,
        // which is valid for the token query below and must not be closed.
        let current =
            owner_for_process(unsafe { GetCurrentProcess() }).ok_or(PlatformError::Invalid {
                capability: "spawn_suspended",
                detail: "current process token unavailable",
            })?;
        let primary_token = primary_token_for(caller, &current)?;
        let mut command = command_line(&request.command)?;
        let mut env = environment(&request.env);
        // SAFETY: documented CreateProcessW structures can be zero-initialized before use.
        let mut startup: STARTUPINFOW = unsafe { zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        // SAFETY: CreateProcessW fills this output structure.
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        let cwd = request.cwd.as_ref().map(|path| {
            path.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        });
        // SAFETY: command/env/cwd buffers are mutable or NUL-terminated and live for the call; handles are not inherited.
        let flags = PROCESS_CREATION_FLAGS(CREATE_SUSPENDED.0 | CREATE_UNICODE_ENVIRONMENT.0);
        let created = if let Some(token) = primary_token {
            // SAFETY: `token` is a duplicated validated primary token; all input buffers live through the call.
            let result = unsafe {
                CreateProcessAsUserW(
                    token,
                    PCWSTR::null(),
                    PWSTR(command.as_mut_ptr()),
                    None,
                    None,
                    false,
                    flags,
                    Some(env.as_mut_ptr().cast()),
                    cwd.as_ref()
                        .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr())),
                    &startup,
                    &mut info,
                )
            }
            .map_err(io_error);
            close(token);
            result
        } else {
            // SAFETY: command/env/cwd buffers are mutable or NUL-terminated and live for the call; handles are not inherited.
            unsafe {
                CreateProcessW(
                    PCWSTR::null(),
                    PWSTR(command.as_mut_ptr()),
                    None,
                    None,
                    false,
                    flags,
                    Some(env.as_mut_ptr().cast()),
                    cwd.as_ref()
                        .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr())),
                    &startup,
                    &mut info,
                )
            }
            .map_err(io_error)
        };
        created?;
        let key = match creation_time(info.hProcess) {
            Ok(start_time) => ProcessKey {
                pid: info.dwProcessId,
                start_time,
            },
            Err(error) => {
                // SAFETY: CreateProcessW succeeded, so this owned suspended
                // process must be ended before its handles are released.
                let _ = unsafe { TerminateProcess(info.hProcess, 1) };
                // SAFETY: same owned process handle; reap before close.
                let _ = unsafe { WaitForSingleObject(info.hProcess, u32::MAX) };
                close(info.hThread);
                close(info.hProcess);
                return Err(error);
            }
        };
        // SAFETY: creates an unnamed job; ownership moves into WindowsHeldChild below.
        let job = match unsafe { CreateJobObjectW(None, PCWSTR::null()) } {
            Ok(job) => job,
            Err(error) => {
                let mut child = WindowsHeldChild {
                    job: HANDLE::default(),
                    process: info.hProcess,
                    thread: info.hThread,
                    key,
                    released: false,
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
            released: false,
        };
        if let Err(error) = set_kill_on_close(job, true) {
            child.kill_reap_close();
            return Err(error);
        }
        // SAFETY: both Job and suspended process handles are valid and owned here.
        if let Err(error) =
            unsafe { AssignProcessToJobObject(job, info.hProcess) }.map_err(io_error)
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
        // SAFETY: snapshot handle is closed before return.
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(io_error)?;
        let mut raw = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut rows = Vec::new();
        // SAFETY: snapshot and output structure are valid.
        let mut next = unsafe { Process32FirstW(snapshot, &mut raw) };
        while next.is_ok() {
            if let Some(row) = entry(raw.th32ProcessID, Some(raw.th32ParentProcessID))? {
                rows.push(row);
            }
            raw = PROCESSENTRY32W {
                dwSize: size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            }; // SAFETY: same valid snapshot/output contract as Process32FirstW.
            next = unsafe { Process32NextW(snapshot, &mut raw) };
        }
        close(snapshot);
        Ok(rows)
    }
    fn reap_child(&self, key: ProcessKey) -> Result<ReapOutcome, PlatformError> {
        let mut map = children().lock().map_err(|_| PlatformError::Invalid {
            capability: "reap_child",
            detail: "child handle registry poisoned",
        })?;
        let Some(raw) = map.get(&key).copied() else {
            return Ok(ReapOutcome::NotOurChild);
        };
        let process = HANDLE(raw);
        // SAFETY: map retains this process handle while the lock is held.
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_TIMEOUT => Ok(ReapOutcome::StillRunning),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32; // SAFETY: signalled retained process handle and writable output.
                unsafe { GetExitCodeProcess(process, &mut code) }.map_err(io_error)?;
                map.remove(&key);
                close(process);
                Ok(ReapOutcome::Exited(code as i32))
            }
            WAIT_FAILED => Err(io_error(Error::from_win32())),
            _ => Err(PlatformError::Invalid {
                capability: "reap_child",
                detail: "unexpected wait result",
            }),
        }
    }
    fn secure_data_dir(&self, path: &Path) -> Result<(), PlatformError> {
        std::fs::create_dir_all(path)?;
        secure_directory_acl(path)
    }
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError> {
        std::env::var_os("ProgramData")
            .map(|value| PathBuf::from(value).join("AgentWatch"))
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
}

#[cfg(test)]
mod tests {
    use super::command_line;
    #[test]
    fn quotes_sensitive_args_without_logging_them() {
        let Ok(line) = command_line(&["cmd".to_owned(), "/c".to_owned(), "a b\\\"c\\".to_owned()])
        else {
            panic!("command line")
        };
        assert_eq!(line.last(), Some(&0));
        assert!(line.len() > 1);
    }
}
