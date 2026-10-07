//! Back-fill of a process command line and current directory.
//!
//! This module is the second FFI boundary in the crate (the first is `etw::ffi`).
//! `unsafe_code` stays `deny` on the crate. The allow below is this module only,
//! and every `unsafe` block carries a `SAFETY` comment.

#![cfg_attr(target_os = "windows", allow(unsafe_code))]
//!
//! The decode path in [`crate::etw::process`] never calls this module itself. It
//! hands a [`BackfillRequest`] to a [`crate::etw::process::BackfillPool`], and
//! the pool calls a [`ProcessReader`]. Tests supply a reader that returns canned
//! answers and never opens a process. The Windows reader is [`NtProcessReader`];
//! it is the only type here that touches a handle.
//!
//! What each answer means:
//!
//! | call | success | process already gone | anything else, including PPL |
//! |---|---|---|---|
//! | command line | [`ReadOutcome::Value`] at evidence S | [`ReadOutcome::Exited`] | [`ReadOutcome::Unavailable`] |
//! | cwd | [`ReadOutcome::Value`] at evidence S | [`ReadOutcome::Exited`] | [`ReadOutcome::Unavailable`] |
//!
//! An empty string is not a stand-in for "could not read". WOW64 (a 32-bit
//! process on 64-bit Windows) uses a separate PEB layout. When that path is not
//! implemented, cwd comes back [`ReadOutcome::Unavailable`] with
//! [`UnavailableReason::Wow64Unimplemented`] instead of `""`.
//!
//! Environment blocks are never read. PPL processes are not opened for
//! `PROCESS_VM_READ`: the reader asks for protection with
//! `PROCESS_QUERY_LIMITED_INFORMATION` first, and a protected process is
//! [`UnavailableReason::Ppl`].
//!
//! SPIKE-02 did not measure `NtQueryInformationProcess(ProcessCommandLineInformation)`
//! or the PEB layout. The information-class numbers and the offsets below are
//! copied from public Win32 headers, not from a recording on this machine.

use std::fmt;

/// Why a back-fill did not return a value.
///
/// These are collector-local. The event maps every one of them to
/// `NA(collector_unavailable)` except [`UnavailableReason::Exited`], which the
/// command-line path also maps to that same `NA` (the task's three-way split).
/// The specific reason stays here so a test can tell "the process exited" from
/// "we refused to open a PPL process".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// `OpenProcess` failed because the pid is already gone.
    Exited,
    /// The process is PPL (or otherwise protected). It was not opened for read.
    Ppl,
    /// 32-bit process on 64-bit Windows, and this build has no WOW64 PEB walk.
    Wow64Unimplemented,
    /// The API or the privilege is missing, or the read failed for another reason.
    Unreadable,
}

/// One back-fill result. `Unavailable` is not a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    /// Bytes the platform returned. Evidence level is decided by the caller (S).
    Value(String),
    /// The pid was already dead when the read was attempted.
    Exited,
    /// The read was not attempted, or it failed. `reason` says which.
    Unavailable(UnavailableReason),
}

impl ReadOutcome {
    /// `true` when this outcome is "process already exited".
    pub fn is_exited(&self) -> bool {
        matches!(
            self,
            Self::Exited | Self::Unavailable(UnavailableReason::Exited)
        )
    }
}

/// What the pool asks a [`ProcessReader`] for. One process, two questions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillRequest {
    /// Pid from the ProcessStart event. Not a `ProcUid`.
    pub pid: u32,
    /// `true` when the event itself had no command line.
    pub want_argv: bool,
    /// cwd is never on the Kernel-Process event this crate decodes, so a start
    /// always asks. The flag exists so a test can request one field at a time.
    pub want_cwd: bool,
}

/// Command line and cwd for one pid. Either field may be unavailable on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillAnswer {
    /// Set when [`BackfillRequest::want_argv`] was set. `None` means "not asked".
    pub argv: Option<ReadOutcome>,
    /// Set when [`BackfillRequest::want_cwd`] was set. `None` means "not asked".
    pub cwd: Option<ReadOutcome>,
}

/// Reads another process. Implemented for real by [`NtProcessReader`] and by
/// test doubles that return fixed answers.
///
/// The trait takes `&self` so a pool can share one reader across workers. A
/// reader that needs mutation interior-mutates it.
pub trait ProcessReader: Send + Sync {
    /// Read the fields `request` names. Must not read the environment block.
    fn read(&self, request: &BackfillRequest) -> BackfillAnswer;
}

/// A reader that never opens a process. Every asked field is unavailable.
///
/// Used when the pool is constructed without a platform reader (tests, and any
/// caller that has not been given a real reader).
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableReader;

impl ProcessReader for UnavailableReader {
    fn read(&self, request: &BackfillRequest) -> BackfillAnswer {
        let unavailable = ReadOutcome::Unavailable(UnavailableReason::Unreadable);
        BackfillAnswer {
            argv: request.want_argv.then(|| unavailable.clone()),
            cwd: request.want_cwd.then_some(unavailable),
        }
    }
}

/// Windows reader: command line through `NtQueryInformationProcess`, cwd through
/// the PEB. Not used by the decode tests.
///
/// # WOW64
///
/// A 32-bit process is detected with `IsWow64Process`. Its PEB is the 32-bit
/// PEB (`NtQueryInformationProcess` with `ProcessWow64Information`), whose
/// `ProcessParameters` uses 32-bit pointers. This build does **not** walk that
/// layout. cwd for a WOW64 process is [`UnavailableReason::Wow64Unimplemented`].
/// Returning an empty string would look like a successful read of an empty
/// directory. Command line is still attempted: `ProcessCommandLineInformation`
/// is a native query and does not depend on the PEB pointer width. SPIKE-02 has
/// not confirmed either path.
#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct NtProcessReader;

#[cfg(target_os = "windows")]
impl ProcessReader for NtProcessReader {
    fn read(&self, request: &BackfillRequest) -> BackfillAnswer {
        read_process(request)
    }
}

#[cfg(target_os = "windows")]
fn read_process(request: &BackfillRequest) -> BackfillAnswer {
    // Both questions share one open. Opening twice would race a short-lived
    // process into "exited" on the second call after the first succeeded.
    match ProcessHandle::open(request.pid) {
        Ok(handle) => BackfillAnswer {
            argv: request.want_argv.then(|| read_command_line(&handle)),
            cwd: request.want_cwd.then(|| read_cwd(&handle)),
        },
        Err(reason) => {
            let outcome = if reason == UnavailableReason::Exited {
                ReadOutcome::Exited
            } else {
                ReadOutcome::Unavailable(reason)
            };
            BackfillAnswer {
                argv: request.want_argv.then(|| outcome.clone()),
                cwd: request.want_cwd.then_some(outcome),
            }
        }
    }
}

/// Owned process handle. Drop closes it. The read methods borrow it.
#[cfg(target_os = "windows")]
struct ProcessHandle {
    raw: windows::Win32::Foundation::HANDLE,
    /// `IsWow64Process` result. `None` when the query itself failed.
    wow64: Option<bool>,
}

#[cfg(target_os = "windows")]
impl ProcessHandle {
    fn open(pid: u32) -> Result<Self, UnavailableReason> {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::System::Threading::{
            IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        // Protection is checked *before* asking for VM_READ. A PPL process
        // rejects PROCESS_VM_READ; opening it that way and then giving up is
        // still "we tried to read a protected process". Limited-information is
        // enough for `ProcessProtectionInformation` and does not include VM_READ.
        if is_ppl(pid) {
            return Err(UnavailableReason::Ppl);
        }

        let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        // SAFETY: `OpenProcess` returns a real handle or an error. We do not
        // dereference the handle here. `pid` is the caller's integer. The
        // inherit flag is false, so the handle is not passed to a child.
        let raw = unsafe { OpenProcess(access, false, pid) };
        let raw = match raw {
            Ok(handle) if !handle.is_invalid() => handle,
            _ => return Err(classify_open_error()),
        };

        let mut wow = BOOL(0);
        // SAFETY: `raw` is an open process handle. `wow` is a BOOL we own.
        // Failure leaves `wow64` as None; the cwd path then refuses rather
        // than assuming a native PEB.
        let wow64 = unsafe { IsWow64Process(raw, &mut wow) }
            .ok()
            .map(|_| wow.as_bool());

        Ok(Self { raw, wow64 })
    }
}

#[cfg(target_os = "windows")]
fn close_handle(raw: &mut windows::Win32::Foundation::HANDLE) {
    use windows::Win32::Foundation::CloseHandle;
    if raw.is_invalid() {
        return;
    }
    // SAFETY: `raw` came from `OpenProcess` and has not been closed yet. One
    // close, then the slot is invalidated so a second drop is a no-op.
    // `HANDLE`'s `Free` impl also calls `CloseHandle`; this function is the
    // only closer, and nothing else calls `Free::free` on the same value.
    let _ = unsafe { CloseHandle(*raw) };
    raw.0 = 0;
}

#[cfg(target_os = "windows")]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        close_handle(&mut self.raw);
    }
}

/// `ProcessProtectionInformation` (61). Public `ntdll` class, not measured by
/// SPIKE-02. A non-zero `Type` means the process is protected (PPL and friends).
#[cfg(target_os = "windows")]
const PROCESS_PROTECTION_INFORMATION: u32 = 61;

/// `ProcessCommandLineInformation` (60). Public `ntdll` class, Win8.1+.
/// SPIKE-02 has not confirmed the class number on this machine.
#[cfg(target_os = "windows")]
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

/// `ProcessBasicInformation` (0). Returns `PebBaseAddress`.
#[cfg(target_os = "windows")]
const PROCESS_BASIC_INFORMATION: u32 = 0;

/// `ProcessWow64Information` (26). Returns the 32-bit PEB address, or 0.
#[cfg(target_os = "windows")]
const PROCESS_WOW64_INFORMATION: u32 = 26;

/// Offset of `ProcessParameters` inside a native (64-bit) PEB.
///
/// Public x64 layout (Win10). SPIKE-02 did not dump a PEB on this machine, so a
/// mismatch is reported as [`UnavailableReason::Unreadable`] rather than a
/// guessed path.
#[cfg(target_os = "windows")]
const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20;

/// Offset of `CurrentDirectory` (`CURDIR`) inside `RTL_USER_PROCESS_PARAMETERS`
/// on x64. `CURDIR.DosPath` is a `UNICODE_STRING` (Length, MaximumLength, pad,
/// Buffer). SPIKE-02 has not confirmed this offset.
#[cfg(target_os = "windows")]
const PARAMS_CURRENT_DIRECTORY_OFFSET: usize = 0x38;

/// Cap on a single back-fill buffer. A command line or a cwd longer than this
/// is reported unavailable rather than allocated without a bound.
#[cfg(target_os = "windows")]
const MAX_BACKFILL_BYTES: u32 = 64 * 1024;

/// `STATUS_PROCESS_IS_TERMINATING`.
#[cfg(target_os = "windows")]
const STATUS_PROCESS_IS_TERMINATING: i32 = 0xC000_010A_u32 as i32;

/// `STATUS_INFO_LENGTH_MISMATCH`. The size-query status for a short buffer.
#[cfg(target_os = "windows")]
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

/// `STATUS_BUFFER_TOO_SMALL`.
#[cfg(target_os = "windows")]
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

/// `STATUS_BUFFER_OVERFLOW`.
#[cfg(target_os = "windows")]
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;

#[cfg(target_os = "windows")]
fn is_ppl(pid: u32) -> bool {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: limited query only. No VM_READ. The handle is closed before return.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let Ok(mut raw) = raw else {
        return false;
    };
    if raw.is_invalid() {
        return false;
    }
    let protected = query_protection(raw);
    close_handle(&mut raw);
    protected
}

/// `PS_PROTECTION`: one byte. `Type` is bits 0..2. Non-zero means protected.
#[cfg(target_os = "windows")]
#[repr(C)]
struct PsProtection {
    level: u8,
}

#[cfg(target_os = "windows")]
fn query_protection(raw: windows::Win32::Foundation::HANDLE) -> bool {
    let mut info = PsProtection { level: 0 };
    let mut returned = 0_u32;
    // SAFETY: `raw` is an open process handle. `info` is a one-byte buffer we
    // own, and `returned` is a u32 we own. The class number is the public
    // `ProcessProtectionInformation`. A failed query is "not known protected",
    // so the later VM_READ open still runs and fails on its own.
    let status = unsafe {
        NtQueryInformationProcess(
            raw,
            PROCESS_PROTECTION_INFORMATION,
            std::ptr::from_mut(&mut info).cast::<std::ffi::c_void>(),
            std::mem::size_of::<PsProtection>() as u32,
            &mut returned,
        )
    };
    if status != 0 {
        return false;
    }
    // Type == 0 is unprotected. Any other type (Protected, ProtectedLight) is PPL.
    info.level & 0b111 != 0
}

#[cfg(target_os = "windows")]
fn classify_open_error() -> UnavailableReason {
    // `OpenProcess` on a dead pid returns `ERROR_INVALID_PARAMETER` (87).
    // Access denied after the PPL pre-check is "unreadable": known PPL was
    // already refused, and a later denial (missing privilege) is not the same
    // fact. `GetLastError` is unsafe in this crate's windows binding.
    // SAFETY: no pointer. Reads the calling thread's last-error slot.
    let code = unsafe { windows::Win32::Foundation::GetLastError() };
    if code.0 == 87 {
        UnavailableReason::Exited
    } else {
        UnavailableReason::Unreadable
    }
}

#[cfg(target_os = "windows")]
fn read_command_line(handle: &ProcessHandle) -> ReadOutcome {
    // First call asks for the size. A failure that is not a size-query status
    // is unavailable, not an empty command line.
    let mut length = 0_u32;
    // SAFETY: null buffer with a zero length is the size-query pattern.
    // `length` is ours. The handle is open. Nothing is written except `length`.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    let size_query = status == STATUS_INFO_LENGTH_MISMATCH
        || status == STATUS_BUFFER_TOO_SMALL
        || status == STATUS_BUFFER_OVERFLOW;
    if !size_query && status != 0 {
        return if status == STATUS_PROCESS_IS_TERMINATING {
            ReadOutcome::Exited
        } else {
            ReadOutcome::Unavailable(UnavailableReason::Unreadable)
        };
    }
    if length == 0 || length > MAX_BACKFILL_BYTES {
        // Zero means the query gave no size. That is not an empty command line.
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    }
    let mut buf = vec![0_u8; length as usize];
    let mut returned = 0_u32;
    // SAFETY: `buf` is `length` bytes and we own it. The class writes a
    // `UNICODE_STRING`-shaped blob. We only read it after a zero status.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast::<std::ffi::c_void>(),
            length,
            &mut returned,
        )
    };
    if status == STATUS_PROCESS_IS_TERMINATING {
        return ReadOutcome::Exited;
    }
    if status != 0 {
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    }
    match unicode_string_from_buffer(&buf) {
        Some(text) => ReadOutcome::Value(text),
        None => ReadOutcome::Unavailable(UnavailableReason::Unreadable),
    }
}

#[cfg(target_os = "windows")]
fn read_cwd(handle: &ProcessHandle) -> ReadOutcome {
    // WOW64 has a different PEB. This build does not walk it. An empty string
    // would look like a successful read of an empty directory.
    match handle.wow64 {
        Some(true) => return ReadOutcome::Unavailable(UnavailableReason::Wow64Unimplemented),
        None => return ReadOutcome::Unavailable(UnavailableReason::Unreadable),
        Some(false) => {}
    }
    // Also refuse when `ProcessWow64Information` says there is a 32-bit PEB,
    // even if `IsWow64Process` said no. Disagreeing answers are not a native PEB.
    if wow64_peb_present(handle) {
        return ReadOutcome::Unavailable(UnavailableReason::Wow64Unimplemented);
    }

    let Some(peb) = peb_address(handle) else {
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    };
    let Some(params_addr) = read_pointer(handle, peb.wrapping_add(PEB_PROCESS_PARAMETERS_OFFSET))
    else {
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    };
    if params_addr == 0 {
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    }
    // `CURDIR.DosPath` at `PARAMS_CURRENT_DIRECTORY_OFFSET`: Length u16,
    // MaximumLength u16, pad u32, Buffer pointer.
    let dos = params_addr.wrapping_add(PARAMS_CURRENT_DIRECTORY_OFFSET);
    let Some(header) = read_bytes(handle, dos, 16) else {
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    };
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = usize_from_le(&header[8..16]);
    if buffer == 0 || length == 0 || length > MAX_BACKFILL_BYTES as usize {
        // A zero length is "no directory string", not a confirmed empty cwd.
        // windows.md says the field lives at CurrentDirectory; a zero buffer
        // means we did not read it.
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    }
    let Some(wide) = read_bytes(handle, buffer, length) else {
        return ReadOutcome::Unavailable(UnavailableReason::Unreadable);
    };
    ReadOutcome::Value(utf16_bytes_to_string(&wide))
}

#[cfg(target_os = "windows")]
fn usize_from_le(bytes: &[u8]) -> usize {
    let mut arr = [0_u8; 8];
    let n = bytes.len().min(8);
    arr[..n].copy_from_slice(&bytes[..n]);
    usize::from_le_bytes(arr)
}

#[cfg(target_os = "windows")]
fn wow64_peb_present(handle: &ProcessHandle) -> bool {
    let mut peb32 = 0_u64;
    let mut returned = 0_u32;
    // SAFETY: `peb32` is a u64 we own. The class writes a pointer-sized value.
    // Non-zero means a 32-bit PEB exists. We do not dereference it.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw,
            PROCESS_WOW64_INFORMATION,
            std::ptr::from_mut(&mut peb32).cast::<std::ffi::c_void>(),
            std::mem::size_of::<u64>() as u32,
            &mut returned,
        )
    };
    status == 0 && peb32 != 0
}

/// Public `PROCESS_BASIC_INFORMATION` on x64. Only `peb_base_address` is read.
#[cfg(target_os = "windows")]
#[repr(C)]
struct ProcessBasicInformation {
    exit_status: isize,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: isize,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[cfg(target_os = "windows")]
fn peb_address(handle: &ProcessHandle) -> Option<usize> {
    let mut info = ProcessBasicInformation {
        exit_status: 0,
        peb_base_address: 0,
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let mut returned = 0_u32;
    // SAFETY: `info` is ours and matches the public PROCESS_BASIC_INFORMATION
    // layout on x64. The handle is open. We only use `peb_base_address`.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw,
            PROCESS_BASIC_INFORMATION,
            std::ptr::from_mut(&mut info).cast::<std::ffi::c_void>(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut returned,
        )
    };
    if status != 0 || info.peb_base_address == 0 {
        None
    } else {
        Some(info.peb_base_address)
    }
}

#[cfg(target_os = "windows")]
fn read_pointer(handle: &ProcessHandle, address: usize) -> Option<usize> {
    let bytes = read_bytes(handle, address, std::mem::size_of::<usize>())?;
    Some(usize_from_le(&bytes))
}

#[cfg(target_os = "windows")]
fn read_bytes(handle: &ProcessHandle, address: usize, len: usize) -> Option<Vec<u8>> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    if len == 0 || len > MAX_BACKFILL_BYTES as usize || address == 0 {
        return None;
    }
    let mut buf = vec![0_u8; len];
    let mut read = 0_usize;
    // SAFETY: `buf` is `len` bytes we own. `address` is a remote address we do
    // not dereference locally. `ReadProcessMemory` writes into `buf` and sets
    // `read`. A failure returns None; a short read is not used as a value.
    let ok = unsafe {
        ReadProcessMemory(
            handle.raw,
            address as *const std::ffi::c_void,
            buf.as_mut_ptr().cast::<std::ffi::c_void>(),
            len,
            Some(&mut read),
        )
    };
    if ok.is_err() || read != len {
        None
    } else {
        Some(buf)
    }
}

/// Interpret a `UNICODE_STRING` written at the start of `buf`.
///
/// Layout: `Length: u16`, `MaximumLength: u16`, padding, `Buffer: *u16`.
/// This function only accepts the inline form: the characters sit immediately
/// after the 16-byte header. A remote `Buffer` pointer is not chased.
/// `ProcessCommandLineInformation` is supposed to return the string inline, and
/// chasing an arbitrary pointer from an unconfirmed layout (SPIKE-02 has no
/// dump) is not a read.
///
/// A header with `Length == 0` is a real empty command line, which is a value.
/// A buffer shorter than the header is not.
#[cfg(target_os = "windows")]
fn unicode_string_from_buffer(buf: &[u8]) -> Option<String> {
    if buf.len() < 16 {
        return None;
    }
    let length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if length == 0 {
        return Some(String::new());
    }
    let inline = buf.get(16..)?;
    let bytes = inline.get(..length)?;
    Some(utf16_bytes_to_string(bytes))
}

#[cfg(target_os = "windows")]
fn utf16_bytes_to_string(bytes: &[u8]) -> String {
    let (chunks, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = chunks
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_owned()
}

#[cfg(target_os = "windows")]
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: windows::Win32::Foundation::HANDLE,
        process_information_class: u32,
        process_information: *mut std::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited => f.write_str("process exited before the read"),
            Self::Ppl => f.write_str("process is PPL; not opened"),
            Self::Wow64Unimplemented => {
                f.write_str("WOW64 PEB walk is not implemented; cwd was not read")
            }
            Self::Unreadable => f.write_str("process memory was not readable"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_reader_never_returns_a_value() {
        let reader = UnavailableReader;
        let answer = reader.read(&BackfillRequest {
            pid: 4,
            want_argv: true,
            want_cwd: true,
        });
        assert_eq!(
            answer.argv,
            Some(ReadOutcome::Unavailable(UnavailableReason::Unreadable))
        );
        assert_eq!(
            answer.cwd,
            Some(ReadOutcome::Unavailable(UnavailableReason::Unreadable))
        );
        let skipped = reader.read(&BackfillRequest {
            pid: 4,
            want_argv: false,
            want_cwd: false,
        });
        assert!(skipped.argv.is_none());
        assert!(skipped.cwd.is_none());
    }

    #[test]
    fn exited_is_not_an_empty_string() {
        let outcome = ReadOutcome::Exited;
        assert!(outcome.is_exited());
        // The empty string is a value. It must not compare equal to a miss.
        assert_ne!(outcome, ReadOutcome::Value(String::new()));
        assert_ne!(
            ReadOutcome::Unavailable(UnavailableReason::Wow64Unimplemented),
            ReadOutcome::Value(String::new())
        );
    }
}
