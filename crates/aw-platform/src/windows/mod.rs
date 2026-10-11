//! Windows process identity.  FFI stays in the smallest functions that need it.

use crate::{
    Capability, CapabilityStatus, IdentifiedCaller, IntegrityLevel, Owner, PeerIdentity,
    PipeServerVerificationError, Platform, PlatformError, ProcessEntry, ProcessKey,
    SamplingProcess, SpawnRequest, UnsupportedKind,
};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use windows::core::{Error, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, FILETIME, HANDLE, HLOCAL, PSID,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    RevertToSelf, TokenElevation, TokenIntegrityLevel, TokenUser, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
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
#[allow(unused_imports)] // Kept with the named-pipe-fix import set for its boot-time helpers.
use windows::Win32::System::SystemInformation::{GetSystemTimeAsFileTime, GetTickCount64};
use windows::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
    SECURITY_MANDATORY_SYSTEM_RID,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetCurrentThread,
    GetExitCodeProcess, GetProcessTimes, InitializeProcThreadAttributeList, OpenProcess,
    OpenProcessToken, OpenThreadToken, QueryFullProcessImageNameW, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

pub(crate) struct CurrentPlatform;

/// `aw doctor` reports peer identification as available only after a real
/// named-pipe exchange has successfully read a client token.  A compiled API
/// alone is not evidence that the service can identify its callers.
static PIPE_PEER_IDENTIFICATION_WORKS: AtomicBool = AtomicBool::new(false);

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

pub fn note_pipe_peer_identification() {
    PIPE_PEER_IDENTIFICATION_WORKS.store(true, Ordering::Release);
}

fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "windows",
        kind: UnsupportedKind::NotInThisBuild,
    }
}

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

enum DataDirAcl<'a> {
    Machine,
    Owner(&'a str),
}

impl DataDirAcl<'_> {
    fn sddl(&self) -> String {
        match self {
            // `P` turns off inheritance. OI|CI applies the same two ACEs to
            // database, WAL, lock, and log files created underneath it.
            Self::Machine => "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)".to_owned(),
            Self::Owner(sid) => format!("D:P(A;OICI;GA;;;{sid})"),
        }
    }
}

fn wide_nul(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

fn is_machine_data_dir(path: &Path, default: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&default.as_os_str().to_string_lossy())
}

/// Reject symlinks and junctions/reparse points in every existing component.
/// The boolean tells the caller whether the final component existed before it
/// chose to create it; a pre-created directory gets an ownership check before
/// any ACL is altered.
fn validate_directory_path(path: &Path) -> Result<bool, PlatformError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let reparse = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
                if metadata.file_type().is_symlink() || reparse {
                    return Err(PlatformError::Invalid {
                        capability: "secure_data_dir",
                        detail: "data directory path contains a reparse point",
                    });
                }
                if !metadata.is_dir() {
                    return Err(PlatformError::Invalid {
                        capability: "secure_data_dir",
                        detail: "data directory path contains a non-directory",
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

fn sid_text(sid: PSID) -> Result<String, PlatformError> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` comes from a live token or security descriptor; Windows
    // allocates a NUL-terminated LocalAlloc buffer for `text`.
    #[allow(unsafe_code)]
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(io_error)?;
    // SAFETY: the successful API call above produced a valid UTF-16 string.
    #[allow(unsafe_code)]
    let result = unsafe { text.to_string() }.map_err(|_| PlatformError::Invalid {
        capability: "secure_data_dir",
        detail: "SID was not valid UTF-16",
    });
    // SAFETY: ConvertSidToStringSidW allocated `text` with LocalAlloc.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(text.0.cast())) };
    result
}

fn owner_sid_for_path(path: &Path) -> Result<String, PlatformError> {
    let wide = wide_nul(path.as_os_str());
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is NUL terminated; output pointers are valid and the
    // descriptor remains live until its LocalFree below.
    #[allow(unsafe_code)]
    let result = unsafe {
        GetNamedSecurityInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        )
    }
    .ok()
    .map_err(io_error)
    .and_then(|()| sid_text(owner));
    // SAFETY: GetNamedSecurityInfoW allocates the descriptor with LocalAlloc
    // on success; the default/null value is safe to pass to LocalFree too.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
    result
}

fn set_data_dir_dacl(path: &Path, policy: DataDirAcl<'_>) -> Result<(), PlatformError> {
    let sddl = policy.sddl();
    let sddl_wide = wide_nul(OsStr::new(&sddl));
    let path_wide = wide_nul(path.as_os_str());
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_wide` is a NUL-terminated Rust-owned SDDL string; Windows
    // writes the returned LocalAlloc descriptor pointer into valid storage.
    #[allow(unsafe_code)]
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io_error)?;
    let mut dacl_present = windows::Win32::Foundation::BOOL(0);
    let mut dacl_defaulted = windows::Win32::Foundation::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: descriptor is the valid self-relative descriptor returned above;
    // all output locations are writable for the duration of this function.
    #[allow(unsafe_code)]
    let result = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .map_err(io_error)
    .and_then(|()| {
        if dacl_present.0 == 0 || dacl.is_null() {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "generated data-directory DACL is absent",
            });
        }
        // SAFETY: `path_wide` is NUL terminated and `dacl` points into the
        // live descriptor. Passing DACL|PROTECTED makes inherited ProgramData
        // ACEs disappear instead of leaving a read path for ordinary users.
        #[allow(unsafe_code)]
        unsafe {
            SetNamedSecurityInfoW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                PSID::default(),
                PSID::default(),
                Some(dacl.cast_const()),
                None,
            )
        }
        .ok()
        .map_err(io_error)
    });
    // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW allocated
    // the descriptor with LocalAlloc; no pointer into it is used after this.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
    result
}

fn secure_data_dir_with_policy(
    path: &Path,
    expected_owner: impl Fn(&str) -> bool,
    policy: DataDirAcl<'_>,
) -> Result<(), PlatformError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let existed = validate_directory_path(&absolute)?;
    if existed && !expected_owner(&owner_sid_for_path(&absolute)?) {
        return Err(PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "data directory owner is not trusted",
        });
    }
    std::fs::create_dir_all(&absolute)?;
    if !validate_directory_path(&absolute)? {
        return Err(PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "data directory disappeared while it was being created",
        });
    }
    if !expected_owner(&owner_sid_for_path(&absolute)?) {
        return Err(PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "data directory owner changed while it was being secured",
        });
    }
    set_data_dir_dacl(&absolute, policy)
}

fn io_error(error: Error) -> PlatformError {
    PlatformError::Io(std::io::Error::from_raw_os_error(error.code().0 & 0xffff))
}

/// Preserve the exact Win32 failure from a pipe-authentication primitive. The
/// daemon turns it into its fixed 403 response, while its warning log retains
/// the operation and code for diagnosis.
fn pipe_peer_error(operation: &'static str, error: Error) -> PlatformError {
    PlatformError::PipePeerNotIdentified {
        operation,
        win32_error: error.code().0 & 0xffff,
    }
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

/// A process-lifetime boot discriminator: the System process (pid 4) creation
/// FILETIME. Unlike wall-clock minus uptime it is not affected by NTP or a
/// sampling-time rounding boundary. `aw-collector-poll` calls the public
/// wrapper below, so both identities use these exact bytes.
fn sampling_boot_id() -> &'static Vec<u8> {
    static BOOT_ID: OnceLock<Vec<u8>> = OnceLock::new();
    BOOT_ID.get_or_init(|| {
        // SAFETY: OpenProcess requests only query access to the System process;
        // any returned handle is closed before this helper returns.
        #[allow(unsafe_code)]
        let system = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, 4) };
        let Ok(system) = system else {
            return Vec::new();
        };
        let created = creation_time(system).ok();
        close(system);
        created
            .map(|time| time.to_string().into_bytes())
            .unwrap_or_default()
    })
}

pub(crate) fn system_boot_id() -> Option<Vec<u8>> {
    let value = sampling_boot_id();
    (!value.is_empty()).then(|| value.clone())
}

fn unix_ns_from_filetime(filetime: u64) -> Option<u64> {
    const WINDOWS_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;
    filetime
        .checked_sub(WINDOWS_TO_UNIX_100NS)
        .and_then(|ticks| ticks.checked_mul(100))
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
    sid_text(user.User.Sid)
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

fn owner_for_token(token: HANDLE) -> Result<Owner, PlatformError> {
    Ok(Owner::Windows {
        sid: sid_for_token(token)?,
        elevated: elevated_for_token(token)?,
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

fn snapshot_pids() -> Result<Vec<(u32, u32)>, PlatformError> {
    // SAFETY: the returned snapshot handle is owned here and closed below.
    #[allow(unsafe_code)]
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(io_error)?;
    let mut raw = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut pids = Vec::new();
    // SAFETY: `snapshot` and `raw` are valid for the ToolHelp enumeration.
    #[allow(unsafe_code)]
    let mut next = unsafe { Process32FirstW(snapshot, &mut raw) };
    while next.is_ok() {
        pids.push((raw.th32ProcessID, raw.th32ParentProcessID));
        raw = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        // SAFETY: same snapshot/output contract as Process32FirstW.
        #[allow(unsafe_code)]
        {
            next = unsafe { Process32NextW(snapshot, &mut raw) };
        }
    }
    close(snapshot);
    Ok(pids)
}

fn sampling_entry(
    pid: u32,
    ppid: u32,
    boot_id: &[u8],
) -> Result<Option<SamplingProcess>, PlatformError> {
    // SAFETY: requests limited query access and closes the owned result below.
    #[allow(unsafe_code)]
    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => handle,
        Err(_) => return Ok(None),
    };
    let created = creation_time(process);
    close(process);
    let created = match created {
        Ok(created) => created,
        Err(_) => return Ok(None),
    };
    let Some(start_ns) = unix_ns_from_filetime(created) else {
        return Ok(None);
    };
    Ok(Some(SamplingProcess {
        key: ProcessKey {
            pid,
            start_time: created,
        },
        ppid,
        start_ns,
        boot_id: boot_id.to_vec(),
    }))
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
    environment_from(std::env::vars_os(), extra)
}

fn environment_from(
    inherited: impl IntoIterator<Item = (OsString, OsString)>,
    extra: &[(String, String)],
) -> Vec<u16> {
    let mut vars: BTreeMap<Vec<u16>, (OsString, OsString)> = inherited
        .into_iter()
        .map(|(key, value)| (environment_key(&key), (key, value)))
        .collect();
    for (key, value) in extra {
        let key = OsString::from(key);
        vars.insert(environment_key(&key), (key, OsString::from(value)));
    }
    let mut block = Vec::new();
    for (_, (key, value)) in vars {
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

/// Windows environment variable names are case-insensitive.  The actual
/// spelling remains in the block, but this key makes an explicit `--env`
/// replace inherited `Path`, `PATH`, or any other case variant.
fn environment_key(key: &OsStr) -> Vec<u16> {
    String::from_utf16_lossy(&key.encode_wide().collect::<Vec<_>>())
        .to_uppercase()
        .encode_utf16()
        .collect()
}

/// Inheritable duplicates of precisely the three standard handles.  Duplicating
/// instead of changing the inheritable flag on the originals prevents a
/// concurrent `CreateProcess` in this process from inheriting them by accident.
struct InheritedStdHandles {
    handles: [HANDLE; 3],
}

impl InheritedStdHandles {
    fn for_current_process() -> Result<Self, PlatformError> {
        let std_handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
        // Construct the owner first. Any `?` below then invokes Drop and
        // closes duplicates already made for earlier standard streams.
        let mut inherited = Self {
            handles: [HANDLE::default(); 3],
        };
        for (slot, which) in inherited.handles.iter_mut().zip(std_handles) {
            // SAFETY: `which` names one of the current process's standard handles.
            #[allow(unsafe_code)]
            let source = unsafe { GetStdHandle(which) }.map_err(io_error)?;
            if source.is_invalid() || source == HANDLE::default() {
                *slot = inheritable_nul(which)?;
                continue;
            }
            // SAFETY: both process pseudo-handles are the current process and
            // `slot` is writable storage for one owned duplicate.
            #[allow(unsafe_code)]
            if let Err(error) = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source,
                    GetCurrentProcess(),
                    slot,
                    0,
                    true,
                    DUPLICATE_SAME_ACCESS,
                )
            } {
                return Err(io_error(error));
            }
        }
        Ok(inherited)
    }
}

/// An inheritable `NUL` replacement for an absent standard handle. A console
/// detached by Task Scheduler or a GUI host must not make `aw run` refuse to
/// start the target. Input reads EOF; output and error are discarded.
fn inheritable_nul(
    which: windows::Win32::System::Console::STD_HANDLE,
) -> Result<HANDLE, PlatformError> {
    const NUL: [u16; 4] = [b'N' as u16, b'U' as u16, b'L' as u16, 0];
    let access = if which == STD_INPUT_HANDLE {
        FILE_GENERIC_READ.0
    } else {
        FILE_GENERIC_WRITE.0
    };
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: windows::Win32::Foundation::BOOL(1),
    };
    // SAFETY: NUL is a static NUL-terminated device name and the security
    // attributes are valid for this call; the returned handle is owned by the
    // caller and closed by InheritedStdHandles::Drop.
    #[allow(unsafe_code)]
    unsafe {
        CreateFileW(
            windows::core::PCWSTR(NUL.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&attributes),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    }
    .map_err(io_error)
}

impl Drop for InheritedStdHandles {
    fn drop(&mut self) {
        for handle in self.handles {
            close(handle);
        }
    }
}

/// Owns the opaque backing allocation used by `STARTUPINFOEXW`.
struct AttributeList {
    storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn with_handles(handles: &[HANDLE; 3]) -> Result<Self, PlatformError> {
        let mut bytes = 0_usize;
        // SAFETY: Windows documents a null first call as the sizing query.
        #[allow(unsafe_code)]
        let _ = unsafe {
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST::default(),
                1,
                0,
                &mut bytes,
            )
        };
        if bytes == 0 {
            return Err(io_error(Error::from_win32()));
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        // SAFETY: `storage` is suitably aligned and has at least the requested
        // byte count, and remains live until Drop deletes the list.
        #[allow(unsafe_code)]
        unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) }.map_err(io_error)?;
        // SAFETY: `handles` stays live until CreateProcessW returns, and its
        // byte length precisely describes the three inheritable duplicates.
        #[allow(unsafe_code)]
        if let Err(error) = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                size_of_val(handles),
                None,
                None,
            )
        } {
            // SAFETY: initialization above succeeded, so Windows owns list metadata.
            #[allow(unsafe_code)]
            unsafe {
                DeleteProcThreadAttributeList(list)
            };
            return Err(io_error(error));
        }
        Ok(Self { storage, list })
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: only a successfully initialized list constructs AttributeList;
        // its backing allocation is still live while this destructor runs.
        #[allow(unsafe_code)]
        unsafe {
            DeleteProcThreadAttributeList(self.list)
        };
        let _ = self.storage.len();
    }
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

/// Termination is best-effort during Drop/abort. Never let a stuck kernel wait
/// block daemon shutdown indefinitely.
const KILL_REAP_TIMEOUT_MS: u32 = 5_000;

impl WindowsHeldChild {
    fn kill_reap_close(&mut self) {
        if !self.process.is_invalid() {
            // SAFETY: process is the owned handle returned by CreateProcessW.
            #[allow(unsafe_code)]
            let _ = unsafe { TerminateProcess(self.process, 1) };
            // SAFETY: wait uses that still-owned process handle before it closes.
            #[allow(unsafe_code)]
            let _ = unsafe { WaitForSingleObject(self.process, KILL_REAP_TIMEOUT_MS) };
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
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }
        .map_err(|error| pipe_peer_error("GetNamedPipeClientProcessId", error))?;
    // Keep impersonation synchronous and as small as possible. In particular,
    // do not await while this thread has the client token. `Drop` is also the
    // error path for OpenThreadToken, so RevertToSelf is never skipped.
    let mut impersonation = PipeImpersonation::begin(pipe)?;
    let mut token = HANDLE::default();
    // SAFETY: while `impersonation` is live, the current thread has the
    // connected client's token and `token` is writable output storage.
    #[allow(unsafe_code)]
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    // Revert before doing any work with the duplicated token. If Windows
    // refuses to revert, continuing this IPC thread would run future requests
    // as the client, so `PipeImpersonation` terminates the process instead.
    impersonation.revert_or_abort();
    if let Err(error) = opened {
        return Err(pipe_peer_error("OpenThreadToken", error));
    }
    let owner = owner_for_token(token).map_err(|error| {
        let win32_error = match error {
            PlatformError::Io(ref inner) => inner.raw_os_error().unwrap_or_default(),
            PlatformError::PipePeerNotIdentified { win32_error, .. } => win32_error,
            _ => 0,
        };
        PlatformError::PipePeerNotIdentified {
            operation: "GetTokenInformation(client token)",
            win32_error,
        }
    });
    close(token);
    let peer = owner.map(|owner| PeerIdentity::new(owner, Some(pid)))?;
    note_pipe_peer_identification();
    Ok(peer)
}

/// An impersonation scope for one pipe request. `RevertToSelf` failure is
/// process-fatal: Windows leaves the thread impersonating, and this daemon's
/// IPC runtime may otherwise accept a later request on that same thread.
struct PipeImpersonation {
    active: bool,
}

impl PipeImpersonation {
    fn begin(pipe: HANDLE) -> Result<Self, PlatformError> {
        // SAFETY: `pipe` is the connected server end supplied by the IPC
        // listener, after it has read request bytes from this client.
        #[allow(unsafe_code)]
        unsafe { ImpersonateNamedPipeClient(pipe) }
            .map_err(|error| pipe_peer_error("ImpersonateNamedPipeClient", error))?;
        Ok(Self { active: true })
    }

    fn revert_or_abort(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: a successful `begin` above impersonated this current thread.
        #[allow(unsafe_code)]
        let reverted = unsafe { RevertToSelf() };
        if reverted.is_err() {
            // There is no safe way to return to the tokio IPC thread while it
            // may still be running as a client. The service manager restarts a
            // service process; a foreground daemon exits rather than serving
            // with the wrong token.
            eprintln!("agentwatch: RevertToSelf failed; aborting the process");
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for PipeImpersonation {
    fn drop(&mut self) {
        self.revert_or_abort();
    }
}

/// Verify the owner of the connected pipe object itself. This deliberately
/// does not inspect the server process token: ordinary users can read the
/// pipe object's `READ_CONTROL` owner even when the daemon runs as LocalSystem
/// and its process token is inaccessible to them.
///
/// Only LocalSystem and the current user's SID are valid daemon owners. The
/// caller turns both failure kinds into a local refusal before sending bytes.
pub fn verify_pipe_server(
    handle: std::os::windows::io::RawHandle,
) -> Result<(), PipeServerVerificationError> {
    let current_sid = current_pipe_client_sid()?;
    verify_pipe_server_for_owners(handle, &[LOCAL_SYSTEM_SID, &current_sid])
}

/// Verify an already-connected pipe against an explicit owner allowlist.
///
/// The production caller uses [`verify_pipe_server`]. Keeping the allowlist
/// explicit here gives Windows integration tests a way to prove that a
/// connected but untrusted peer receives zero request bytes.
pub fn verify_pipe_server_for_owners(
    handle: std::os::windows::io::RawHandle,
    trusted_owners: &[&str],
) -> Result<(), PipeServerVerificationError> {
    let owner_sid = pipe_owner_sid(HANDLE(handle as isize))?;
    if trusted_pipe_owner(&owner_sid, trusted_owners) {
        Ok(())
    } else {
        Err(PipeServerVerificationError::NotDaemon)
    }
}

fn trusted_pipe_owner(owner_sid: &str, trusted_owners: &[&str]) -> bool {
    trusted_owners.contains(&owner_sid)
}

fn current_pipe_client_sid() -> Result<String, PipeServerVerificationError> {
    match CurrentPlatform.current_owner() {
        Ok(Owner::Windows { sid, .. }) => Ok(sid),
        Ok(Owner::Unix { .. }) => Err(PipeServerVerificationError::CannotQuery {
            operation: "GetTokenInformation(current process)",
            win32_error: 0,
        }),
        Err(error) => Err(PipeServerVerificationError::CannotQuery {
            operation: "GetTokenInformation(current process)",
            win32_error: platform_win32_error(&error),
        }),
    }
}

fn pipe_owner_sid(pipe: HANDLE) -> Result<String, PipeServerVerificationError> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `pipe` is this process's open client handle. The output pointers
    // are writable and the returned LocalAlloc descriptor is freed below.
    #[allow(unsafe_code)]
    let status = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.is_err() {
        return Err(PipeServerVerificationError::CannotQuery {
            operation: "GetSecurityInfo(pipe owner)",
            win32_error: status.0,
        });
    }
    let result = pipe_sid_text(owner).map_err(|error| PipeServerVerificationError::CannotQuery {
        operation: "ConvertSidToStringSidW(pipe owner)",
        win32_error: error.code().0 as u32 & 0xffff,
    });
    // SAFETY: successful GetSecurityInfo allocated `descriptor` with LocalAlloc.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
    result
}

fn pipe_sid_text(sid: PSID) -> Result<String, Error> {
    if sid.0.is_null() {
        return Err(Error::from_win32());
    }
    let mut text = PWSTR::null();
    // SAFETY: `sid` is valid for the duration of this call; Windows allocates
    // a NUL-terminated string which is freed below on every outcome.
    #[allow(unsafe_code)]
    unsafe { ConvertSidToStringSidW(sid, &mut text) }?;
    // SAFETY: a successful conversion returned a NUL-terminated LocalAlloc
    // string. `to_string` copies it before the allocation is freed.
    #[allow(unsafe_code)]
    let result = unsafe { text.to_string() };
    // SAFETY: ConvertSidToStringSidW allocated `text` with LocalAlloc.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(text.0.cast())) };
    result.map_err(|_| Error::from_win32())
}

fn platform_win32_error(error: &PlatformError) -> u32 {
    match error {
        PlatformError::Io(inner) => inner.raw_os_error().unwrap_or_default() as u32,
        PlatformError::PipePeerNotIdentified { win32_error, .. } => *win32_error as u32,
        _ => 0,
    }
}

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "windows"
    }

    fn host_anchor_pid(&self) -> u32 {
        // PID 4 is the System process, the Windows process-tree root. Unlike
        // Unix, PID 1 is normally absent and must never be used as an anchor.
        4
    }

    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            Capability::SpawnSuspended
            | Capability::ProcessIdentity
            | Capability::ProcessTable
            | Capability::ExitCode => CapabilityStatus::Available,
            Capability::PeerIdentity => {
                if PIPE_PEER_IDENTIFICATION_WORKS.load(Ordering::Acquire) {
                    CapabilityStatus::Available
                } else {
                    CapabilityStatus::Unavailable
                }
            }
            // The platform primitive can validate a pipe peer's token, but the
            // daemon has not wired its launch API to that primitive yet.
            Capability::SpawnAsCaller => CapabilityStatus::NotInThisBuild,
            Capability::SecureDataDir => CapabilityStatus::Available,
        }
    }

    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn crate::HeldChild>, PlatformError> {
        // `CreateProcessW` always uses this process's token.  It must never
        // turn a named-pipe caller into a process running as the daemon (for
        // example, LocalSystem).  Launch-as-caller needs a token-aware path;
        // until that exists, refuse any different OS-authenticated owner.
        if caller.owner() != &self.current_owner()? {
            return Err(no("spawn_suspended_for_other_user"));
        }
        let mut command = command_line(&request.command)?;
        let mut env = environment(&request.env);
        let inherited = InheritedStdHandles::for_current_process()?;
        let attributes = AttributeList::with_handles(&inherited.handles)?;
        // SAFETY: STARTUPINFOEXW is documented as zero-initialized before cb is set.
        #[allow(unsafe_code)]
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited.handles[0];
        startup.StartupInfo.hStdOutput = inherited.handles[1];
        startup.StartupInfo.hStdError = inherited.handles[2];
        startup.lpAttributeList = attributes.list;
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
        let flags = PROCESS_CREATION_FLAGS(
            CREATE_SUSPENDED.0 | CREATE_UNICODE_ENVIRONMENT.0 | EXTENDED_STARTUPINFO_PRESENT.0,
        );
        // SAFETY: command/environment/cwd buffers are live for the synchronous
        // call; handle inheritance is constrained by the explicit attribute list
        // to the three inheritable standard-handle duplicates, and it starts suspended.
        #[allow(unsafe_code)]
        let created = unsafe {
            CreateProcessW(
                windows::core::PCWSTR::null(),
                PWSTR(command.as_mut_ptr()),
                None,
                None,
                true,
                flags,
                Some(env.as_mut_ptr().cast()),
                cwd.as_ref().map_or(windows::core::PCWSTR::null(), |value| {
                    windows::core::PCWSTR(value.as_ptr())
                }),
                &startup.StartupInfo,
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
        let mut rows = Vec::new();
        for (pid, ppid) in snapshot_pids()? {
            if let Some(row) = entry(pid, Some(ppid))? {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    fn sampling_process(&self, pid: u32) -> Result<Option<SamplingProcess>, PlatformError> {
        let Some((_, ppid)) = snapshot_pids()?.into_iter().find(|(item, _)| *item == pid) else {
            return Ok(None);
        };
        sampling_entry(pid, ppid, sampling_boot_id())
    }
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError> {
        let boot_id = sampling_boot_id();
        let mut rows = Vec::new();
        for (pid, ppid) in snapshot_pids()? {
            if let Some(process) = sampling_entry(pid, ppid, boot_id)? {
                rows.push(process);
            }
        }
        Ok(rows)
    }
    fn secure_data_dir(&self, path: &Path) -> Result<(), PlatformError> {
        let Owner::Windows { sid, .. } = self.current_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Windows account",
            });
        };
        let default = self.default_data_dir()?;
        if is_machine_data_dir(path, &default) {
            secure_data_dir_with_policy(
                path,
                |owner| owner == SYSTEM_SID || owner == ADMINISTRATORS_SID,
                DataDirAcl::Machine,
            )
        } else {
            secure_data_dir_with_policy(path, |owner| owner == sid, DataDirAcl::Owner(&sid))
        }
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
    #[allow(unused_imports)] // Kept with the named-pipe-fix test import set.
    use super::{
        close, environment_from, owner_sid_for_path, secure_data_dir_with_policy,
        set_data_dir_dacl, sid_text, trusted_pipe_owner, CurrentPlatform, DataDirAcl,
        ADMINISTRATORS_SID, SYSTEM_SID,
    };
    use crate::{
        platform, Capability, CapabilityStatus, IdentifiedCaller, IntegrityLevel, Owner,
        PeerIdentity, Platform, PlatformError, ReapOutcome, SpawnRequest, UnsupportedKind,
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{HLOCAL, PSID};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };
    use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    #[derive(Debug, PartialEq, Eq)]
    struct DaclReadback {
        protected: bool,
        aces: Vec<(String, u32, u8)>,
    }

    /// `icacls`-equivalent readback used by the ACL test. It deliberately
    /// reads the DACL Windows stored, rather than asserting the SDDL input
    /// string, so inheritance and unexpected Users/Everyone ACEs are visible.
    fn read_dacl(path: &std::path::Path) -> Result<DaclReadback, PlatformError> {
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the path is NUL terminated and output storage remains live
        // until the descriptor is released after all ACEs are read.
        #[allow(unsafe_code)]
        let result = unsafe {
            GetNamedSecurityInfoW(
                windows::core::PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        }
        .ok()
        .map_err(super::io_error)
        .and_then(|()| {
            if dacl.is_null() {
                return Err(PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "data-directory DACL is absent",
                });
            }
            let mut control = 0_u16;
            let mut revision = 0_u32;
            // SAFETY: descriptor is live and came from GetNamedSecurityInfoW;
            // both output locations are writable.
            #[allow(unsafe_code)]
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                .map_err(super::io_error)?;
            let mut aces = Vec::new();
            // SAFETY: the DACL is contained in the still-live descriptor.
            #[allow(unsafe_code)]
            let ace_count = unsafe { (*dacl).AceCount };
            for index in 0..u32::from(ace_count) {
                let mut ace = std::ptr::null_mut();
                // SAFETY: index is below AceCount and `ace` is writable
                // storage for the address owned by the DACL.
                #[allow(unsafe_code)]
                unsafe { GetAce(dacl, index, &mut ace) }.map_err(super::io_error)?;
                // SAFETY: an ACCESS_ALLOWED_ACE begins with the returned ACE
                // address when its type says ACCESS_ALLOWED_ACE_TYPE. Other
                // types are rejected below before their fields are used.
                #[allow(unsafe_code)]
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                if u32::from(allowed.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                    return Err(PlatformError::Invalid {
                        capability: "secure_data_dir",
                        detail: "data-directory DACL has a non-allow ACE",
                    });
                }
                // SAFETY: SidStart is the first u32 of the variable-length SID
                // immediately following the fixed ACCESS_ALLOWED_ACE header.
                let sid = PSID(std::ptr::addr_of!(allowed.SidStart).cast_mut().cast());
                aces.push((sid_text(sid)?, allowed.Mask, allowed.Header.AceFlags));
            }
            Ok(DaclReadback {
                protected: (control & SE_DACL_PROTECTED.0) != 0,
                aces,
            })
        });
        // SAFETY: GetNamedSecurityInfoW allocated the descriptor with LocalAlloc.
        #[allow(unsafe_code)]
        let _ = unsafe { windows::Win32::Foundation::LocalFree(HLOCAL(descriptor.0.cast())) };
        result
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "agentwatch-platform-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ))
    }

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
        assert_eq!(
            CurrentPlatform.capability(Capability::SecureDataDir),
            CapabilityStatus::Available
        );
    }

    #[test]
    fn machine_data_dir_dacl_is_exactly_system_and_administrators() -> Result<(), PlatformError> {
        let root = temp_dir("machine-dacl");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        set_data_dir_dacl(&data, DataDirAcl::Machine)?;
        let readback = read_dacl(&data)?;
        // Restore the creator's access before cleanup. This is outside the
        // assertion: the readback above is the state the daemon leaves behind.
        let owner = owner_sid_for_path(&data)?;
        set_data_dir_dacl(&data, DataDirAcl::Owner(&owner))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(readback.protected, "DACL inheritance must be disabled");
        assert_eq!(readback.aces.len(), 2, "no Users/Everyone/other ACEs");
        assert!(readback.aces.iter().all(|(_, mask, flags)| {
            *mask == windows::Win32::Foundation::GENERIC_ALL.0 && *flags == 3
        }));
        let mut sids: Vec<&str> = readback
            .aces
            .iter()
            .map(|(sid, _, _)| sid.as_str())
            .collect();
        sids.sort_unstable();
        assert_eq!(sids, vec![SYSTEM_SID, ADMINISTRATORS_SID]);
        Ok(())
    }

    #[test]
    fn machine_data_dir_refuses_a_precreated_normal_owner() -> Result<(), PlatformError> {
        let root = temp_dir("foreign-owner");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        let Err(error) = secure_data_dir_with_policy(&data, |_| false, DataDirAcl::Machine) else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "normal user's pre-created directory was accepted",
            });
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory owner is not trusted",
            }
        ));
        Ok(())
    }

    #[test]
    fn pipe_server_must_be_system_or_this_user() {
        let user = "S-1-5-21-10-20-30-1001";
        assert!(trusted_pipe_owner("S-1-5-18", &["S-1-5-18", user]));
        assert!(trusted_pipe_owner(user, &["S-1-5-18", user]));
        assert!(!trusted_pipe_owner(
            "S-1-5-21-10-20-30-1002",
            &["S-1-5-18", user]
        ));
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

    #[test]
    fn released_child_keeps_exit_code_300() {
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["cmd".to_owned(), "/c".to_owned(), "exit 300".to_owned()],
            cwd: None,
            env: Vec::new(),
        };
        let released = platform()
            .spawn_suspended(&caller, &request)
            .expect("held Windows child")
            .release()
            .expect("released Windows child");
        assert_eq!(
            released.wait().expect("reap child"),
            ReapOutcome::Exited(300)
        );
    }

    #[test]
    fn released_child_keeps_ntstatus_exit_code() {
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec![
                "cmd".to_owned(),
                "/c".to_owned(),
                "exit -1073741819".to_owned(),
            ],
            cwd: None,
            env: Vec::new(),
        };
        let released = platform()
            .spawn_suspended(&caller, &request)
            .expect("held Windows child")
            .release()
            .expect("released Windows child");
        assert_eq!(
            released.wait().expect("reap child"),
            ReapOutcome::Exited(-1_073_741_819)
        );
    }

    #[test]
    fn sampler_reads_the_current_process_with_a_stable_boot_discriminator() {
        let first = platform()
            .sampling_process(std::process::id())
            .expect("sample current process")
            .expect("current process exists");
        let second = platform()
            .sampling_process(std::process::id())
            .expect("sample current process again")
            .expect("current process exists again");
        assert_eq!(first.key, second.key);
        assert_eq!(first.boot_id, second.boot_id);
        assert!(first.start_ns > 0);
    }

    #[test]
    fn environment_override_is_case_insensitive_and_preserves_other_values() {
        let block = environment_from(
            [
                ("Path".into(), "old-path".into()),
                ("KEEP".into(), "still-here".into()),
            ],
            &[("path".to_owned(), "new-path".to_owned())],
        );
        let values: Vec<String> = block
            .split(|unit| *unit == 0)
            .filter(|part| !part.is_empty())
            .map(String::from_utf16_lossy)
            .collect();
        assert!(values.iter().any(|value| value == "path=new-path"));
        assert!(values.iter().any(|value| value == "KEEP=still-here"));
        assert_eq!(
            values
                .iter()
                .filter(|value| value
                    .split_once('=')
                    .is_some_and(|(key, _)| key.eq_ignore_ascii_case("path")))
                .count(),
            1
        );
    }

    #[test]
    fn refuses_to_launch_a_different_pipe_owner_as_the_daemon() {
        let caller = IdentifiedCaller::from_peer(PeerIdentity::new(
            Owner::Windows {
                sid: "S-1-5-21-424242".to_owned(),
                elevated: false,
                integrity: Some(IntegrityLevel::Medium),
            },
            Some(42),
        ));
        let request = SpawnRequest {
            command: vec!["cmd".to_owned(), "/c".to_owned(), "exit 0".to_owned()],
            cwd: None,
            env: Vec::new(),
        };

        let error = match CurrentPlatform.spawn_suspended(&caller, &request) {
            Ok(_) => panic!("another owner must not be launched with our token"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PlatformError::Unsupported {
                capability: "spawn_suspended_for_other_user",
                os: "windows",
                kind: UnsupportedKind::NotInThisBuild,
            }
        ));
    }

    #[test]
    fn suspended_child_writes_to_the_explicit_stdout_pipe() {
        // A separate test process gives its actual stdout to the suspended
        // target. This verifies the inherited explicit handle without mutating
        // the Rust test runner's own standard handles, so CI can run it.
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "windows::tests::suspended_child_writes_to_inherited_stdout_in_child",
                "--nocapture",
            ])
            .output()
            .expect("run child test process");
        assert!(
            output.status.success(),
            "child test stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("hello"),
            "target output was not forwarded"
        );
    }

    #[test]
    fn suspended_child_writes_to_inherited_stdout_in_child() {
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["cmd".to_owned(), "/c".to_owned(), "echo hello".to_owned()],
            cwd: None,
            env: Vec::new(),
        };
        let held = platform()
            .spawn_suspended(&caller, &request)
            .expect("held Windows child");
        let released = held.release().expect("released child");
        assert_eq!(released.wait().expect("reap child"), ReapOutcome::Exited(0));
    }
}
