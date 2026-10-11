//! Windows process identity.  FFI stays in the smallest functions that need it.

use crate::{
    Capability, CapabilityStatus, IdentifiedCaller, IntegrityLevel, Owner, PeerIdentity,
    PipeServerVerificationError, PipeServiceStatus, Platform, PlatformError, ProcessEntry,
    ProcessKey, SamplingProcess, SpawnRequest, UnsupportedKind,
};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use windows::core::{Error, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_ALREADY_EXISTS,
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, ERROR_SERVICE_DOES_NOT_EXIST, FILETIME, HANDLE,
    HLOCAL, PSID, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, RevertToSelf, TokenElevation,
    TokenIntegrityLevel, TokenOwner, TokenUser, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FindClose, FindFirstFileW, FindNextFileW,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, READ_CONTROL, WIN32_FIND_DATAW, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QUERY_SERVICE_CONFIGW,
    SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
};
#[allow(unused_imports)] // Kept with the named-pipe-fix import set for its boot-time helpers.
use windows::Win32::System::SystemInformation::{GetSystemTimeAsFileTime, GetTickCount64};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID,
    SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_SYSTEM_RID,
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

/// Counts malformed UTF-16 entries received from `CreateEnvironmentBlock`.
/// The entries themselves are deliberately not retained or logged.
static ACCOUNT_BASE_ENV_INVALID_UTF16_ENTRIES: AtomicU64 = AtomicU64::new(0);

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
/// Matches `WindowsServiceDef::service_name` and the installer `sc.exe` plan.
const AGENTWATCH_SERVICE_NAME: &str = "AgentWatch";

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
            // `FA`, rather than generic access, is stored as one ACE per SID.
            // `O:BA` makes a directory born for a privileged daemon belong to
            // Administrators instead of briefly belonging to its creator.
            Self::Machine => "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_owned(),
            Self::Owner(sid) => format!("D:P(A;OICI;FA;;;{sid})"),
        }
    }

    const fn sets_machine_owner(&self) -> bool {
        matches!(self, Self::Machine)
    }
}

fn wide_nul(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Whether `path` is the official data directory. Both sides are the final path
/// of an opened handle (`\\?\` prefix, 8.3 short names, `.` and `..`, and a
/// trailing separator already resolved), compared case-insensitively. A string
/// compare of the caller's spelling would miss `PROGRA~2`, a doubled separator,
/// or a `\\?\` prefix, and a non-admin daemon could then use the official dir.
fn is_machine_data_dir(path: &Path, default: &Path) -> bool {
    path_key(path) == path_key(default)
}

/// One spelling of a Windows path: drop the `\\?\` prefix, turn `/` into `\`,
/// drop a trailing separator, and resolve `.` and `..`. What remains is compared
/// case-insensitively. The final path of an opened handle already does this;
/// this covers a path that has not been opened yet.
fn path_key(path: &Path) -> String {
    let mut text = path.as_os_str().to_string_lossy().to_string();
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        text = rest.to_owned();
    }
    text = text.replace('/', "\\");
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                // Never pop the drive (`C:`). A `..` above it stays there.
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            other => parts.push(other),
        }
    }
    parts.join("\\").to_ascii_lowercase()
}

#[derive(Clone)]
enum DataDirPolicy {
    Machine,
    /// An unelevated daemon may use a non-official directory made by its
    /// token. Windows applies TokenOwner (the token's default owner), rather
    /// than TokenUser, to newly created objects on some account policies.
    Owner {
        token_user_sid: String,
        default_owner_sid: String,
    },
}

impl DataDirPolicy {
    fn acl(&self) -> DataDirAcl<'_> {
        match self {
            Self::Machine => DataDirAcl::Machine,
            Self::Owner { token_user_sid, .. } => DataDirAcl::Owner(token_user_sid),
        }
    }

    fn accepts_owner(&self, owner: &str) -> bool {
        match self {
            // A privileged process needs a machine-owned directory even when
            // --data-dir names a non-default location.
            Self::Machine => owner == SYSTEM_SID || owner == ADMINISTRATORS_SID,
            // Only the token user. `default_owner_sid` equals it by
            // construction (see `data_dir_policy_for_token`); a group such as
            // Administrators is never trusted for a non-elevated daemon.
            Self::Owner {
                token_user_sid,
                default_owner_sid,
            } => owner == token_user_sid || owner == default_owner_sid,
        }
    }

    fn permits_official_data_dir(&self) -> bool {
        matches!(self, Self::Machine)
    }
}

fn data_dir_policy_for_token(
    sid: String,
    default_owner_sid: String,
    elevated: bool,
) -> DataDirPolicy {
    if elevated || sid == SYSTEM_SID {
        // Elevated: the token's default owner is BUILTIN\Administrators, which
        // the machine policy already accepts (with SYSTEM).
        DataDirPolicy::Machine
    } else {
        // A non-elevated user daemon trusts its default owner only when it is
        // the token user itself. It must never accept an Administrators-owned
        // (or any other group-owned) directory.
        let default_owner_sid = if default_owner_sid == sid {
            default_owner_sid
        } else {
            sid.clone()
        };
        DataDirPolicy::Owner {
            token_user_sid: sid,
            default_owner_sid,
        }
    }
}

struct ResolvedDataDir {
    canonical: PathBuf,
    create_base: PathBuf,
    missing: Vec<OsString>,
}

fn invalid<T>(detail: &'static str) -> Result<T, PlatformError> {
    Err(PlatformError::Invalid {
        capability: "secure_data_dir",
        detail,
    })
}

/// Canonicalize the real existing parent before comparing paths or creating a
/// descendant. Windows has no benign system reparse-point ancestor equivalent:
/// every existing reparse point is refused before it can be followed.
fn resolve_data_dir_path(path: &Path) -> Result<ResolvedDataDir, PlatformError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components: Vec<_> = absolute.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let reparse = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
                if metadata.file_type().is_symlink() || reparse {
                    return invalid("data directory path contains a reparse point");
                }
                if !metadata.is_dir() {
                    return invalid("data directory path contains a non-directory");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = current.parent() else {
                    return invalid("data directory has no existing ancestor");
                };
                let create_base = std::fs::canonicalize(parent)?;
                let missing = components[index..]
                    .iter()
                    .map(|item| item.as_os_str().to_os_string())
                    .collect::<Vec<_>>();
                let canonical = missing
                    .iter()
                    .fold(create_base.clone(), |path, item| path.join(item));
                return Ok(ResolvedDataDir {
                    canonical,
                    create_base,
                    missing,
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    let canonical = std::fs::canonicalize(&absolute)?;
    Ok(ResolvedDataDir {
        create_base: canonical.clone(),
        canonical,
        missing: Vec::new(),
    })
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

fn owner_sid_for_handle(handle: HANDLE) -> Result<String, PlatformError> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `handle` is an open object handle; output pointers are valid and
    // the returned descriptor remains live until LocalFree below.
    #[allow(unsafe_code)]
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(io_error)
    .and_then(|()| sid_text(owner));
    // SAFETY: GetSecurityInfo allocates the descriptor with LocalAlloc
    // on success; the default/null value is safe to pass to LocalFree too.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
    result
}

struct DataDirSecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
    owner: Option<PSID>,
}

impl Drop for DataDirSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW owns
        // this LocalAlloc descriptor until this one-time release.
        #[allow(unsafe_code)]
        let _ = unsafe { LocalFree(HLOCAL(self.descriptor.0.cast())) };
    }
}

fn data_dir_security_descriptor(
    policy: DataDirAcl<'_>,
) -> Result<DataDirSecurityDescriptor, PlatformError> {
    let sddl = policy.sddl();
    let sddl_wide = wide_nul(OsStr::new(&sddl));
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
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .map_err(io_error)?;
    if dacl_present.0 == 0 || dacl.is_null() {
        // SAFETY: the descriptor belongs to this error path and is not wrapped.
        #[allow(unsafe_code)]
        let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
        return invalid("generated data-directory DACL is absent");
    }
    let owner = if policy.sets_machine_owner() {
        let mut owner = PSID::default();
        let mut defaulted = windows::Win32::Foundation::BOOL(0);
        // SAFETY: descriptor is live, and both output locations are writable.
        #[allow(unsafe_code)]
        if let Err(error) =
            unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) }
        {
            // SAFETY: construction has not transferred this LocalAlloc block
            // into DataDirSecurityDescriptor on this error path.
            #[allow(unsafe_code)]
            let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
            return Err(io_error(error));
        }
        Some(owner)
    } else {
        None
    };
    Ok(DataDirSecurityDescriptor {
        descriptor,
        dacl,
        owner,
    })
}

fn set_data_dir_dacl(handle: HANDLE, policy: DataDirAcl<'_>) -> Result<(), PlatformError> {
    let descriptor = data_dir_security_descriptor(policy)?;
    let owner_information = if descriptor.owner.is_some() {
        OWNER_SECURITY_INFORMATION
    } else {
        windows::Win32::Security::OBJECT_SECURITY_INFORMATION(0)
    };
    // SAFETY: every pointer comes from the live descriptor; security changes
    // target this open handle and therefore cannot follow a substituted path.
    #[allow(unsafe_code)]
    unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | owner_information,
            descriptor.owner.unwrap_or_default(),
            PSID::default(),
            Some(descriptor.dacl.cast_const()),
            None,
        )
    }
    .ok()
    .map_err(io_error)
}

/// Return whether `handle` already carries the complete policy.  An inherited
/// child ACE is just as restrictive as the explicit equivalent, so it is
/// deliberately accepted here.  Reapplying an identical descriptor to a
/// locked child can fail with `ACCESS_DENIED` on Windows; more importantly,
/// there is no security benefit to changing an already-correct descriptor.
fn data_dir_security_is_current(
    handle: HANDLE,
    policy: &DataDirPolicy,
    require_protected_dacl: bool,
) -> Result<bool, PlatformError> {
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `handle` is live, every output location is writable, and the
    // returned LocalAlloc descriptor remains live until it is released below.
    #[allow(unsafe_code)]
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(io_error)
    .and_then(|()| {
        if dacl.is_null() || !policy.accepts_owner(&sid_text(owner)?) {
            return Ok(false);
        }

        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `descriptor` came from GetSecurityInfo and remains live;
        // both output locations are writable.
        #[allow(unsafe_code)]
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
            .map_err(io_error)?;
        if require_protected_dacl && (control & SE_DACL_PROTECTED.0) == 0 {
            return Ok(false);
        }

        let expected_ace_count = match policy {
            DataDirPolicy::Machine => 2,
            DataDirPolicy::Owner { .. } => 1,
        };
        // SAFETY: `dacl` points into the still-live security descriptor.
        #[allow(unsafe_code)]
        let ace_count = unsafe { (*dacl).AceCount };
        if usize::from(ace_count) != expected_ace_count {
            return Ok(false);
        }

        let mut system_seen = false;
        let mut administrators_seen = false;
        let mut owner_seen = false;
        for index in 0..u32::from(ace_count) {
            let mut ace = std::ptr::null_mut();
            // SAFETY: `index` is below AceCount and `ace` is writable storage
            // for the pointer owned by the live DACL.
            #[allow(unsafe_code)]
            unsafe { GetAce(dacl, index, &mut ace) }.map_err(io_error)?;
            // SAFETY: the fields below are read only after checking the ACE
            // type, so this is an ACCESS_ALLOWED_ACE layout.
            #[allow(unsafe_code)]
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            // 0x03 is OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE. Windows
            // can add 0x10 (INHERITED_ACE) and can remove inheritance bits
            // on a file child; all of those describe the same full-access
            // policy for the current object. A directory must keep 0x03 so
            // future children inherit the restricted DACL too.
            let ace_flags_match = if require_protected_dacl {
                allowed.Header.AceFlags == 0x03
            } else {
                allowed.Header.AceFlags & !0x13_u8 == 0
            };
            if u32::from(allowed.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || allowed.Mask != FILE_ALL_ACCESS.0
                || !ace_flags_match
            {
                return Ok(false);
            }
            // SAFETY: SidStart is the first u32 of the variable-length SID
            // immediately following the fixed ACCESS_ALLOWED_ACE header.
            let sid = PSID(std::ptr::addr_of!(allowed.SidStart).cast_mut().cast());
            let sid = sid_text(sid)?;
            match policy {
                DataDirPolicy::Machine if sid == SYSTEM_SID && !system_seen => {
                    system_seen = true;
                }
                DataDirPolicy::Machine if sid == ADMINISTRATORS_SID && !administrators_seen => {
                    administrators_seen = true;
                }
                DataDirPolicy::Owner { token_user_sid, .. }
                    if sid == *token_user_sid && !owner_seen =>
                {
                    owner_seen = true;
                }
                _ => return Ok(false),
            }
        }
        Ok(match policy {
            DataDirPolicy::Machine => system_seen && administrators_seen,
            DataDirPolicy::Owner { .. } => owner_seen,
        })
    });
    // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc. A
    // null descriptor from an unsuccessful call is safe to pass to LocalFree.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
    result
}

/// Create every missing component with its protected descriptor already in
/// place. There is no inherited-ACL interval in which another user can seed a
/// junction or a file beneath the new directory.
fn create_missing_directories(
    resolved: &ResolvedDataDir,
    policy: &DataDirPolicy,
) -> Result<(), PlatformError> {
    let descriptor = data_dir_security_descriptor(policy.acl())?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.descriptor.0.cast(),
        bInheritHandle: windows::Win32::Foundation::BOOL(0),
    };
    let mut current = resolved.create_base.clone();
    for name in &resolved.missing {
        current.push(name);
        let wide = wide_nul(current.as_os_str());
        // SAFETY: the path is NUL terminated and `attributes` owns a live
        // security descriptor for the duration of CreateDirectoryW.
        #[allow(unsafe_code)]
        match unsafe {
            CreateDirectoryW(
                windows::core::PCWSTR(wide.as_ptr()),
                Some(&attributes as *const SECURITY_ATTRIBUTES),
            )
        } {
            Ok(()) => {}
            Err(error) if (error.code().0 & 0xffff) == ERROR_ALREADY_EXISTS.0 as i32 => {
                // An object appeared during creation. Pin it before checking
                // its owner or changing a DACL; never trust a path query here.
                let (handle, directory) = open_data_object(&current)?;
                let result = if directory {
                    secure_entry_handle(handle, policy, true)
                } else {
                    invalid("data directory path contains a non-directory")
                };
                close(handle);
                result?;
            }
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

/// Open a final component without following a symlink/junction. A reparse
/// point is opened as the point itself and immediately refused.
fn open_data_object(path: &Path) -> Result<(HANDLE, bool), PlatformError> {
    let wide = wide_nul(path.as_os_str());
    // SAFETY: `wide` is NUL terminated. The returned handle is closed by the
    // caller on every path after this function succeeds.
    #[allow(unsafe_code)]
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            HANDLE::default(),
        )
    }
    .map_err(io_error)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is open and `information` is writable output storage.
    #[allow(unsafe_code)]
    let information_result =
        unsafe { GetFileInformationByHandle(handle, &mut information) }.map_err(io_error);
    if let Err(error) = information_result {
        close(handle);
        return Err(error);
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        close(handle);
        return invalid("data directory path contains a reparse point");
    }
    Ok((
        handle,
        information.dwFileAttributes
            & windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY.0
            != 0,
    ))
}

/// `FOLDERID_ProgramData` from the shell, never from the process environment.
/// The returned path is the folder Windows names, so a `ProgramData` variable
/// set by the caller does not move it.
///
/// Called through `shell32` directly. The `windows` crate's binding needs the
/// `Win32_UI_Shell` feature, which is not in the locked feature set; adding it
/// would change `Cargo.lock`. The GUID and the signature are the documented ones.
fn known_folder_program_data() -> Result<PathBuf, PlatformError> {
    // FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}.
    const FOLDERID_PROGRAM_DATA: windows::core::GUID =
        windows::core::GUID::from_u128(0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97);
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(
            rfid: *const windows::core::GUID,
            dwflags: u32,
            htoken: HANDLE,
            ppszpath: *mut PWSTR,
        ) -> windows::core::HRESULT;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(block: *const c_void);
    }
    let mut wide = PWSTR::null();
    // SAFETY: a null token asks for this process's folder. On success Windows
    // allocates `wide` with CoTaskMemAlloc; it is copied below and freed here.
    #[allow(unsafe_code)]
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_PROGRAM_DATA, 0, HANDLE::default(), &mut wide) };
    if result.is_err() {
        return Err(io_error(Error::from(result)));
    }
    // SAFETY: the call succeeded, so `wide` is a NUL-terminated wide string.
    #[allow(unsafe_code)]
    let text = unsafe { wide.to_string() }.map_err(|_| PlatformError::Invalid {
        capability: "default_data_dir",
        detail: "ProgramData folder path was not valid UTF-16",
    });
    // SAFETY: SHGetKnownFolderPath allocated `wide` with CoTaskMemAlloc.
    #[allow(unsafe_code)]
    unsafe {
        CoTaskMemFree(wide.0.cast());
    }
    text.map(PathBuf::from)
}

fn final_path_for_handle(handle: HANDLE) -> Result<PathBuf, PlatformError> {
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: `handle` is open and `buffer` is writable for the documented
    // number of UTF-16 code units.
    #[allow(unsafe_code)]
    let length = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(io_error(Error::from_win32()));
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn directory_children(path: &Path) -> Result<Vec<OsString>, PlatformError> {
    let wildcard = path.join("*");
    let wide = wide_nul(wildcard.as_os_str());
    let mut entry = WIN32_FIND_DATAW::default();
    // SAFETY: the wildcard is NUL terminated and `entry` is writable storage.
    #[allow(unsafe_code)]
    let find = unsafe { FindFirstFileW(windows::core::PCWSTR(wide.as_ptr()), &mut entry) }
        .map_err(io_error)?;
    let mut names = Vec::new();
    loop {
        let length = entry
            .cFileName
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(entry.cFileName.len());
        let name = &entry.cFileName[..length];
        if name != [u16::from(b'.')] && name != [u16::from(b'.'), u16::from(b'.')] {
            if entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                // SAFETY: `find` is an owned FindFirstFileW handle.
                #[allow(unsafe_code)]
                let _ = unsafe { FindClose(find) };
                return invalid("data directory contains a reparse point");
            }
            names.push(OsString::from_wide(&entry.cFileName[..length]));
        }
        // SAFETY: `find` remains valid until FindClose below; `entry` is writable.
        #[allow(unsafe_code)]
        match unsafe { FindNextFileW(find, &mut entry) } {
            Ok(()) => {}
            Err(error) if (error.code().0 & 0xffff) == ERROR_NO_MORE_FILES.0 as i32 => break,
            Err(error) => {
                // SAFETY: `find` is an owned FindFirstFileW handle.
                #[allow(unsafe_code)]
                let _ = unsafe { FindClose(find) };
                return Err(io_error(error));
            }
        }
    }
    // SAFETY: `find` is an owned FindFirstFileW handle and is closed exactly once.
    #[allow(unsafe_code)]
    let _ = unsafe { FindClose(find) };
    Ok(names)
}

fn secure_entry_handle(
    handle: HANDLE,
    policy: &DataDirPolicy,
    require_protected_dacl: bool,
) -> Result<(), PlatformError> {
    if !policy.accepts_owner(&owner_sid_for_handle(handle)?) {
        return invalid("data directory owner is not trusted");
    }
    if data_dir_security_is_current(handle, policy, require_protected_dacl)? {
        return Ok(());
    }
    set_data_dir_dacl(handle, policy.acl())
}

fn secure_directory_tree(
    handle: HANDLE,
    canonical_path: &Path,
    policy: &DataDirPolicy,
) -> Result<(), PlatformError> {
    secure_entry_handle(handle, policy, true)?;
    // The root descriptor is now protected, so an ordinary user cannot
    // substitute children while their individual handles are opened below.
    for name in directory_children(canonical_path)? {
        let child_path = canonical_path.join(name);
        let (child, is_directory) = open_data_object(&child_path)?;
        let result = if is_directory {
            let child_canonical = final_path_for_handle(child)?;
            secure_directory_tree(child, &child_canonical, policy)
        } else {
            // New files inherit the protected root DACL. They need no rewrite
            // when that inherited descriptor still grants exactly the policy.
            secure_entry_handle(child, policy, false)
        };
        close(child);
        result?;
    }
    Ok(())
}

fn secure_data_dir_with_policy(
    path: &Path,
    default: &Path,
    policy: DataDirPolicy,
) -> Result<PathBuf, PlatformError> {
    let resolved = resolve_data_dir_path(path)?;
    let default = resolve_data_dir_path(default)?;
    // Compare canonical paths before creation. A normal token cannot use the
    // machine's official location, even if an ACL happens to name that user.
    let official_data_dir = is_machine_data_dir(&resolved.canonical, &default.canonical);
    if official_data_dir && !policy.permits_official_data_dir() {
        return invalid("official data directory requires a privileged daemon");
    }
    create_missing_directories(&resolved, &policy)?;
    let (directory, is_directory) = open_data_object(&resolved.canonical)?;
    if !is_directory {
        close(directory);
        return invalid("data directory path contains a non-directory");
    }
    let canonical = final_path_for_handle(directory)?;
    let result = secure_directory_tree(directory, &canonical, &policy).map(|()| canonical);
    close(directory);
    result
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

/// Return the SID that Windows uses as the default owner for objects created
/// by this token. It is an identity from the daemon's own kernel token, never
/// from a caller or a configurable path.
fn default_owner_sid_for_token(token: HANDLE) -> Result<String, PlatformError> {
    let mut bytes = 0_u32;
    // SAFETY: this is the documented TokenOwner sizing query.
    #[allow(unsafe_code)]
    let _ = unsafe { GetTokenInformation(token, TokenOwner, None, 0, &mut bytes) };
    if bytes == 0 {
        return Err(io_error(Error::from_win32()));
    }
    let mut storage = vec![0_u64; (bytes as usize).div_ceil(size_of::<u64>())];
    // SAFETY: storage is aligned and contains at least `bytes` writable bytes.
    #[allow(unsafe_code)]
    unsafe {
        GetTokenInformation(
            token,
            TokenOwner,
            Some(storage.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }
    .map_err(io_error)?;
    // SAFETY: successful TokenOwner writes TOKEN_OWNER at the beginning of storage.
    #[allow(unsafe_code)]
    let owner = unsafe { &*storage.as_ptr().cast::<TOKEN_OWNER>() };
    sid_text(owner.Owner)
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

/// Read the daemon process token directly. Data-directory policy must not use
/// a caller-provided identity, an environment switch, or a process-table view.
fn current_token_owner() -> Result<Owner, PlatformError> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a valid pseudo-handle and `token` is
    // writable output storage for an owned token handle.
    #[allow(unsafe_code)]
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(io_error)?;
    let owner = owner_for_token(token);
    close(token);
    owner
}

/// Build the data-directory policy solely from the daemon's current token.
/// TokenOwner is included because it is the SID Windows actually assigns to a
/// newly created object when the token's default owner differs from TokenUser.
fn current_data_dir_policy() -> Result<DataDirPolicy, PlatformError> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a valid pseudo-handle and `token` is
    // writable output storage for an owned token handle.
    #[allow(unsafe_code)]
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(io_error)?;
    let policy = (|| {
        let sid = sid_for_token(token)?;
        let default_owner_sid = default_owner_sid_for_token(token)?;
        let elevated = elevated_for_token(token)?;
        Ok(data_dir_policy_for_token(sid, default_owner_sid, elevated))
    })();
    close(token);
    policy
}

const ACCOUNT_BASE_ENV_ALLOWLIST: [&str; 16] = [
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ComSpec",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
];
const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// Owns the `userenv.dll` allocation until every entry has been copied out.
struct ProfileEnvironmentBlock {
    pointer: *mut c_void,
}

impl ProfileEnvironmentBlock {
    fn for_current_process_token() -> Result<Self, PlatformError> {
        let mut token = HANDLE::default();
        // SAFETY: the current-process pseudo-handle is valid and `token` is
        // writable storage for the owned TOKEN_QUERY handle.
        #[allow(unsafe_code)]
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(io_error)?;

        let mut pointer = std::ptr::null_mut();
        // SAFETY: `token` is an open token for the current process; `pointer`
        // is valid writable storage. Passing false prevents inheriting the
        // daemon environment into the account-profile environment block.
        #[allow(unsafe_code)]
        let created = unsafe { CreateEnvironmentBlock(&mut pointer, token, false) };
        close(token);
        created.map_err(io_error)?;
        if pointer.is_null() {
            return Err(PlatformError::Invalid {
                capability: "account_base_env",
                detail: "CreateEnvironmentBlock returned a null environment",
            });
        }
        Ok(Self { pointer })
    }

    fn entries(&self) -> Vec<Vec<u16>> {
        let mut entries = Vec::new();
        // SAFETY: CreateEnvironmentBlock returned a live, double-NUL
        // terminated UTF-16 environment block. We copy each NUL-delimited
        // entry before this owner calls DestroyEnvironmentBlock in Drop.
        #[allow(unsafe_code)]
        unsafe {
            let mut cursor = self.pointer.cast::<u16>();
            loop {
                let start = cursor;
                while *cursor != 0 {
                    cursor = cursor.add(1);
                }
                if cursor == start {
                    break;
                }
                let length = cursor.offset_from(start) as usize;
                entries.push(std::slice::from_raw_parts(start, length).to_vec());
                cursor = cursor.add(1);
            }
        }
        entries
    }
}

impl Drop for ProfileEnvironmentBlock {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: the pointer was allocated by CreateEnvironmentBlock and
            // remains owned by this wrapper until this single Drop call.
            #[allow(unsafe_code)]
            let _ = unsafe { DestroyEnvironmentBlock(self.pointer) };
        }
    }
}

struct FilteredProfileEnvironment {
    values: Vec<(String, String)>,
    invalid_utf16_entries: u64,
}

fn account_base_env_name(name: &str) -> bool {
    ACCOUNT_BASE_ENV_ALLOWLIST
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

fn insert_profile_value(values: &mut Vec<(String, String)>, name: String, value: String) {
    if let Some((existing_name, existing_value)) = values
        .iter_mut()
        .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
    {
        *existing_name = name;
        *existing_value = value;
    } else {
        values.push((name, value));
    }
}

fn filter_profile_environment_entries(
    entries: impl IntoIterator<Item = Vec<u16>>,
) -> FilteredProfileEnvironment {
    let mut values = Vec::new();
    let mut invalid_utf16_entries = 0_u64;
    for entry in entries {
        let Ok(entry) = String::from_utf16(&entry) else {
            invalid_utf16_entries = invalid_utf16_entries.saturating_add(1);
            continue;
        };
        let Some((name, value)) = entry.split_once('=') else {
            continue;
        };
        if account_base_env_name(name) {
            // The profile's own spelling is kept. The Windows environment
            // lookup rules remain case-insensitive at process creation time.
            insert_profile_value(&mut values, name.to_owned(), value.to_owned());
        }
    }
    FilteredProfileEnvironment {
        values,
        invalid_utf16_entries,
    }
}

fn fixed_path(system_root: &str) -> String {
    format!(
        "{system_root}\\system32;{system_root};{system_root}\\System32\\Wbem;{system_root}\\System32\\WindowsPowerShell\\v1.0\\"
    )
}

fn account_base_env_from_profile(
    mut values: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, PlatformError> {
    let Some(system_root) = values
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("SystemRoot"))
        .map(|(_, value)| value.clone())
    else {
        return Err(PlatformError::Invalid {
            capability: "account_base_env",
            detail: "profile environment has no SystemRoot",
        });
    };
    if !values
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("PATHEXT"))
    {
        values.push(("PATHEXT".to_owned(), DEFAULT_PATHEXT.to_owned()));
    }
    // Do not preserve a daemon- or profile-provided Path. This fixed search
    // path is the contract for a process started by the daemon.
    values.retain(|(name, _)| !name.eq_ignore_ascii_case("Path"));
    values.push(("Path".to_owned(), fixed_path(&system_root)));
    Ok(values)
}

/// Build the Windows launch base environment from the current account profile.
///
/// `CreateEnvironmentBlock` consults the account profile/registry. Passing
/// `bInherit = FALSE` ensures no daemon-process variables are copied in.
pub fn account_base_env() -> Result<Vec<(String, String)>, PlatformError> {
    let block = ProfileEnvironmentBlock::for_current_process_token()?;
    let filtered = filter_profile_environment_entries(block.entries());
    ACCOUNT_BASE_ENV_INVALID_UTF16_ENTRIES
        .fetch_add(filtered.invalid_utf16_entries, Ordering::Relaxed);
    account_base_env_from_profile(filtered.values)
}

/// Windows treats environment variable names case-insensitively.
#[must_use]
pub fn windows_reserved_env_name(name: &str) -> bool {
    account_base_env_name(name) || name.eq_ignore_ascii_case("Path")
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

/// Build an inherited environment block for the target only. This buffer is
/// never sent to a daemon, logged, or persisted.
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
/// An installed AgentWatch service makes LocalSystem the sole trusted owner.
/// A same-user pipe is a development-only exception when the service does not
/// exist. A failed SCM query is deliberately treated as installed.
pub fn verify_pipe_server(
    handle: std::os::windows::io::RawHandle,
) -> Result<(), PipeServerVerificationError> {
    let service_status = service_status_from_scm();
    verify_pipe_server_with_service_status(handle, &service_status)
}

/// Verify an already-connected pipe against an injected SCM observation.
///
/// The production caller gets that observation from [`service_status_from_scm`].
/// Keeping the status explicit gives Windows integration tests a way to prove
/// that a connected same-user peer receives zero request bytes when a service
/// is installed, without installing one on the runner.
pub fn verify_pipe_server_with_service_status(
    handle: std::os::windows::io::RawHandle,
    service_status: &PipeServiceStatus,
) -> Result<(), PipeServerVerificationError> {
    let scm_detail = service_status_detail(service_status);
    let owner_sid = pipe_owner_sid(HANDLE(handle as isize))
        .map_err(|error| with_verification_detail(error, scm_detail.clone()))?;
    let current_sid = if matches!(service_status, PipeServiceStatus::NotInstalled) {
        Some(
            current_pipe_client_sid()
                .map_err(|error| with_verification_detail(error, scm_detail.clone()))?,
        )
    } else {
        None
    };
    if trusted_pipe_owner(&owner_sid, service_status, current_sid.as_deref()) {
        Ok(())
    } else {
        let image_detail = installed_service_image_detail(HANDLE(handle as isize), service_status);
        Err(PipeServerVerificationError::NotDaemon {
            detail: combine_verification_details(scm_detail, image_detail),
        })
    }
}

/// Explicit owner allowlist used only by existing test helpers. It is not a
/// product decision path: production calls use SCM-derived service status.
#[cfg(any(test, feature = "test-support"))]
pub fn verify_pipe_server_for_owners(
    handle: std::os::windows::io::RawHandle,
    trusted_owners: &[&str],
) -> Result<(), PipeServerVerificationError> {
    let owner_sid = pipe_owner_sid(HANDLE(handle as isize))?;
    if trusted_owners.contains(&owner_sid.as_str()) {
        Ok(())
    } else {
        Err(PipeServerVerificationError::NotDaemon { detail: None })
    }
}

fn trusted_pipe_owner(
    owner_sid: &str,
    service_status: &PipeServiceStatus,
    current_sid: Option<&str>,
) -> bool {
    if owner_sid == LOCAL_SYSTEM_SID {
        return true;
    }
    matches!(service_status, PipeServiceStatus::NotInstalled) && current_sid == Some(owner_sid)
}

fn service_status_from_scm() -> PipeServiceStatus {
    // SAFETY: null machine/database names select the local active SCM; the
    // returned handle is closed on every path below.
    #[allow(unsafe_code)]
    let manager =
        match unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) } {
            Ok(handle) => handle,
            Err(error) => return service_query_failed("OpenSCManagerW", error),
        };
    let service_name = wide_nul(OsStr::new(AGENTWATCH_SERVICE_NAME));
    // SAFETY: `service_name` is NUL-terminated and `manager` is the live SCM
    // handle obtained above.
    #[allow(unsafe_code)]
    let service =
        unsafe { OpenServiceW(manager, PCWSTR(service_name.as_ptr()), SERVICE_QUERY_CONFIG) };
    // SAFETY: `manager` is an owned SCM handle and no longer used after this.
    #[allow(unsafe_code)]
    let _ = unsafe { CloseServiceHandle(manager) };
    let service = match service {
        Ok(handle) => handle,
        Err(error) if error.code() == ERROR_SERVICE_DOES_NOT_EXIST.into() => {
            return PipeServiceStatus::NotInstalled;
        }
        Err(error) => return service_query_failed("OpenServiceW(AgentWatch)", error),
    };
    let status = match service_binary_path(service) {
        Ok(binary_path) => PipeServiceStatus::Installed { binary_path },
        Err((operation, win32_error)) => PipeServiceStatus::QueryFailed {
            operation,
            win32_error,
        },
    };
    // SAFETY: `service` is an owned service handle and no longer used after
    // this close.
    #[allow(unsafe_code)]
    let _ = unsafe { CloseServiceHandle(service) };
    status
}

fn service_binary_path(
    service: windows::Win32::Security::SC_HANDLE,
) -> Result<Option<PathBuf>, (&'static str, u32)> {
    let mut bytes = 0_u32;
    // SAFETY: this is the documented size query. `bytes` is writable and the
    // null config pointer is paired with a zero buffer length.
    #[allow(unsafe_code)]
    let sized = unsafe { QueryServiceConfigW(service, None, 0, &mut bytes) };
    if let Err(error) = sized {
        if error.code() != ERROR_INSUFFICIENT_BUFFER.into() {
            return Err(("QueryServiceConfigW(size)", win32_error(error)));
        }
    }
    if bytes == 0 {
        return Err(("QueryServiceConfigW(size)", 0));
    }
    let word_count = (bytes as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; word_count];
    // SAFETY: `storage` has pointer alignment and at least `bytes` writable
    // bytes. QueryServiceConfigW initializes QUERY_SERVICE_CONFIGW at offset
    // zero and keeps all returned string pointers inside this live buffer.
    #[allow(unsafe_code)]
    unsafe {
        QueryServiceConfigW(
            service,
            Some(storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
            (storage.len() * size_of::<usize>()) as u32,
            &mut bytes,
        )
    }
    .map_err(|error| ("QueryServiceConfigW", win32_error(error)))?;
    // SAFETY: the successful call above initialized this structure in the
    // aligned storage, which remains live while the string is copied below.
    #[allow(unsafe_code)]
    let config = unsafe { &*storage.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    // SAFETY: lpBinaryPathName is a NUL-terminated UTF-16 string owned by the
    // live QueryServiceConfigW buffer. `to_string` copies it before `storage`
    // is dropped.
    #[allow(unsafe_code)]
    let command = unsafe { config.lpBinaryPathName.to_string() }
        .map_err(|_| ("QueryServiceConfigW(binary path)", 0))?;
    Ok(service_image_from_command(&command))
}

fn service_image_from_command(command: &str) -> Option<PathBuf> {
    let command = command.trim();
    if let Some(quoted) = command.strip_prefix('"') {
        return quoted
            .find('"')
            .filter(|end| *end > 0)
            .map(|end| PathBuf::from(&quoted[..end]));
    }
    command
        .split_ascii_whitespace()
        .next()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn service_query_failed(operation: &'static str, error: Error) -> PipeServiceStatus {
    PipeServiceStatus::QueryFailed {
        operation,
        win32_error: win32_error(error),
    }
}

fn win32_error(error: Error) -> u32 {
    error.code().0 as u32 & 0xffff
}

fn service_status_detail(status: &PipeServiceStatus) -> Option<String> {
    match status {
        PipeServiceStatus::QueryFailed {
            operation,
            win32_error,
        } => Some(format!(
            "{operation} failed (Win32 error {win32_error}); treating AgentWatch as installed and requiring a LocalSystem-owned pipe"
        )),
        PipeServiceStatus::NotInstalled | PipeServiceStatus::Installed { .. } => None,
    }
}

fn with_verification_detail(
    error: PipeServerVerificationError,
    detail: Option<String>,
) -> PipeServerVerificationError {
    match error {
        PipeServerVerificationError::CannotQuery {
            operation,
            win32_error,
            detail: existing,
        } => PipeServerVerificationError::CannotQuery {
            operation,
            win32_error,
            detail: combine_verification_details(existing, detail),
        },
        PipeServerVerificationError::NotDaemon { detail: existing } => {
            PipeServerVerificationError::NotDaemon {
                detail: combine_verification_details(existing, detail),
            }
        }
    }
}

fn combine_verification_details(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
        (Some(detail), None) | (None, Some(detail)) => Some(detail),
        (None, None) => None,
    }
}

fn installed_service_image_detail(
    pipe: HANDLE,
    service_status: &PipeServiceStatus,
) -> Option<String> {
    let PipeServiceStatus::Installed {
        binary_path: Some(installed_path),
    } = service_status
    else {
        return None;
    };
    let server_path = pipe_server_image_path(pipe)?;
    installed_service_image_detail_for_paths(installed_path, &server_path)
}

fn installed_service_image_detail_for_paths(
    installed_path: &Path,
    server_path: &Path,
) -> Option<String> {
    (!same_image_path(server_path, installed_path)).then(|| {
        format!(
            "pipe is held by {}, not the installed agentwatchd",
            server_path.display()
        )
    })
}

fn pipe_server_image_path(pipe: HANDLE) -> Option<PathBuf> {
    let mut pid = 0_u32;
    // SAFETY: `pipe` is the connected client handle. The PID output is valid
    // for the duration of this call.
    #[allow(unsafe_code)]
    unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) }.ok()?;
    // SAFETY: this asks only for limited query access to the named-pipe server
    // process. The returned handle is closed before this helper returns.
    #[allow(unsafe_code)]
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let image = image_for_process(process);
    close(process);
    image
}

fn same_image_path(left: &Path, right: &Path) -> bool {
    let Some(left) = canonical_image_path(left) else {
        return false;
    };
    let Some(right) = canonical_image_path(right) else {
        return false;
    };
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn canonical_image_path(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path)
        .ok()
        .or_else(|| lexical_absolute_path(path))
}

fn lexical_absolute_path(path: &Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Some(normalized)
}

fn current_pipe_client_sid() -> Result<String, PipeServerVerificationError> {
    match CurrentPlatform.current_owner() {
        Ok(Owner::Windows { sid, .. }) => Ok(sid),
        Ok(Owner::Unix { .. }) => Err(PipeServerVerificationError::CannotQuery {
            operation: "GetTokenInformation(current process)",
            win32_error: 0,
            detail: None,
        }),
        Err(error) => Err(PipeServerVerificationError::CannotQuery {
            operation: "GetTokenInformation(current process)",
            win32_error: platform_win32_error(&error),
            detail: None,
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
            detail: None,
        });
    }
    let result = pipe_sid_text(owner).map_err(|error| PipeServerVerificationError::CannotQuery {
        operation: "ConvertSidToStringSidW(pipe owner)",
        win32_error: error.code().0 as u32 & 0xffff,
        detail: None,
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
        // Exact starts from no inherited name at all. `environment_from` sorts
        // and deduplicates keys case-insensitively for the Unicode block that
        // CreateProcessW receives; Inherit intentionally retains its existing
        // process-environment behavior.
        let mut env = match request.env_source {
            crate::EnvSource::Exact => {
                environment_from(std::iter::empty::<(OsString, OsString)>(), &request.env)
            }
            crate::EnvSource::Inherit => environment(&request.env),
        };
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
    fn secure_data_dir(&self, path: &Path) -> Result<PathBuf, PlatformError> {
        let default = self.default_data_dir()?;
        // Token elevation and owner SIDs are read from the daemon's own
        // kernel-authenticated identity. A privileged daemon cannot bypass
        // machine ownership by selecting a custom location.
        let policy = current_data_dir_policy()?;
        secure_data_dir_with_policy(path, &default, policy)
    }
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError> {
        // The known-folder API, not the `ProgramData` environment variable. A
        // caller who sets that variable must not move the official directory.
        let program_data = known_folder_program_data()?;
        Ok(program_data.join("AgentWatch"))
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
        current_token_owner()
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
        account_base_env, account_base_env_from_profile, account_base_env_name, close,
        current_token_owner, data_dir_policy_for_token, environment_from,
        filter_profile_environment_entries, fixed_path, installed_service_image_detail_for_paths,
        open_data_object, same_image_path, secure_data_dir_with_policy, service_status_detail,
        set_data_dir_dacl, sid_text, trusted_pipe_owner, windows_reserved_env_name,
        CurrentPlatform, DataDirAcl, DataDirPolicy, ADMINISTRATORS_SID, LOCAL_SYSTEM_SID,
        SYSTEM_SID,
    };
    use crate::{
        platform, Capability, CapabilityStatus, IdentifiedCaller, IntegrityLevel, Owner,
        PeerIdentity, PipeServiceStatus, Platform, PlatformError, ReapOutcome, SpawnRequest,
        UnsupportedKind,
    };
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HLOCAL, PSID};
    use windows::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateSymbolicLinkW, FILE_ALL_ACCESS, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
        SYMBOLIC_LINK_FLAG_DIRECTORY,
    };
    use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    #[derive(Debug, PartialEq, Eq)]
    struct DaclReadback {
        protected: bool,
        aces: Vec<(String, u32, u8)>,
    }

    fn account_value<'a>(environment: &'a [(String, String)], name: &str) -> Option<&'a str> {
        environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn profile_environment_filter_keeps_only_account_values_and_fixes_path() {
        let filtered = filter_profile_environment_entries([
            "sYsTeMrOoT=C:\\Windows".encode_utf16().collect(),
            "UserName=profile-user".encode_utf16().collect(),
            "LANG=must-not-pass".encode_utf16().collect(),
            vec![0xD800],
        ]);
        assert_eq!(filtered.invalid_utf16_entries, 1);
        assert!(filtered
            .values
            .iter()
            .all(|(name, _)| account_base_env_name(name)));

        let environment = account_base_env_from_profile(filtered.values).expect("base environment");
        assert_eq!(
            account_value(&environment, "Path"),
            Some(
                "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            )
        );
        assert_eq!(
            account_value(&environment, "PATHEXT"),
            Some(".COM;.EXE;.BAT;.CMD")
        );
        assert_eq!(
            account_value(&environment, "sYsTeMrOoT"),
            Some("C:\\Windows")
        );
        assert!(account_value(&environment, "LANG").is_none());
    }

    #[test]
    fn windows_reserved_environment_names_are_case_insensitive() {
        for name in [
            "SystemRoot",
            "windir",
            "SystemDrive",
            "ComSpec",
            "PATHEXT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "USERNAME",
            "USERDOMAIN",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
            "ProgramFiles",
            "Path",
            "path",
            "PATH",
        ] {
            assert!(windows_reserved_env_name(name), "{name} must be reserved");
        }
        assert!(!windows_reserved_env_name("Home"));
        for name in ["LANG", "TZ", "LC_ALL"] {
            assert!(!windows_reserved_env_name(name), "{name} is not reserved");
        }
    }

    #[test]
    fn account_base_environment_ignores_the_daemon_environment() {
        let expected_path = account_value(
            &account_base_env().expect("account profile environment"),
            "Path",
        )
        .expect("fixed profile Path")
        .to_owned();
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "windows::tests::account_base_environment_ignores_the_daemon_environment_in_child",
                "--nocapture",
            ])
            .env("AW_SECRET_PROBE", "must-not-be-in-profile-base-environment")
            .env("LANG", "daemon-language")
            .env("TZ", "Daemon/Timezone")
            .env("Path", r"C:\daemon-only-path")
            .env("USERPROFILE", r"C:\daemon-only-profile")
            .env("AW_EXPECTED_PROFILE_PATH", expected_path)
            // The parent's own USERPROFILE is the real profile of this account;
            // the child must get it from the profile even though its process
            // environment says otherwise.
            .env(
                "AW_EXPECTED_USERPROFILE",
                std::env::var("USERPROFILE").expect("test account USERPROFILE"),
            )
            .output()
            .expect("run isolated environment test");
        assert!(
            output.status.success(),
            "isolated environment test stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn account_base_environment_ignores_the_daemon_environment_in_child() {
        // Only meaningful when started by the parent test above with a
        // poisoned process environment.
        let Ok(expected_profile) = std::env::var("AW_EXPECTED_USERPROFILE") else {
            return;
        };
        let environment = account_base_env().expect("account profile environment");
        assert!(environment
            .iter()
            .all(|(name, _)| { account_base_env_name(name) || name.eq_ignore_ascii_case("Path") }));
        for forbidden in ["AW_SECRET_PROBE", "LANG", "TZ"] {
            assert!(
                account_value(&environment, forbidden).is_none(),
                "{forbidden} leaked from the daemon environment"
            );
        }

        let system_root = account_value(&environment, "SystemRoot").expect("profile SystemRoot");
        let path = account_value(&environment, "Path").expect("fixed Path");
        assert_eq!(path, fixed_path(system_root));
        assert_eq!(
            path,
            std::env::var("AW_EXPECTED_PROFILE_PATH").expect("expected profile Path")
        );
        assert_ne!(path, r"C:\daemon-only-path");
        assert_ne!(
            account_value(&environment, "USERPROFILE"),
            Some(r"C:\daemon-only-profile")
        );
        // USERPROFILE points at the caller's (this account's) profile.
        assert_eq!(
            account_value(&environment, "USERPROFILE").map(str::to_ascii_lowercase),
            Some(expected_profile.to_ascii_lowercase())
        );
    }

    /// `icacls`-equivalent readback used by the ACL test. It deliberately
    /// reads the DACL Windows stored, rather than asserting the SDDL input
    /// string, so inheritance and unexpected Users/Everyone ACEs are visible.
    fn read_dacl(
        handle: windows::Win32::Foundation::HANDLE,
    ) -> Result<DaclReadback, PlatformError> {
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the pinned object handle and all output storage remain live
        // until the descriptor is released after all ACEs are read.
        #[allow(unsafe_code)]
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                Some(&mut descriptor),
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
            // SAFETY: descriptor is live and came from GetSecurityInfo;
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
        // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc.
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

    /// The official directory comes from the known folder, not from the
    /// `ProgramData` environment variable. Setting that variable to somewhere
    /// else does not move it. This is the reverse of the old behavior: removing
    /// the known-folder call and reading the variable again makes this fail.
    #[test]
    fn program_data_env_does_not_move_the_official_dir() {
        let saved = std::env::var_os("ProgramData");
        std::env::set_var("ProgramData", r"C:\aw-not-program-data");
        let got = CurrentPlatform.default_data_dir().expect("known folder");
        match saved {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }
        let text = got.to_string_lossy().to_ascii_lowercase();
        assert!(
            text.ends_with(r"\agentwatch") || text.ends_with("/agentwatch"),
            "official dir ends in AgentWatch: {got:?}"
        );
        assert!(
            !text.contains("aw-not-program-data"),
            "ProgramData env moved the official dir: {got:?}"
        );
    }

    /// Spellings of the same directory are still the official one: different
    /// case, a trailing separator, a `\\?\` prefix, and a `..` segment. A
    /// case-sensitive string compare would let a non-admin daemon through.
    #[test]
    fn official_dir_spellings_compare_equal() {
        let official = std::path::Path::new(r"C:\ProgramData\AgentWatch");
        for spelling in [
            r"c:\programdata\agentwatch",
            r"C:\ProgramData\AgentWatch\\",
            r"\\?\C:\ProgramData\AgentWatch",
            r"C:\ProgramData\AgentWatch\.",
            r"C:\ProgramData\Other\..\AgentWatch",
        ] {
            assert!(
                super::is_machine_data_dir(std::path::Path::new(spelling), official),
                "{spelling} must be recognized as the official dir"
            );
        }
        assert!(!super::is_machine_data_dir(
            std::path::Path::new(r"C:\somewhere-else\AgentWatch"),
            official
        ));
    }

    /// Give a fixture the exact owner its test claims it has. In particular,
    /// an elevated GitHub runner's TokenOwner is Administrators, while the
    /// fixture can represent a normal user's pre-created directory.
    fn set_fixture_owner(path: &Path, owner: &str) -> Result<(), PlatformError> {
        let (handle, _) = open_data_object(path)?;
        let owner_wide: Vec<u16> = std::ffi::OsStr::new(owner)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut owner_sid = PSID::default();
        // SAFETY: owner_wide is a NUL-terminated SID string and owner_sid is
        // writable output storage for a LocalAlloc result.
        #[allow(unsafe_code)]
        let converted =
            unsafe { ConvertStringSidToSidW(PCWSTR(owner_wide.as_ptr()), &mut owner_sid) };
        if let Err(error) = converted {
            close(handle);
            return Err(super::io_error(error));
        }
        // SAFETY: handle is an open file or directory handle and owner_sid is
        // live until SetSecurityInfo finishes below.
        #[allow(unsafe_code)]
        let result = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner_sid,
                PSID::default(),
                None,
                None,
            )
        }
        .ok()
        .map_err(super::io_error);
        // SAFETY: ConvertStringSidToSidW allocated owner_sid with LocalAlloc.
        #[allow(unsafe_code)]
        let _ = unsafe { windows::Win32::Foundation::LocalFree(HLOCAL(owner_sid.0.cast())) };
        close(handle);
        result
    }

    fn user_data_dir_policy(sid: String) -> DataDirPolicy {
        data_dir_policy_for_token(sid.clone(), sid, false)
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
        let (handle, is_directory) = open_data_object(&data)?;
        assert!(is_directory);
        set_data_dir_dacl(handle, DataDirAcl::Machine)?;
        let readback = read_dacl(handle)?;
        // Restore the creator's access before cleanup. This is outside the
        // assertion: the readback above is the state the daemon leaves behind.
        let Owner::Windows { sid: owner, .. } = current_token_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Windows account",
            });
        };
        set_data_dir_dacl(handle, DataDirAcl::Owner(&owner))?;
        close(handle);
        let _ = std::fs::remove_dir_all(&root);

        assert!(readback.protected, "DACL inheritance must be disabled");
        assert_eq!(readback.aces.len(), 2, "no Users/Everyone/other ACEs");
        assert!(readback
            .aces
            .iter()
            .all(|(_, mask, flags)| { *mask == FILE_ALL_ACCESS.0 && *flags == 3 }));
        let mut sids: Vec<&str> = readback
            .aces
            .iter()
            .map(|(sid, _, _)| sid.as_str())
            .collect();
        sids.sort_unstable();
        assert_eq!(sids, vec![SYSTEM_SID, ADMINISTRATORS_SID]);
        Ok(())
    }

    /// Fixture: give `path` an unprotected DACL that lets Everyone, Users and
    /// Authenticated Users write, with inheritable ACEs (the opposite of what
    /// the daemon leaves behind).
    fn set_world_writable_dacl(path: &Path) -> Result<(), PlatformError> {
        let (handle, _) = open_data_object(path)?;
        let sddl: Vec<u16> =
            std::ffi::OsStr::new("D:(A;OICI;FA;;;WD)(A;OICI;FA;;;BU)(A;OICI;FA;;;AU)")
                .encode_wide()
                .chain(Some(0))
                .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated SDDL; Windows writes a LocalAlloc descriptor.
        #[allow(unsafe_code)]
        let converted = unsafe {
            super::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                super::SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        };
        if let Err(error) = converted {
            close(handle);
            return Err(super::io_error(error));
        }
        let mut present = windows::Win32::Foundation::BOOL(0);
        let mut defaulted = windows::Win32::Foundation::BOOL(0);
        let mut dacl: *mut super::ACL = std::ptr::null_mut();
        // SAFETY: descriptor is live until LocalFree below; outputs writable.
        #[allow(unsafe_code)]
        let result = unsafe {
            super::GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
        }
        .map_err(super::io_error)
        .and_then(|()| {
            // SAFETY: `dacl` points into the live descriptor; handle is open.
            #[allow(unsafe_code)]
            unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    PSID::default(),
                    PSID::default(),
                    Some(dacl.cast_const()),
                    None,
                )
            }
            .ok()
            .map_err(super::io_error)
        });
        // SAFETY: descriptor came from the SDDL conversion above.
        #[allow(unsafe_code)]
        let _ = unsafe { windows::Win32::Foundation::LocalFree(HLOCAL(descriptor.0.cast())) };
        close(handle);
        result
    }

    /// Review 15:07 (b): an elevated daemon given an Administrators-owned dir
    /// whose DACL is world-writable (plus a world-writable file inside) must
    /// not keep that DACL: it is replaced by the protected SYSTEM +
    /// Administrators DACL, with no Everyone/Users/Authenticated Users ACE.
    #[test]
    fn elevated_admin_owned_dir_with_world_writable_dacl_is_corrected() -> Result<(), PlatformError>
    {
        let root = temp_dir("world-writable");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        std::fs::write(data.join("state"), b"x")?;
        if let Err(error) = set_fixture_owner(&data, ADMINISTRATORS_SID)
            .and_then(|()| set_fixture_owner(&data.join("state"), ADMINISTRATORS_SID))
        {
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("skipped: cannot set an Administrators owner here ({error:?})");
            return Ok(());
        }
        set_world_writable_dacl(&data)?;
        set_world_writable_dacl(&data.join("state"))?;
        let policy = data_dir_policy_for_token(
            "S-1-5-21-10-20-30-1001".to_owned(),
            ADMINISTRATORS_SID.to_owned(),
            true,
        );
        let secured = secure_data_dir_with_policy(&data, &root.join("official"), policy);
        let mut readbacks = Vec::new();
        for path in [data.clone(), data.join("state")] {
            let (handle, _) = open_data_object(&path)?;
            readbacks.push(read_dacl(handle));
            let Owner::Windows { sid: owner, .. } = current_token_owner()? else {
                close(handle);
                return Err(PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "current process is not a Windows account",
                });
            };
            let _ = set_data_dir_dacl(handle, DataDirAcl::Owner(&owner));
            close(handle);
        }
        let _ = std::fs::remove_dir_all(&root);
        secured?;
        for readback in readbacks {
            let readback = readback?;
            assert!(readback.protected, "inheritance must be disabled");
            let mut sids: Vec<&str> = readback
                .aces
                .iter()
                .map(|(sid, _, _)| sid.as_str())
                .collect();
            sids.sort_unstable();
            assert_eq!(sids, vec![SYSTEM_SID, ADMINISTRATORS_SID], "{readback:?}");
            for broad in ["S-1-1-0", "S-1-5-32-545", "S-1-5-11"] {
                assert!(!sids.contains(&broad), "{broad} ACE survived");
            }
        }
        Ok(())
    }

    /// A second daemon must validate the first daemon's inherited lock-file
    /// DACL without trying to write it. Windows can reject a DACL replacement
    /// while that file has the first daemon's exclusive instance lock.
    #[test]
    fn matching_inherited_dacl_is_not_rewritten_while_locked() -> Result<(), PlatformError> {
        let root = temp_dir("locked-inherited-dacl");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        set_fixture_owner(&data, ADMINISTRATORS_SID)?;
        let policy = data_dir_policy_for_token(
            "S-1-5-21-10-20-30-1001".to_owned(),
            ADMINISTRATORS_SID.to_owned(),
            true,
        );
        secure_data_dir_with_policy(&data, &root.join("official"), policy.clone())?;

        let lock_path = data.join("agentwatchd.lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock.try_lock().map_err(|_| PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "test fixture could not lock the instance file",
        })?;

        let second_start = secure_data_dir_with_policy(&data, &root.join("official"), policy);
        drop(lock);
        let _ = std::fs::remove_dir_all(&root);
        second_start.map(|_| ())
    }

    #[test]
    fn machine_data_dir_refuses_a_precreated_normal_owner() -> Result<(), PlatformError> {
        let root = temp_dir("foreign-owner");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        let Owner::Windows { sid, .. } = current_token_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Windows account",
            });
        };
        set_fixture_owner(&data, &sid)?;
        let Err(error) =
            secure_data_dir_with_policy(&data, &root.join("official"), DataDirPolicy::Machine)
        else {
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

    /// Review 15:07: a non-elevated token must never accept an
    /// Administrators-owned directory, whatever its default owner says. Token
    /// info is mocked, so this runs the same on an elevated CI runner.
    #[test]
    fn non_elevated_token_refuses_an_administrators_owned_dir() {
        let user = "S-1-5-21-10-20-30-1001".to_owned();
        for default_owner in [ADMINISTRATORS_SID.to_owned(), user.clone()] {
            let policy = data_dir_policy_for_token(user.clone(), default_owner, false);
            assert!(!policy.accepts_owner(ADMINISTRATORS_SID));
            assert!(policy.accepts_owner(&user));
        }
        // Elevated with default owner Administrators: accepted (machine policy).
        let elevated = data_dir_policy_for_token(user.clone(), ADMINISTRATORS_SID.to_owned(), true);
        assert!(elevated.accepts_owner(ADMINISTRATORS_SID));
        assert!(!elevated.accepts_owner(&user));
    }

    #[test]
    fn data_dir_policy_matrix_uses_only_the_daemon_token() {
        let user = "S-1-5-21-10-20-30-1001".to_owned();
        let default_owner = ADMINISTRATORS_SID.to_owned();
        let other = "S-1-5-21-10-20-30-1002";
        for (policy, official, owner, allowed) in [
            // A normal token can use a non-official dir owned by its user SID
            // and no other owner, even if its default owner is a group.
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                true,
                user.as_str(),
                false,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                true,
                SYSTEM_SID,
                false,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                true,
                other,
                false,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                false,
                user.as_str(),
                true,
            ),
            // Non-elevated token whose default owner is Administrators: an
            // Administrators-owned dir is refused (review 15:07).
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                false,
                default_owner.as_str(),
                false,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                false,
                SYSTEM_SID,
                false,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), false),
                false,
                other,
                false,
            ),
            // An elevated token cannot use either official or custom dirs
            // owned by the normal token.
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), true),
                true,
                SYSTEM_SID,
                true,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), true),
                true,
                ADMINISTRATORS_SID,
                true,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), true),
                true,
                user.as_str(),
                false,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), true),
                false,
                SYSTEM_SID,
                true,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), true),
                false,
                ADMINISTRATORS_SID,
                true,
            ),
            (
                data_dir_policy_for_token(user.clone(), default_owner.clone(), true),
                false,
                user.as_str(),
                false,
            ),
        ] {
            let path_allowed = !official || policy.permits_official_data_dir();
            assert_eq!(path_allowed && policy.accepts_owner(owner), allowed);
        }
    }

    #[test]
    fn user_policy_refuses_the_official_machine_path() -> Result<(), PlatformError> {
        let root = temp_dir("official-user");
        std::fs::create_dir_all(&root)?;
        let Owner::Windows { sid, .. } = current_token_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Windows account",
            });
        };
        let Err(error) = secure_data_dir_with_policy(&root, &root, user_data_dir_policy(sid))
        else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "normal token used the machine location",
            });
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "official data directory requires a privileged daemon",
            }
        ));
        Ok(())
    }

    #[test]
    fn user_data_dir_accepts_its_creator_and_has_one_owner_ace() -> Result<(), PlatformError> {
        let root = temp_dir("self-owner");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        let secret = data.join("secret.txt");
        std::fs::write(&secret, b"metadata only")?;
        let Owner::Windows { sid, .. } = current_token_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Windows account",
            });
        };
        set_fixture_owner(&data, &sid)?;
        set_fixture_owner(&secret, &sid)?;
        secure_data_dir_with_policy(
            &data,
            &root.join("official"),
            user_data_dir_policy(sid.clone()),
        )?;
        let (handle, is_directory) = open_data_object(&data)?;
        assert!(is_directory);
        let readback = read_dacl(handle)?;
        close(handle);
        let (secret_handle, is_directory) = open_data_object(&secret)?;
        assert!(!is_directory);
        let secret_readback = read_dacl(secret_handle)?;
        close(secret_handle);
        let _ = std::fs::remove_dir_all(&root);
        assert!(readback.protected);
        assert_eq!(readback.aces, vec![(sid, FILE_ALL_ACCESS.0, 3)]);
        assert_eq!(secret_readback.aces.len(), 1, "existing file is hardened");
        assert_eq!(secret_readback.aces[0].0, readback.aces[0].0);
        assert_eq!(secret_readback.aces[0].1, FILE_ALL_ACCESS.0);
        Ok(())
    }

    #[test]
    fn secure_data_dir_refuses_final_ancestor_and_nested_reparse_points(
    ) -> Result<(), PlatformError> {
        let root = temp_dir("reparse");
        let target = root.join("target");
        let link = root.join("link");
        let data = root.join("data");
        std::fs::create_dir_all(&target)?;
        let Owner::Windows { sid, .. } = current_token_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Windows account",
            });
        };
        let link_wide: Vec<u16> = link.as_os_str().encode_wide().chain(Some(0)).collect();
        let target_wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both paths are NUL terminated; this only creates a test link.
        #[allow(unsafe_code)]
        let created = unsafe {
            CreateSymbolicLinkW(
                windows::core::PCWSTR(link_wide.as_ptr()),
                windows::core::PCWSTR(target_wide.as_ptr()),
                SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            )
        };
        if !created.as_bool() {
            let _ = std::fs::remove_dir_all(&root);
            return Err(super::io_error(windows::core::Error::from_win32()));
        }
        std::fs::create_dir_all(&data)?;
        set_fixture_owner(&data, &sid)?;
        let policy = user_data_dir_policy(sid.clone());
        let final_error =
            secure_data_dir_with_policy(&link, &root.join("official"), policy.clone());
        let ancestor_error = secure_data_dir_with_policy(
            &link.join("child"),
            &root.join("official"),
            policy.clone(),
        );
        secure_data_dir_with_policy(&data, &root.join("official"), policy)?;
        let nested = data.join("evil");
        let nested_wide: Vec<u16> = nested.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both paths are NUL terminated; this only creates a test link.
        #[allow(unsafe_code)]
        let nested_created = unsafe {
            CreateSymbolicLinkW(
                windows::core::PCWSTR(nested_wide.as_ptr()),
                windows::core::PCWSTR(target_wide.as_ptr()),
                SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            )
        };
        if !nested_created.as_bool() {
            let _ = std::fs::remove_dir_all(&root);
            return Err(super::io_error(windows::core::Error::from_win32()));
        }
        let nested_error =
            secure_data_dir_with_policy(&data, &root.join("official"), user_data_dir_policy(sid));
        let _ = std::fs::remove_dir_all(&root);
        for error in [final_error, ancestor_error, nested_error] {
            assert!(matches!(
                error,
                Err(PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "data directory path contains a reparse point"
                        | "data directory contains a reparse point",
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn pipe_owner_rule_depends_on_service_installation() {
        let user = "S-1-5-21-10-20-30-1001";
        let other = "S-1-5-21-10-20-30-1002";
        let no_service = PipeServiceStatus::NotInstalled;
        let installed = PipeServiceStatus::Installed { binary_path: None };
        let scm_failed = PipeServiceStatus::QueryFailed {
            operation: "OpenSCManagerW",
            win32_error: 5,
        };

        assert!(trusted_pipe_owner(
            LOCAL_SYSTEM_SID,
            &no_service,
            Some(user)
        ));
        assert!(trusted_pipe_owner(user, &no_service, Some(user)));
        assert!(!trusted_pipe_owner(other, &no_service, Some(user)));
        assert!(trusted_pipe_owner(LOCAL_SYSTEM_SID, &installed, Some(user)));
        assert!(!trusted_pipe_owner(user, &installed, Some(user)));
        assert!(trusted_pipe_owner(
            LOCAL_SYSTEM_SID,
            &scm_failed,
            Some(user)
        ));
        assert!(!trusted_pipe_owner(user, &scm_failed, Some(user)));
        assert!(service_status_detail(&scm_failed)
            .expect("SCM failure detail")
            .contains("requiring a LocalSystem-owned pipe"));
    }

    #[test]
    fn image_path_comparison_uses_the_full_canonical_path_case_insensitively() {
        let root = temp_dir("pipe-image");
        let installed_dir = root.join("installed");
        let other_dir = root.join("other");
        std::fs::create_dir_all(&installed_dir).expect("installed dir");
        std::fs::create_dir_all(&other_dir).expect("other dir");
        let installed = installed_dir.join("agentwatchd.exe");
        let same_name_elsewhere = other_dir.join("agentwatchd.exe");
        std::fs::write(&installed, b"").expect("installed image");
        std::fs::write(&same_name_elsewhere, b"").expect("other image");
        let different_case = PathBuf::from(installed.to_string_lossy().to_ascii_uppercase());

        assert!(same_image_path(&installed, &different_case));
        assert!(!same_image_path(&installed, &same_name_elsewhere));
        assert!(
            installed_service_image_detail_for_paths(&installed, &same_name_elsewhere)
                .expect("different directories have detail")
                .contains("not the installed agentwatchd")
        );
        assert!(installed_service_image_detail_for_paths(&installed, &different_case).is_none());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn release_transfers_the_only_reap_handle_and_keeps_exit_7() {
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["cmd".to_owned(), "/c".to_owned(), "exit 7".to_owned()],
            cwd: None,
            env: Vec::new(),
            env_source: crate::EnvSource::Inherit,
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
            env_source: crate::EnvSource::Inherit,
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
            env_source: crate::EnvSource::Inherit,
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
            env_source: crate::EnvSource::Inherit,
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
            env_source: crate::EnvSource::Inherit,
        };
        let held = platform()
            .spawn_suspended(&caller, &request)
            .expect("held Windows child");
        let released = held.release().expect("released child");
        assert_eq!(released.wait().expect("reap child"), ReapOutcome::Exited(0));
    }

    /// `Exact` gives CreateProcessW only the request's names. Re-executing the
    /// test binary avoids a shell adding its own variables before recording
    /// the child environment.
    #[test]
    fn exact_environment_contains_only_request_values() {
        let caller = IdentifiedCaller::current_user().expect("current user");
        let dir = std::env::temp_dir().join(format!("aw-windows-exact-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("output directory");
        let output = dir.join("environment.txt");
        let request = SpawnRequest {
            command: vec![
                std::env::current_exe()
                    .expect("test executable")
                    .to_string_lossy()
                    .into_owned(),
                "--exact".to_owned(),
                "windows::tests::exact_environment_child_records_values".to_owned(),
                "--nocapture".to_owned(),
            ],
            cwd: None,
            env: vec![
                (
                    "AW_EXACT_ENV_OUTPUT".to_owned(),
                    output.to_string_lossy().into_owned(),
                ),
                ("aw_exact_env_value".to_owned(), "first".to_owned()),
                ("AW_EXACT_ENV_VALUE".to_owned(), "only-this".to_owned()),
            ],
            env_source: crate::EnvSource::Exact,
        };
        let held = platform()
            .spawn_suspended(&caller, &request)
            .expect("held Windows child");
        let released = held.release().expect("released child");
        assert_eq!(released.wait().expect("reap child"), ReapOutcome::Exited(0));

        let mut got: Vec<String> = std::fs::read_to_string(&output)
            .expect("child environment")
            .lines()
            .map(str::to_owned)
            .collect();
        got.sort();
        let mut want = vec![
            format!("AW_EXACT_ENV_OUTPUT={}", output.display()),
            "AW_EXACT_ENV_VALUE=only-this".to_owned(),
        ];
        want.sort();
        assert_eq!(got, want, "Exact child environment differs from request");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exact_environment_child_records_values() {
        let Ok(output) = std::env::var("AW_EXACT_ENV_OUTPUT") else {
            return;
        };
        let mut values: Vec<String> = std::env::vars()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        values.sort();
        std::fs::write(output, values.join("\n")).expect("write child environment");
    }
}
