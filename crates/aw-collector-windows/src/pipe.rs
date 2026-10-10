//! Named-pipe security for agentwatchd's internal channel (api-and-cli §1).
//!
//! The daemon runs as LocalSystem or an elevated administrator; the desktop
//! app and `aw` run as the ordinary user. The pipe therefore carries an
//! explicit DACL instead of the default one (which only lets LocalSystem,
//! Administrators, and the creator write):
//!
//! - LocalSystem and Administrators: full control.
//! - `AgentWatch Users` (when that local group exists), otherwise the
//!   interactive users (`IU`): read and write, but **not**
//!   `FILE_CREATE_PIPE_INSTANCE`, so an ordinary user cannot add a rogue
//!   instance of the pipe name and impersonate the server.
//!
//! The caller is identified from its token: `GetNamedPipeClientProcessId` →
//! `OpenProcess` → `OpenProcessToken` → `TokenUser` (SID) and `TokenElevation`.
//! Administrator means an elevated token or LocalSystem, not membership in a
//! group filtered by UAC.
//!
//! [`sddl_for`] is pure and tested on every target. Everything that calls
//! Win32 is Windows-only and is the only `unsafe` in this module; each block
//! carries a `SAFETY` comment.

#![cfg_attr(target_os = "windows", allow(unsafe_code))]

/// Local group named by api-and-cli §1.
pub const USERS_GROUP: &str = "AgentWatch Users";

/// LocalSystem.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE` without `FILE_APPEND_DATA`
/// (= `FILE_CREATE_PIPE_INSTANCE` on a pipe). 0x120089 | 0x120112.
pub const CLIENT_RIGHTS: u32 = 0x0012_019B;

/// SDDL for the pipe. `group_sid` is the `AgentWatch Users` SID when the group
/// exists; `None` falls back to interactive users.
#[must_use]
pub fn sddl_for(group_sid: Option<&str>) -> String {
    let clients = group_sid.filter(|sid| is_sid_text(sid)).unwrap_or("IU");
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{CLIENT_RIGHTS:x};;;{clients})")
}

/// `S-1-…` with digits and dashes only, so a SID cannot inject SDDL.
fn is_sid_text(text: &str) -> bool {
    text.starts_with("S-1-") && text[4..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Who is on the other end of a pipe connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeClient {
    /// String SID of the client process token (`S-1-5-21-…`).
    pub sid: String,
    /// Elevated token or LocalSystem.
    pub admin: bool,
}

/// Admin decision from token facts. Pure.
#[must_use]
pub fn is_admin(sid: &str, elevated: bool) -> bool {
    elevated || sid == LOCAL_SYSTEM_SID
}

#[cfg(target_os = "windows")]
pub use imp::{client_identity, create_server, pipe_sddl};

#[cfg(target_os = "windows")]
mod imp {
    use std::ffi::{c_void, OsStr};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, PSID};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountNameW, TokenElevation, TokenUser, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{is_admin, sddl_for, PipeClient, USERS_GROUP};

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text).encode_wide().chain(Some(0)).collect()
    }

    fn os_err(err: windows::core::Error) -> io::Error {
        io::Error::from_raw_os_error(err.code().0 & 0xFFFF)
    }

    /// SDDL with the `AgentWatch Users` SID when the group exists.
    #[must_use]
    pub fn pipe_sddl() -> String {
        sddl_for(group_sid(USERS_GROUP).as_deref())
    }

    fn group_sid(name: &str) -> Option<String> {
        let account = wide(name);
        let mut sid_len = 0_u32;
        let mut domain_len = 0_u32;
        let mut use_ = SID_NAME_USE(0);
        // SAFETY: size query. Null buffers with zero lengths are the documented
        // way to learn the sizes; the call fails with ERROR_INSUFFICIENT_BUFFER.
        let _ = unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(account.as_ptr()),
                PSID(std::ptr::null_mut()),
                &mut sid_len,
                PWSTR::null(),
                &mut domain_len,
                &mut use_,
            )
        };
        if sid_len == 0 {
            return None;
        }
        let mut sid = vec![0_u8; sid_len as usize];
        let mut domain = vec![0_u16; domain_len.max(1) as usize];
        // SAFETY: both buffers have exactly the lengths the size query returned
        // and live until the call returns.
        let found = unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(account.as_ptr()),
                PSID(sid.as_mut_ptr().cast()),
                &mut sid_len,
                PWSTR(domain.as_mut_ptr()),
                &mut domain_len,
                &mut use_,
            )
        };
        found.ok()?;
        sid_string(PSID(sid.as_mut_ptr().cast()))
    }

    fn sid_string(sid: PSID) -> Option<String> {
        let mut text = PWSTR::null();
        // SAFETY: `sid` points at a valid SID for the duration of the call. On
        // success `text` is a LocalAlloc'd NUL-terminated string freed below.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }.ok()?;
        // SAFETY: `text` is a valid NUL-terminated wide string from the call above.
        let out = unsafe { text.to_string() }.ok();
        // SAFETY: `text` was allocated by ConvertSidToStringSidW with LocalAlloc.
        let _ = unsafe { LocalFree(HLOCAL(text.0.cast())) };
        out
    }

    /// Create one pipe instance named `name` with the DACL in `sddl`.
    /// Must be called inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// SDDL parse or pipe creation failure.
    pub fn create_server(name: &OsStr, first: bool, sddl: &str) -> io::Result<NamedPipeServer> {
        let text = wide(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `text` is NUL-terminated and outlives the call. On success
        // `descriptor` is LocalAlloc'd and freed below, after the pipe exists.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(os_err)?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
        // stays allocated until after this call; the kernel copies it into the
        // pipe object, so freeing it afterwards is allowed.
        let created = unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        };
        // SAFETY: `descriptor` was LocalAlloc'd by the conversion above.
        let _ = unsafe { LocalFree(HLOCAL(descriptor.0)) };
        created
    }

    /// Identify the client connected to `pipe` from its process token.
    ///
    /// # Errors
    ///
    /// Any Win32 failure along the PID → process → token → SID path. The
    /// caller must treat an error as "not identified", never as admin.
    pub fn client_identity(pipe: &NamedPipeServer) -> io::Result<PipeClient> {
        let handle = HANDLE(pipe.as_raw_handle() as isize);
        let mut pid = 0_u32;
        // SAFETY: `handle` is the live server end owned by `pipe`.
        unsafe { GetNamedPipeClientProcessId(handle, &mut pid) }.map_err(os_err)?;
        // SAFETY: plain query access to a process id; the handle is closed below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(os_err)?;
        let mut token = HANDLE::default();
        // SAFETY: `process` is a valid handle opened above.
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        // SAFETY: `process` is owned here and not used again.
        let _ = unsafe { CloseHandle(process) };
        opened.map_err(os_err)?;
        let result = token_identity(token);
        // SAFETY: `token` was opened above and is not used again.
        let _ = unsafe { CloseHandle(token) };
        result
    }

    fn token_identity(token: HANDLE) -> io::Result<PipeClient> {
        let mut needed = 0_u32;
        // SAFETY: size query with no buffer.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::other("TokenUser size query returned 0"));
        }
        // u64 storage keeps TOKEN_USER aligned.
        let mut buf = vec![0_u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `needed` bytes and is 8-byte aligned.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(os_err)?;
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
        // pointer points inside `buf`, which is alive for this scope.
        let sid_ptr = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let sid = sid_string(sid_ptr).ok_or_else(|| io::Error::other("SID not convertible"))?;

        let mut elevation = TOKEN_ELEVATION::default();
        let size = u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(4);
        // SAFETY: `elevation` is a TOKEN_ELEVATION of exactly `size` bytes.
        unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                size,
                &mut needed,
            )
        }
        .map_err(os_err)?;
        let elevated = elevation.TokenIsElevated != 0;
        Ok(PipeClient {
            admin: is_admin(&sid, elevated),
            sid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{is_admin, sddl_for, CLIENT_RIGHTS};

    #[test]
    fn fallback_grants_interactive_users_without_create_instance() {
        let sddl = sddl_for(None);
        assert_eq!(sddl, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)");
        // FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE) is not granted.
        assert_eq!(CLIENT_RIGHTS & 0x4, 0);
        // Read and write data are.
        assert_eq!(CLIENT_RIGHTS & 0x3, 0x3);
    }

    #[test]
    fn group_sid_is_used_and_cannot_inject() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert!(sddl_for(Some(sid)).ends_with(&format!(";;;{sid})")));
        assert!(sddl_for(Some("S-1-5)(A;;GA;;;WD")).ends_with(";;;IU)"));
        assert!(sddl_for(Some("WD")).ends_with(";;;IU)"));
    }

    #[test]
    fn admin_is_elevation_or_system() {
        assert!(is_admin("S-1-5-18", false));
        assert!(is_admin("S-1-5-21-1-2-3-500", true));
        assert!(!is_admin("S-1-5-21-1-2-3-500", false));
    }
}
