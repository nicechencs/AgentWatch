//! Named-pipe security for agentwatchd's internal channel (api-and-cli §1).
//!
//! The daemon runs as LocalSystem or an elevated administrator; the desktop
//! app and `aw` run as the ordinary user. The pipe therefore carries an
//! explicit DACL instead of the default one (which only lets LocalSystem,
//! Administrators, and the creator write):
//!
//! - LocalSystem and Administrators: full control; the pipe's owner (the
//!   daemon's own account) too, through `OW`.
//! - `AgentWatch Users` (when that local group exists), otherwise the
//!   interactive users (`IU`): read and write, but **not**
//!   `FILE_CREATE_PIPE_INSTANCE`, so an ordinary user cannot add a rogue
//!   instance of the pipe name and impersonate the server.
//!
//! Caller identification belongs to `aw-platform::identify_pipe_peer`, which
//! authenticates the connected pipe token at the OS boundary. This module only
//! creates the DACL-protected server endpoint.
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

/// SDDL for the pipe. The daemon's actual token owner is explicit so clients
/// can authenticate the already-open pipe object without opening the daemon
/// process token. A service daemon therefore creates an `O:SY` pipe; a
/// development daemon creates a pipe owned by its current user.
///
/// `group_sid` is the `AgentWatch Users` SID when the group exists; `None`
/// falls back to interactive users.
#[must_use]
pub fn sddl_for(owner_sid: &str, group_sid: Option<&str>) -> String {
    let owner = if is_sid_text(owner_sid) {
        owner_sid
    } else {
        LOCAL_SYSTEM_SID
    };
    let clients = group_sid.filter(|sid| is_sid_text(sid)).unwrap_or("IU");
    // OW (owner rights): the account that created the pipe keeps full
    // control, so an unprivileged development daemon can still add the next
    // instance even though `clients` may not.
    format!("O:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x{CLIENT_RIGHTS:x};;;{clients})")
}

/// `S-1-…` with digits and dashes only, so a SID cannot inject SDDL.
fn is_sid_text(text: &str) -> bool {
    text.starts_with("S-1-") && text[4..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Admin decision from token facts. Pure.
#[must_use]
pub fn is_admin(sid: &str, elevated: bool) -> bool {
    elevated || sid == LOCAL_SYSTEM_SID
}

#[cfg(target_os = "windows")]
pub use imp::{create_server, flush_server, pipe_sddl};

#[cfg(target_os = "windows")]
mod imp {
    use std::ffi::{c_void, OsStr};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::RawHandle;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::core::Error;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, PSID};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountNameW, TokenUser, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::FlushFileBuffers;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{sddl_for, USERS_GROUP};

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text).encode_wide().chain(Some(0)).collect()
    }

    fn os_err(err: windows::core::Error) -> io::Error {
        io::Error::from_raw_os_error(err.code().0 & 0xFFFF)
    }

    /// SDDL with this daemon's explicit owner SID and the `AgentWatch Users`
    /// SID when that group exists.
    pub fn pipe_sddl() -> io::Result<String> {
        Ok(sddl_for(
            &current_owner_sid()?,
            group_sid(USERS_GROUP).as_deref(),
        ))
    }

    fn current_owner_sid() -> io::Result<String> {
        let mut token = HANDLE::default();
        // SAFETY: the current-process pseudo-handle is valid, and `token` is
        // writable output. The returned token is closed on every path below.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(os_err)?;
        let result = token_user_sid(token);
        // SAFETY: OpenProcessToken above returned this owned token handle.
        let _ = unsafe { CloseHandle(token) };
        result
    }

    fn token_user_sid(token: HANDLE) -> io::Result<String> {
        let mut bytes = 0_u32;
        // SAFETY: documented TokenUser sizing query with no output buffer.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut bytes) };
        if bytes == 0 {
            return Err(os_err(Error::from_win32()));
        }
        let mut storage = vec![0_u64; (bytes as usize).div_ceil(std::mem::size_of::<u64>())];
        // SAFETY: storage is aligned and has at least `bytes` writable bytes.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                bytes,
                &mut bytes,
            )
        }
        .map_err(os_err)?;
        // SAFETY: successful TokenUser output starts with TOKEN_USER and the
        // SID remains live in `storage` until `sid_text` returns.
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        sid_text(user.User.Sid)
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
        sid_text(sid).ok()
    }

    fn sid_text(sid: PSID) -> io::Result<String> {
        let mut text = PWSTR::null();
        // SAFETY: `sid` points at a valid SID for the duration of the call. On
        // success `text` is a LocalAlloc'd NUL-terminated string freed below.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(os_err)?;
        // SAFETY: `text` is a valid NUL-terminated wide string from the call above.
        let out = unsafe { text.to_string() }
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID was not valid UTF-16"));
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
        // The API is local-only.  Do not allow a remote SMB client to reach an
        // otherwise valid local DACL.
        options.reject_remote_clients(true);
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

    /// Commit a connected server pipe's buffered reply before disconnecting
    /// that one-request instance. `DisconnectNamedPipe` otherwise may discard
    /// a response while the client is still reading it.
    pub fn flush_server(handle: RawHandle) -> io::Result<()> {
        // SAFETY: `handle` is the live server end of a connected named pipe;
        // the IPC server retains ownership for the duration of this call.
        unsafe { FlushFileBuffers(windows::Win32::Foundation::HANDLE(handle as isize)) }
            .map_err(os_err)
    }
}

#[cfg(test)]
mod tests {
    use super::{is_admin, sddl_for, CLIENT_RIGHTS};

    const OWNER: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn fallback_grants_interactive_users_without_create_instance() {
        let sddl = sddl_for(OWNER, None);
        assert_eq!(
            sddl,
            "O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;IU)"
        );
        // FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE) is not granted.
        assert_eq!(CLIENT_RIGHTS & 0x4, 0);
        // Read and write data are.
        assert_eq!(CLIENT_RIGHTS & 0x3, 0x3);
    }

    #[test]
    fn group_sid_is_used_and_cannot_inject() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert!(sddl_for(OWNER, Some(sid)).ends_with(&format!(";;;{sid})")));
        assert!(sddl_for(OWNER, Some("S-1-5)(A;;GA;;;WD")).ends_with(";;;IU)"));
        assert!(sddl_for(OWNER, Some("WD")).ends_with(";;;IU)"));
    }

    #[test]
    fn owner_is_explicit_and_invalid_owner_is_not_interpolated() {
        assert!(sddl_for(OWNER, None).starts_with(&format!("O:{OWNER}D:")));
        assert!(sddl_for("S-1-5)(A;;GA;;;WD", None).starts_with("O:S-1-5-18D:"));
    }

    #[test]
    fn admin_is_elevation_or_system() {
        assert!(is_admin("S-1-5-18", false));
        assert!(is_admin("S-1-5-21-1-2-3-500", true));
        assert!(!is_admin("S-1-5-21-1-2-3-500", false));
    }
}
