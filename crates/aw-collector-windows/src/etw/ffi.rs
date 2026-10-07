//! The only module in this crate that calls ETW directly.
//!
//! ferrisetw 1.2.0 exposes `stop_trace_by_name` but keeps `ControlTraceW` and
//! the loss counters private, and it does not read `QueryPerformanceFrequency`.
//! The two wrappers below are the whole of the `unsafe` in `aw-collector-windows`.
//! Everything else goes through ferrisetw's safe API.
//!
//! `windows` 0.57 is already in the tree as a ferrisetw dependency (MIT OR
//! Apache-2.0). This crate names it directly so the FFI stays in one file.

#![allow(unsafe_code)]

use std::mem::size_of;

use ferrisetw::native::EvntraceNativeError;
use ferrisetw::trace::TraceError;
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
    WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

use super::session::{LossReading, SessionError};

/// Win32 `ERROR_WMI_INSTANCE_NOT_FOUND` (4201). `ControlTrace(STOP)` returns
/// this when no session of that name exists, which is the normal case at
/// startup. It is not a failure.
const ERROR_WMI_INSTANCE_NOT_FOUND: i32 = 4201;

/// Stop a leftover session by name.
///
/// `Ok(true)` means a session was stopped. `Ok(false)` means there was no
/// session of that name. Any other Win32 code becomes [`SessionError`].
pub fn stop_session_by_name(name: &str) -> Result<bool, SessionError> {
    let wide = wide_name(name)?;
    let mut properties = query_properties();
    // SAFETY: `properties` is a zeroed EVENT_TRACE_PROPERTIES plus no trailing
    // name buffer. STOP does not read LoggerName (the name is the second
    // argument) and does not write past the struct. `wide` is NUL-terminated
    // and outlives the call. The handle is 0 because the lookup is by name.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR(wide.as_ptr()),
            &mut properties,
            windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_STOP,
        )
    };
    match win32_code(status) {
        0 => Ok(true),
        ERROR_WMI_INSTANCE_NOT_FOUND => Ok(false),
        code => Err(SessionError::from_win32("stop", code)),
    }
}

/// `ControlTrace(QUERY)` for `EventsLost` and `RealTimeBuffersLost`.
///
/// The counters are cumulative for the life of the session. The caller diffs
/// them; this function does not.
pub fn query_loss(name: &str) -> Result<LossReading, SessionError> {
    let wide = wide_name(name)?;
    let mut properties = query_properties();
    // SAFETY: same layout guarantee as `stop_session_by_name`. QUERY writes
    // the counters into `properties` and does not write the trailing name
    // buffers when `LogFileNameOffset` and `LoggerNameOffset` are 0, which
    // they are (`..Default::default()` zeroes them).
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR(wide.as_ptr()),
            &mut properties,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    let code = win32_code(status);
    if code != 0 {
        return Err(SessionError::from_win32("query", code));
    }
    Ok(LossReading {
        events_lost: properties.EventsLost,
        realtime_buffers_lost: properties.RealTimeBuffersLost,
    })
}

/// One QPC sample: `(counter, frequency)`.
///
/// `None` when the frequency is 0 or the API failed. A missing clock is not
/// reported as frequency 1.
pub fn read_qpc() -> Option<(u64, u64)> {
    let mut counter = 0i64;
    let mut frequency = 0i64;
    // SAFETY: both pointers are live local `i64`s. The API writes one value to
    // each and does not retain them. A failure leaves the locals untouched.
    let ok = unsafe {
        QueryPerformanceCounter(&mut counter).is_ok()
            && QueryPerformanceFrequency(&mut frequency).is_ok()
    };
    if !ok || frequency <= 0 || counter < 0 {
        return None;
    }
    Some((counter as u64, frequency as u64))
}

/// Unix epoch nanoseconds from the wall clock, sampled next to a QPC read.
///
/// `GetSystemTimePreciseAsFileTime` returns a FILETIME by value (100-ns ticks
/// since 1601-01-01). The `windows` 0.57 binding writes into its own local and
/// returns it, so there is no pointer for us to pass.
pub fn read_wall_unix_ns() -> Option<i64> {
    use windows::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
    // SAFETY: the binding allocates the FILETIME itself and returns it. The
    // call has no out-pointer of ours to invalidate.
    let ft = unsafe { GetSystemTimePreciseAsFileTime() };
    let ticks = (i64::from(ft.dwHighDateTime) << 32) | i64::from(ft.dwLowDateTime);
    super::session::filetime_to_unix_ns(ticks)
}

fn query_properties() -> EVENT_TRACE_PROPERTIES {
    // `Default` for this windows-rs struct is `mem::zeroed()`, which is the
    // documented starting point for a QUERY/STOP buffer. BufferSize must cover
    // the struct itself or ControlTraceW rejects it.
    let mut properties = EVENT_TRACE_PROPERTIES::default();
    properties.Wnode.BufferSize = u32::try_from(size_of::<EVENT_TRACE_PROPERTIES>()).unwrap_or(0);
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties
}

fn wide_name(name: &str) -> Result<U16CString, SessionError> {
    U16CString::from_str(name)
        .map_err(|_| SessionError::Config(super::session::ConfigError::BadBootId))
}

fn win32_code(status: windows::Win32::Foundation::WIN32_ERROR) -> i32 {
    if status == ERROR_SUCCESS {
        0
    } else {
        status.0 as i32
    }
}

/// ferrisetw's `TraceError` to our error, without the inner debug payload.
pub fn from_trace_error(op: &'static str, err: &TraceError) -> SessionError {
    match err {
        TraceError::InvalidTraceName => {
            SessionError::Config(super::session::ConfigError::BadBootId)
        }
        TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist) => {
            SessionError::AlreadyExists
        }
        TraceError::EtwNativeError(EvntraceNativeError::InvalidHandle) => SessionError::Etw {
            op,
            code: 6, // ERROR_INVALID_HANDLE
        },
        TraceError::EtwNativeError(EvntraceNativeError::IoError(io)) => {
            let code = io.raw_os_error().unwrap_or(0);
            SessionError::from_win32(op, code)
        }
    }
}
