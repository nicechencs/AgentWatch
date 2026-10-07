//! Where the CLI sends requests, and which credential (if any) it presents.
//!
//! api-and-cli §1 lists two CLI transports and one UI transport:
//!
//! 1. Unix socket `/run/agentwatch/api.sock` (Linux) or `/var/run/agentwatch/api.sock`
//!    (macOS). The peer's uid is the credential; there is no bearer token.
//! 2. Named pipe `\\.\pipe\agentwatch-api` (Windows). The client's SID is the
//!    credential; there is no bearer token.
//! 3. Loopback HTTP `127.0.0.1:<port>` (default 7456) is the Web UI channel. It
//!    requires `Authorization: Bearer <ui_token>`. The CLI uses it only when the
//!    user passes `--http`.
//!
//! Resolution order for the address:
//!
//! 1. `--socket PATH` selects the socket or pipe and wins over `--http`.
//! 2. Otherwise `--http URL` selects loopback HTTP.
//! 3. Otherwise the platform default socket or pipe is used. That path is a
//!    documented constant, not a probed port. A missing socket is exit 3 at
//!    request time, not a silent success.
//!
//! Resolution order for the bearer token, and only when the address is HTTP:
//!
//! 1. `--token`.
//! 2. `AW_TOKEN`.
//! 3. Neither is present: [`EndpointError::MissingToken`]. An empty string is
//!    the same as missing. The socket and pipe transports do not read a token.
//!
//! Nothing here dials. [`crate::client`] owns the exchange.

use std::env;
use std::fmt;
use std::path::PathBuf;

/// Default UI listen port from api-and-cli §1. Used only to recognise the
/// documented URL; this crate never binds it.
#[allow(dead_code)]
pub const DEFAULT_HTTP_PORT: u16 = 7456;

/// Linux CLI socket (api-and-cli §1).
#[allow(dead_code)]
pub const LINUX_SOCKET: &str = "/run/agentwatch/api.sock";

/// macOS CLI socket (api-and-cli §1).
#[allow(dead_code)]
pub const MACOS_SOCKET: &str = "/var/run/agentwatch/api.sock";

/// Windows CLI named pipe (api-and-cli §1).
pub const WINDOWS_PIPE: &str = r"\\.\pipe\agentwatch-api";

/// Environment variable read when `--token` is absent on an HTTP address.
pub const TOKEN_ENV: &str = "AW_TOKEN";

/// Why an address or token could not be resolved. The token text is never stored here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    /// `--http` was set but the URL is not loopback HTTP.
    BadHttpUrl { detail: String },
    /// HTTP was selected and neither `--token` nor `AW_TOKEN` held a token.
    MissingToken,
    /// This operating system has no documented CLI socket or pipe.
    NoPlatformDefault,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHttpUrl { detail } => write!(f, "refusing HTTP address: {detail}"),
            Self::MissingToken => write!(
                f,
                "HTTP transport requires a bearer token; pass --token or set {TOKEN_ENV}. An empty token is not a credential"
            ),
            Self::NoPlatformDefault => {
                write!(f, "no default CLI socket or named pipe on this operating system; pass --socket or --http")
            }
        }
    }
}

impl std::error::Error for EndpointError {}

/// A resolved daemon address plus the credential the transport should present.
///
/// Not `Debug`: `token` is a bearer secret. [`fmt::Display`] prints the address
/// and, for HTTP, the token length and last four characters.
#[derive(Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Unix socket. Authenticated by peer uid, not a bearer token.
    Unix { path: PathBuf },
    /// Windows named pipe. Authenticated by the client SID, not a bearer token.
    Pipe { path: PathBuf },
    /// Loopback HTTP. `token` is the bearer value without the `Bearer ` prefix.
    Http { base: HttpBase, token: String },
}

/// Loopback origin the HTTP transport may dial. Non-loopback URLs never construct this.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpBase {
    /// `127.0.0.1` or `localhost`.
    pub host: String,
    /// Port from the URL. Never `0`: an absent or zero port is an error.
    pub port: u16,
}

impl HttpBase {
    /// `http://<host>:<port>` with no trailing slash.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// `Host` header the daemon stub accepts: `127.0.0.1:<port>` or `localhost:<port>`.
    #[must_use]
    pub fn host_header(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix { path } => write!(f, "unix socket {}", path.display()),
            Self::Pipe { path } => write!(f, "named pipe {}", path.display()),
            Self::Http { base, token } => {
                write!(f, "http {} (token {})", base.origin(), token_hint(token))
            }
        }
    }
}

/// What the user passed. Empty strings are treated as absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointInput {
    /// `--socket`.
    pub socket: Option<String>,
    /// `--http`.
    pub http: Option<String>,
    /// `--token`.
    pub token: Option<String>,
    /// Value of [`TOKEN_ENV`], already read by the caller (tests inject this).
    pub token_env: Option<String>,
}

impl EndpointInput {
    /// Read `AW_TOKEN` from the process environment. Does not log the value.
    #[must_use]
    pub fn from_args(socket: Option<String>, http: Option<String>, token: Option<String>) -> Self {
        Self {
            socket: blank_to_none(socket),
            http: blank_to_none(http),
            token: blank_to_none(token),
            token_env: blank_to_none(env::var(TOKEN_ENV).ok()),
        }
    }
}

/// Resolve [`EndpointInput`] into an [`Endpoint`].
///
/// # Errors
///
/// [`EndpointError::BadHttpUrl`] when `--http` is not a loopback `http://` URL
/// with a non-zero port. [`EndpointError::MissingToken`] when that URL was
/// selected and no token was provided. [`EndpointError::NoPlatformDefault`]
/// when neither flag was set and this OS has no documented CLI socket.
pub fn resolve(input: &EndpointInput) -> Result<Endpoint, EndpointError> {
    if let Some(path) = blank_to_none(input.socket.clone()) {
        return Ok(classify_socket_path(path));
    }
    if let Some(url) = blank_to_none(input.http.clone()) {
        let base = parse_loopback_http(&url)?;
        let token = match bearer_from(input) {
            Some(token) => token,
            None => return Err(EndpointError::MissingToken),
        };
        return Ok(Endpoint::Http { base, token });
    }
    match platform_default() {
        Some(endpoint) => Ok(endpoint),
        None => Err(EndpointError::NoPlatformDefault),
    }
}

fn bearer_from(input: &EndpointInput) -> Option<String> {
    blank_to_none(input.token.clone()).or_else(|| blank_to_none(input.token_env.clone()))
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

/// A user-supplied path. Windows pipe prefixes stay pipes; everything else is a socket.
fn classify_socket_path(path: String) -> Endpoint {
    if path.starts_with(r"\\.\pipe\") || path.starts_with(r"\\?\pipe\") {
        Endpoint::Pipe {
            path: PathBuf::from(path),
        }
    } else {
        Endpoint::Unix {
            path: PathBuf::from(path),
        }
    }
}

fn platform_default() -> Option<Endpoint> {
    #[cfg(target_os = "linux")]
    {
        Some(Endpoint::Unix {
            path: PathBuf::from(LINUX_SOCKET),
        })
    }
    #[cfg(target_os = "macos")]
    {
        Some(Endpoint::Unix {
            path: PathBuf::from(MACOS_SOCKET),
        })
    }
    #[cfg(target_os = "windows")]
    {
        Some(Endpoint::Pipe {
            path: PathBuf::from(WINDOWS_PIPE),
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Accept only `http://127.0.0.1:<port>` and `http://localhost:<port>`.
///
/// `https`, a path, a query, a userinfo, a non-loopback host, an omitted port,
/// and port `0` are refused. Port `0` would ask the OS for an ephemeral port,
/// which is not "the daemon".
fn parse_loopback_http(raw: &str) -> Result<HttpBase, EndpointError> {
    let Some(rest) = raw.strip_prefix("http://") else {
        return Err(EndpointError::BadHttpUrl {
            detail: "only http://127.0.0.1:<port> or http://localhost:<port> is accepted"
                .to_owned(),
        });
    };
    if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return Err(EndpointError::BadHttpUrl {
            detail: "the URL must be an origin with no path, query, or userinfo".to_owned(),
        });
    }
    let (host, port_text) = split_host_port(rest)?;
    if !is_loopback_host(host) {
        return Err(EndpointError::BadHttpUrl {
            detail: "host must be 127.0.0.1 or localhost; other hosts are refused".to_owned(),
        });
    }
    let port: u16 = port_text.parse().map_err(|_| EndpointError::BadHttpUrl {
        detail: format!("port `{port_text}` is not a number"),
    })?;
    if port == 0 {
        return Err(EndpointError::BadHttpUrl {
            detail: "port 0 is not a daemon address".to_owned(),
        });
    }
    Ok(HttpBase {
        host: host.to_owned(),
        port,
    })
}

fn split_host_port(origin: &str) -> Result<(&str, &str), EndpointError> {
    match origin.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => Ok((host, port)),
        _ => Err(EndpointError::BadHttpUrl {
            detail: "a non-zero port is required; there is no default HTTP port on this flag"
                .to_owned(),
        }),
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("127.0.0.1") || host.eq_ignore_ascii_case("localhost")
}

/// Length and last four characters. Short tokens show the length only.
#[must_use]
pub fn token_hint(token: &str) -> String {
    let len = token.chars().count();
    let tail: String = token
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if len > 4 {
        format!("len={len} …{tail}")
    } else if len == 0 {
        "len=0".to_owned()
    } else {
        format!("len={len}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        parse_loopback_http, resolve, token_hint, Endpoint, EndpointError, EndpointInput,
        DEFAULT_HTTP_PORT,
    };

    fn input(
        socket: Option<&str>,
        http: Option<&str>,
        token: Option<&str>,
        env: Option<&str>,
    ) -> EndpointInput {
        EndpointInput {
            socket: socket.map(str::to_owned),
            http: http.map(str::to_owned),
            token: token.map(str::to_owned),
            token_env: env.map(str::to_owned),
        }
    }

    #[test]
    fn socket_flag_wins_over_http_and_needs_no_token() {
        let endpoint = resolve(&input(
            Some("/tmp/aw.sock"),
            Some("http://127.0.0.1:7456"),
            None,
            None,
        ))
        .expect("socket");
        match endpoint {
            Endpoint::Unix { path } => assert_eq!(path.as_os_str(), "/tmp/aw.sock"),
            other => panic!("expected unix, got {other}"),
        }
    }

    #[test]
    fn http_without_token_is_an_error_and_names_no_secret() {
        let err = match resolve(&input(
            None,
            Some("http://127.0.0.1:7456"),
            None,
            Some("  "),
        )) {
            Ok(_) => panic!("expected missing token"),
            Err(err) => err,
        };
        assert_eq!(err, EndpointError::MissingToken);
        let text = err.to_string();
        assert!(!text.contains("7456") || text.contains("AW_TOKEN"));
        assert!(!text.contains("secret"));
    }

    #[test]
    fn http_token_flag_beats_env_and_display_hides_the_body() {
        let endpoint = resolve(&input(
            None,
            Some("http://localhost:7456"),
            Some("flag-secret-value"),
            Some("env-secret-value"),
        ))
        .expect("http");
        let shown = endpoint.to_string();
        assert!(shown.contains("http://localhost:7456"), "{shown}");
        assert!(!shown.contains("flag-secret-value"), "{shown}");
        assert!(!shown.contains("env-secret-value"), "{shown}");
        assert!(shown.contains("len=17"), "{shown}");
        assert!(shown.contains("alue"), "{shown}");
        match endpoint {
            Endpoint::Http { token, .. } => assert_eq!(token, "flag-secret-value"),
            other => panic!("expected http, got {other}"),
        }
    }

    #[test]
    fn http_falls_back_to_env_token() {
        let endpoint = resolve(&input(
            None,
            Some("http://127.0.0.1:9"),
            None,
            Some("env-token-xyz"),
        ))
        .expect("env");
        match endpoint {
            Endpoint::Http { base, token } => {
                assert_eq!(base.port, 9);
                assert_eq!(token, "env-token-xyz");
            }
            other => panic!("expected http, got {other}"),
        }
    }

    #[test]
    fn zero_port_and_foreign_host_are_refused() {
        assert!(parse_loopback_http("http://127.0.0.1:0").is_err());
        assert!(parse_loopback_http("http://evil.com:7456").is_err());
        assert!(parse_loopback_http("http://127.0.0.1").is_err());
        assert!(parse_loopback_http("https://127.0.0.1:7456").is_err());
        let ok = parse_loopback_http("http://127.0.0.1:7456").expect("ok");
        assert_eq!(ok.port, DEFAULT_HTTP_PORT);
    }

    #[test]
    fn token_hint_never_returns_the_whole_token() {
        let hint = token_hint("abcdefghij");
        assert_eq!(hint, "len=10 …ghij");
        assert!(!hint.contains("abcdefghij"));
        assert_eq!(token_hint("ab"), "len=2");
        assert_eq!(token_hint(""), "len=0");
    }

    #[test]
    fn windows_pipe_prefix_is_a_pipe() {
        let endpoint = resolve(&input(Some(r"\\.\pipe\custom"), None, None, None)).expect("pipe");
        assert!(matches!(endpoint, Endpoint::Pipe { .. }));
    }

    #[test]
    fn platform_default_is_not_a_zero_port() {
        let endpoint = resolve(&input(None, None, None, None)).expect("default");
        let shown = endpoint.to_string();
        assert!(!shown.contains(":0"), "{shown}");
        assert!(!shown.contains("token"), "{shown}");
    }
}
