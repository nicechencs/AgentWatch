//! Session CA lifecycle (P3-PROXY-01, security-privacy §5).
//!
//! One ECDSA P-256 CA, 90 days, `pathlen:0`. The private key stays in the
//! daemon: [`CaInfo`] and every `Debug` impl print the SHA-256 fingerprint of
//! the certificate, never the key. Leaf certificates last 7 days and live in
//! an in-memory LRU of 1024. They are not written to disk.
//!
//! A CA inside the rotation window (7 days before `not_after`) is replaced on
//! the next [`CaStore::ensure`]. The previous CA keeps signing for sessions
//! that already hold it, until those sessions end and [`CaStore::retire_if_idle`]
//! deletes it.

mod protect;

use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use protect::{
    platform_protector, KeyProtector, ProtectedKey, UnixFileProtector, WindowsDpapiPlaceholder,
};

const CA_LIFETIME_SECS: i64 = 90 * 24 * 60 * 60;
const LEAF_LIFETIME_SECS: i64 = 7 * 24 * 60 * 60;
const ROTATE_BEFORE_SECS: i64 = 7 * 24 * 60 * 60;
const LEAF_CACHE_CAP: usize = 1024;
const KEY_FILE: &str = "ca.key";
const CERT_FILE: &str = "ca.crt";
const META_FILE: &str = "ca.meta";

/// SHA-256 of the certificate DER, lowercase hex. Safe to log and to return.
#[derive(Clone, PartialEq, Eq)]
pub struct Fingerprint(String);

impl Fingerprint {
    fn of_der(der: &[u8]) -> Self {
        let digest = Sha256::digest(der);
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            hex.push_str(&format!("{byte:02x}"));
        }
        Self(hex)
    }

    /// Lowercase hex. Not a secret.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What `aw proxy ca-info` and `GET /api/v1/proxy/ca` may show.
///
/// No private key, no PKCS#8, no PEM of the key. `protected` is `false` on the
/// Windows placeholder, with `unprotected_reason` saying why.
#[derive(Clone, PartialEq, Eq)]
pub struct CaInfo {
    /// SHA-256 of the active CA certificate DER.
    pub fingerprint: Fingerprint,
    /// Unix seconds. `None` is not used: a CA always has both times.
    pub not_before_unix: i64,
    /// Unix seconds.
    pub not_after_unix: i64,
    /// True when the stored key bytes are encrypted. The Windows placeholder is false.
    pub protected: bool,
    /// Set when `protected` is false.
    pub unprotected_reason: Option<String>,
    /// How many sessions still use a CA that is no longer the active one.
    pub retired_in_use: u32,
}

impl fmt::Debug for CaInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaInfo")
            .field("fingerprint", &self.fingerprint)
            .field("not_before_unix", &self.not_before_unix)
            .field("not_after_unix", &self.not_after_unix)
            .field("protected", &self.protected)
            .field("unprotected_reason", &self.unprotected_reason)
            .field("retired_in_use", &self.retired_in_use)
            .finish()
    }
}

/// PKCS#8 of one CA. Dropped with [`Zeroizing`]. `Debug` prints the fingerprint.
struct CaKey {
    fingerprint: Fingerprint,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for CaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaKey")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

struct LoadedCa {
    key: CaKey,
    /// PEM of the certificate only.
    cert_pem: String,
    /// Issuer object rcgen needs to sign a leaf. Not serializable; rebuilt only
    /// at mint time. After [`CaStore::load`] this is `None`, and leaf issuance
    /// fails until the next rotation mints a fresh in-memory CA.
    issuer: Option<Certificate>,
    not_before_unix: i64,
    not_after_unix: i64,
    /// Sessions that received material from this CA and have not ended.
    sessions: u32,
}

impl fmt::Debug for LoadedCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedCa")
            .field("fingerprint", &self.key.fingerprint)
            .field("not_before_unix", &self.not_before_unix)
            .field("not_after_unix", &self.not_after_unix)
            .field("sessions", &self.sessions)
            .finish()
    }
}

struct LeafEntry {
    dns: String,
    cert_pem: String,
    /// Leaf private key, PKCS#8 DER. Stays in memory so the MITM listener can
    /// terminate TLS. Never written to disk and never printed.
    pkcs8: Zeroizing<Vec<u8>>,
    expires_unix: i64,
}

/// One CA directory plus the leaf cache.
///
/// `clock` is Unix seconds. Callers pass it so expiry does not read the host
/// clock except when generating a brand-new CA (the generation time is part of
/// the certificate, and the caller supplies that instant too).
pub struct CaStore<P: KeyProtector> {
    dir: PathBuf,
    protector: P,
    active: Option<LoadedCa>,
    /// Previous CAs that still have live sessions. Empty when none.
    retired: Vec<LoadedCa>,
    leaves: VecDeque<LeafEntry>,
}

impl<P: KeyProtector> fmt::Debug for CaStore<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprint = self.active.as_ref().map(|ca| &ca.key.fingerprint);
        f.debug_struct("CaStore")
            .field("fingerprint", &fingerprint)
            .field("retired", &self.retired.len())
            .field("leaves", &self.leaves.len())
            .finish()
    }
}

impl<P: KeyProtector> CaStore<P> {
    /// Empty store. Does not create a CA and does not touch the disk.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, protector: P) -> Self {
        Self {
            dir: dir.into(),
            protector,
            active: None,
            retired: Vec::new(),
            leaves: VecDeque::new(),
        }
    }

    /// Load `ca.key` and `ca.crt` if both exist. A missing pair is "no CA", not an error.
    ///
    /// # Errors
    ///
    /// The directory exists but the pair is unreadable, or the PEM is not a certificate.
    pub fn load(&mut self) -> Result<(), CaError> {
        let key_path = self.dir.join(KEY_FILE);
        let cert_path = self.dir.join(CERT_FILE);
        if !key_path.exists() && !cert_path.exists() {
            return Ok(());
        }
        let stored = fs::read(&key_path).map_err(|err| CaError::io("read ca.key", &err))?;
        let pkcs8 = self
            .protector
            .unprotect(&stored)
            .map_err(CaError::Protect)?;
        let cert_pem =
            fs::read_to_string(&cert_path).map_err(|err| CaError::io("read ca.crt", &err))?;
        let (not_before, not_after) = read_meta(&self.dir.join(META_FILE))?;
        let der = cert_der_from_pem(&cert_pem)?;
        // rcgen 0.13 cannot turn a stored PEM back into a `Certificate`.
        // `issuer` stays `None` until `ensure` / `rotate` mints a new CA in this
        // process. The key is still loaded so a later rotate can replace the files
        // and so drop wipes the bytes.
        self.active = Some(LoadedCa {
            key: CaKey {
                fingerprint: Fingerprint::of_der(&der),
                pkcs8,
            },
            cert_pem,
            issuer: None,
            not_before_unix: not_before,
            not_after_unix: not_after,
            sessions: 0,
        });
        Ok(())
    }

    /// Create a CA when there is none. Rotate when `now_unix` is inside the
    /// 7-day window. The current CA, if any session still holds it, moves to
    /// the retired list instead of being deleted.
    ///
    /// # Errors
    ///
    /// Generation or the write to `ca.key` / `ca.crt` failed.
    pub fn ensure(&mut self, now_unix: i64, host_tag: &str) -> Result<CaInfo, CaError> {
        let rotate = self
            .active
            .as_ref()
            .is_some_and(|ca| ca.not_after_unix.saturating_sub(now_unix) <= ROTATE_BEFORE_SECS);
        if self.active.is_none() || rotate {
            self.rotate(now_unix, host_tag, false)?;
        }
        self.info()
    }

    /// Mint a new CA. With `revoke_now`, every retired CA is dropped and the
    /// caller is expected to close proxy sessions. Without it, a CA that still
    /// has sessions stays available for those sessions.
    ///
    /// # Errors
    ///
    /// Generation or the disk write failed. The previous files are left in place
    /// only when the new pair could not be written; a successful write replaces them.
    pub fn rotate(
        &mut self,
        now_unix: i64,
        host_tag: &str,
        revoke_now: bool,
    ) -> Result<CaInfo, CaError> {
        let minted = mint_ca(now_unix, host_tag)?;
        if let Some(previous) = self.active.take() {
            if !revoke_now && previous.sessions > 0 {
                self.retired.push(previous);
            }
        }
        if revoke_now {
            self.retired.clear();
            self.leaves.clear();
        }
        self.write_active(&minted)?;
        self.active = Some(minted);
        self.info()
    }

    /// Public description. Errors when no CA has been created or loaded.
    ///
    /// # Errors
    ///
    /// [`CaError::Missing`].
    pub fn info(&self) -> Result<CaInfo, CaError> {
        let active = self.active.as_ref().ok_or(CaError::Missing)?;
        let reason = self.protector.unprotected_reason().map(str::to_owned);
        Ok(CaInfo {
            fingerprint: active.key.fingerprint.clone(),
            not_before_unix: active.not_before_unix,
            not_after_unix: active.not_after_unix,
            protected: self.protector.is_protected(),
            unprotected_reason: if self.protector.is_protected() {
                None
            } else {
                reason
            },
            retired_in_use: self
                .retired
                .iter()
                .map(|ca| ca.sessions)
                .fold(0u32, u32::saturating_add),
        })
    }

    /// Certificate PEM of the active CA. No key.
    ///
    /// # Errors
    ///
    /// [`CaError::Missing`].
    pub fn cert_pem(&self) -> Result<&str, CaError> {
        self.active
            .as_ref()
            .map(|ca| ca.cert_pem.as_str())
            .ok_or(CaError::Missing)
    }

    /// Note that `session` is using the active CA. Rotation will keep it until
    /// [`Self::release_session`].
    ///
    /// # Errors
    ///
    /// [`CaError::Missing`].
    pub fn acquire_session(&mut self) -> Result<Fingerprint, CaError> {
        let active = self.active.as_mut().ok_or(CaError::Missing)?;
        active.sessions = active.sessions.saturating_add(1);
        Ok(active.key.fingerprint.clone())
    }

    /// A session ended. A retired CA with no remaining sessions is dropped from
    /// memory. The on-disk files always belong to the active CA.
    pub fn release_session(&mut self, fingerprint: &Fingerprint) {
        if let Some(active) = self.active.as_mut() {
            if &active.key.fingerprint == fingerprint {
                active.sessions = active.sessions.saturating_sub(1);
                return;
            }
        }
        self.retired.retain_mut(|ca| {
            if &ca.key.fingerprint == fingerprint {
                ca.sessions = ca.sessions.saturating_sub(1);
            }
            ca.sessions > 0
        });
    }

    /// Delete retired CAs that no session holds. The active CA stays.
    pub fn retire_if_idle(&mut self) {
        self.retired.retain(|ca| ca.sessions > 0);
    }

    /// Issue or reuse a 7-day leaf for `dns_name`. Cached in memory, cap 1024.
    ///
    /// An expired cache entry is not reused. The name is not logged by this function.
    ///
    /// # Errors
    ///
    /// No CA, or the name is not a usable DNS label, or signing failed.
    pub fn leaf_for(&mut self, dns_name: &str, now_unix: i64) -> Result<LeafCert, CaError> {
        if dns_name.is_empty() || dns_name.contains(['/', '\\', ' ', '\n', '\r']) {
            return Err(CaError::BadName);
        }
        if let Some(hit) = self
            .leaves
            .iter()
            .find(|entry| entry.dns == dns_name && entry.expires_unix > now_unix)
        {
            return Ok(LeafCert {
                dns_name: hit.dns.clone(),
                cert_pem: hit.cert_pem.clone(),
                key_pkcs8: hit.pkcs8.clone(),
                expires_unix: hit.expires_unix,
            });
        }
        let active = self.active.as_ref().ok_or(CaError::Missing)?;
        let Some(issuer) = active.issuer.as_ref() else {
            return Err(CaError::Issue(
                "CA was loaded from disk; rcgen 0.13 cannot rebuild the issuer, so leaf signing waits for the next rotate".to_owned(),
            ));
        };
        let issued = issue_leaf(dns_name, now_unix, &active.key, issuer)?;
        self.leaves.retain(|entry| entry.expires_unix > now_unix);
        while self.leaves.len() >= LEAF_CACHE_CAP {
            self.leaves.pop_front();
        }
        self.leaves.push_back(LeafEntry {
            dns: issued.dns_name.clone(),
            cert_pem: issued.cert_pem.clone(),
            pkcs8: issued.key_pkcs8.clone(),
            expires_unix: issued.expires_unix,
        });
        Ok(issued)
    }

    /// Remove the CA directory. Does not touch a system or user trust store.
    ///
    /// # Errors
    ///
    /// The directory could not be removed. A missing directory is success.
    pub fn delete_dir(&mut self) -> Result<(), CaError> {
        self.active = None;
        self.retired.clear();
        self.leaves.clear();
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).map_err(|err| CaError::io("remove ca dir", &err))?;
        }
        Ok(())
    }

    fn write_active(&self, ca: &LoadedCa) -> Result<(), CaError> {
        fs::create_dir_all(&self.dir).map_err(|err| CaError::io("create ca dir", &err))?;
        let protected = self
            .protector
            .protect(ca.key.pkcs8.as_slice())
            .map_err(CaError::Protect)?;
        let key_path = self.dir.join(KEY_FILE);
        write_secret(&key_path, protected.as_bytes())?;
        fs::write(self.dir.join(CERT_FILE), ca.cert_pem.as_bytes())
            .map_err(|err| CaError::io("write ca.crt", &err))?;
        let meta = format!("{}\n{}\n", ca.not_before_unix, ca.not_after_unix);
        fs::write(self.dir.join(META_FILE), meta)
            .map_err(|err| CaError::io("write ca.meta", &err))?;
        Ok(())
    }
}

/// A leaf certificate plus the key that terminates TLS for it.
///
/// The key stays in memory and is never written to disk. [`Debug`] prints neither
/// the PEM nor the key, only the name length and the expiry.
#[derive(Clone, PartialEq, Eq)]
pub struct LeafCert {
    /// The DNS name it was issued for. Not printed by [`Debug`].
    pub dns_name: String,
    /// Certificate PEM. Public.
    pub cert_pem: String,
    /// Leaf private key, PKCS#8 DER. Not printed by [`Debug`].
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    /// Unix seconds.
    pub expires_unix: i64,
}

impl fmt::Debug for LeafCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeafCert")
            .field("dns_len", &self.dns_name.len())
            .field("expires_unix", &self.expires_unix)
            .finish()
    }
}

/// Write `<dir>/ca.pem` (this CA only) and `<dir>/bundle.pem`.
///
/// `bundle.pem` is the session CA certificate plus a comment that names how many
/// Mozilla roots [`webpki_roots::TLS_SERVER_ROOTS`] holds. webpki-roots 1.0
/// ships subject public keys, not full certificates, so those roots are not
/// written as `CERTIFICATE` blocks (a client would reject them). The private
/// key is in neither file.
///
/// `root_pem` is an optional extra PEM the caller already has (a system bundle).
/// `None` means this process did not read one. The file still gets the session CA.
///
/// The directory is created at `0o700` on Unix. This function does not delete it.
///
/// # Errors
///
/// A directory or file could not be created.
pub fn write_session_material(
    dir: &Path,
    ca_cert_pem: &str,
    root_pem: Option<&str>,
) -> Result<SessionMaterial, CaError> {
    fs::create_dir_all(dir).map_err(|err| CaError::io("create session ca dir", &err))?;
    #[cfg(unix)]
    set_dir_mode(dir, 0o700)?;
    let ca_pem = dir.join("ca.pem");
    let bundle_pem = dir.join("bundle.pem");
    fs::write(&ca_pem, ca_cert_pem.as_bytes()).map_err(|err| CaError::io("write ca.pem", &err))?;
    let mut bundle = String::new();
    if let Some(roots) = root_pem {
        bundle.push_str(roots);
        if !roots.ends_with('\n') {
            bundle.push('\n');
        }
    }
    bundle.push_str(ca_cert_pem);
    if !ca_cert_pem.ends_with('\n') {
        bundle.push('\n');
    }
    let root_count = webpki_roots::TLS_SERVER_ROOTS.len();
    bundle.push_str(&format!(
        "# webpki-roots {root_count} public keys are not certificates and are not inlined\n"
    ));
    fs::write(&bundle_pem, bundle.as_bytes())
        .map_err(|err| CaError::io("write bundle.pem", &err))?;
    Ok(SessionMaterial { ca_pem, bundle_pem })
}

/// Paths written for one session. Both are certificate material, not keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMaterial {
    /// `<session_tmp>/ca.pem`.
    pub ca_pem: PathBuf,
    /// `<session_tmp>/bundle.pem`.
    pub bundle_pem: PathBuf,
}

/// Delete a session directory created by [`write_session_material`].
///
/// Only `ca.pem` and `bundle.pem` are removed, then the directory if it is empty
/// of anything else. A path outside the caller's control is the caller's problem;
/// this does not follow symlinks on Unix (`remove_file` removes the link).
///
/// # Errors
///
/// A file that exists could not be removed.
pub fn remove_session_material(dir: &Path) -> Result<(), CaError> {
    for name in ["ca.pem", "bundle.pem"] {
        let path = dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(CaError::io("remove session pem", &err)),
        }
    }
    match fs::remove_dir(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        // Not empty: something else lives there. Leave it. Not an error.
        Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {}
        Err(err) => return Err(CaError::io("remove session dir", &err)),
    }
    Ok(())
}

/// Why a CA operation failed. Display text never includes key bytes.
#[derive(Debug)]
pub enum CaError {
    /// No CA has been generated or loaded.
    Missing,
    /// The DNS name is empty or contains a separator.
    BadName,
    /// rcgen refused the parameters.
    Issue(String),
    /// The protector failed. The string is the protector's message.
    Protect(String),
    /// A filesystem call failed. `action` is a fixed label, not a path.
    Io {
        action: &'static str,
        message: String,
    },
}

impl CaError {
    fn io(action: &'static str, err: &io::Error) -> Self {
        Self::Io {
            action,
            message: err.kind().to_string(),
        }
    }
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "no CA has been generated"),
            Self::BadName => write!(f, "leaf DNS name is empty or contains a separator"),
            Self::Issue(detail) => write!(f, "certificate issue failed: {detail}"),
            Self::Protect(detail) => write!(f, "key protect failed: {detail}"),
            Self::Io { action, message } => write!(f, "{action}: {message}"),
        }
    }
}

impl std::error::Error for CaError {}

fn mint_ca(now_unix: i64, host_tag: &str) -> Result<LoadedCa, CaError> {
    let not_before = unix_to_offset(now_unix)?;
    let not_after = unix_to_offset(now_unix.saturating_add(CA_LIFETIME_SECS))?;
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let mut name = DistinguishedName::new();
    let cn = format!("AgentWatch Local CA {host_tag}");
    name.push(DnType::CommonName, cn.as_str());
    params.distinguished_name = name;
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().map_err(|err| CaError::Issue(err.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|err| CaError::Issue(err.to_string()))?;
    let cert_pem = cert.pem();
    let pkcs8 = Zeroizing::new(key.serialize_der());
    let der = cert.der().as_ref().to_vec();
    Ok(LoadedCa {
        key: CaKey {
            fingerprint: Fingerprint::of_der(&der),
            pkcs8,
        },
        cert_pem,
        issuer: Some(cert),
        not_before_unix: now_unix,
        not_after_unix: now_unix.saturating_add(CA_LIFETIME_SECS),
        sessions: 0,
    })
}

fn issue_leaf(
    dns_name: &str,
    now_unix: i64,
    ca_key: &CaKey,
    issuer: &Certificate,
) -> Result<LeafCert, CaError> {
    let ia5 = dns_name.try_into().map_err(|_| CaError::BadName)?;
    let not_before = unix_to_offset(now_unix)?;
    let not_after = unix_to_offset(now_unix.saturating_add(LEAF_LIFETIME_SECS))?;
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::NoCa;
    params.subject_alt_names = vec![SanType::DnsName(ia5)];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, dns_name);
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;

    let leaf_key = KeyPair::generate().map_err(|err| CaError::Issue(err.to_string()))?;
    let ca_key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(ca_key.pkcs8.as_ref()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|err| CaError::Issue(err.to_string()))?;
    let leaf = params
        .signed_by(&leaf_key, issuer, &ca_key_pair)
        .map_err(|err| CaError::Issue(err.to_string()))?;
    // The key stays in memory so `server::mitm` can build a rustls ServerConfig.
    // It is zeroized on drop and is not part of the on-disk CA material.
    let key_pkcs8 = Zeroizing::new(leaf_key.serialize_der());
    Ok(LeafCert {
        dns_name: dns_name.to_owned(),
        cert_pem: leaf.pem(),
        key_pkcs8,
        expires_unix: now_unix.saturating_add(LEAF_LIFETIME_SECS),
    })
}

fn unix_to_offset(unix: i64) -> Result<time::OffsetDateTime, CaError> {
    time::OffsetDateTime::from_unix_timestamp(unix).map_err(|err| CaError::Issue(err.to_string()))
}

fn cert_der_from_pem(pem_text: &str) -> Result<Vec<u8>, CaError> {
    let parsed = ::pem::parse(pem_text).map_err(|err| CaError::Issue(err.to_string()))?;
    if parsed.tag() != "CERTIFICATE" {
        return Err(CaError::Issue(
            "ca.crt is not a CERTIFICATE block".to_owned(),
        ));
    }
    Ok(parsed.into_contents())
}

fn read_meta(path: &Path) -> Result<(i64, i64), CaError> {
    let text = fs::read_to_string(path).map_err(|err| CaError::io("read ca.meta", &err))?;
    let mut lines = text.lines();
    let before = lines
        .next()
        .and_then(|line| line.parse::<i64>().ok())
        .ok_or_else(|| CaError::Issue("ca.meta has no not_before".to_owned()))?;
    let after = lines
        .next()
        .and_then(|line| line.parse::<i64>().ok())
        .ok_or_else(|| CaError::Issue("ca.meta has no not_after".to_owned()))?;
    Ok((before, after))
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), CaError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| CaError::io("create ca.key", &err))?;
        file.write_all(bytes)
            .map_err(|err| CaError::io("write ca.key", &err))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes).map_err(|err| CaError::io("write ca.key", &err))
    }
}

#[cfg(unix)]
fn set_dir_mode(path: &Path, mode: u32) -> Result<(), CaError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms).map_err(|err| CaError::io("chmod session dir", &err))
}

/// Unix seconds for `SystemTime`. `None` when the clock is before the epoch.
#[must_use]
pub fn unix_now() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|dur| i64::try_from(dur.as_secs()).ok())
}
