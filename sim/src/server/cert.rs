//! In-memory self-signed certificate for the localhost HTTPS listener.
//!
//! PEM is written only under the directory the caller passed as `--cert-out`.
//! Nothing here touches the Windows certificate store, `certutil`, or
//! `SSL_CERT_FILE`.

use std::net::Ipv4Addr;
use std::path::Path;

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};

pub struct Material {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

pub fn generate() -> Result<Material, String> {
    let key = KeyPair::generate().map_err(|err| err.to_string())?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|err| err.to_string())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            Ipv4Addr::LOCALHOST,
        )));
    // An empty EKU is not serverAuth. webpki rejects the handshake without it.
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let cert = params.self_signed(&key).map_err(|err| err.to_string())?;
    Ok(Material {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().as_ref().to_vec(),
        key_der: key.serialize_der(),
    })
}

pub fn write_pem(dir: &Path, material: &Material) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &material.cert_pem)
        .map_err(|err| format!("{}: {err}", cert_path.display()))?;
    std::fs::write(&key_path, &material.key_pem)
        .map_err(|err| format!("{}: {err}", key_path.display()))?;
    Ok(())
}
