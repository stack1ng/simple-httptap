//! An authority kept as one PEM file in its folder, signing each host's certificate with rcgen.
//!
//! The file, the root and its key, is written once, atomically, and never replaced. Each process makes
//! one key for its host certificates and keeps each host's certificate while it runs.

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::sync::Mutex;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
};
use simple_httptap_authority::{Authority, Issued, Signer};
use time::{Duration, OffsetDateTime};

/// The keeper of authorities in folders.
#[derive(Debug, Default)]
pub struct RcgenAuthority;

/// An opened authority with this process's host key and its cache of host certificates.
pub struct RcgenSigner {
    root: String,
    issuer: Issuer<'static, KeyPair>,
    host_key: KeyPair,
    /// Where host certificates say their revocation is checked, on Windows only.
    revocation_list: Option<String>,
    issued: Mutex<HashMap<String, Issued>>,
}

impl Authority for RcgenAuthority {
    type Signer = RcgenSigner;

    fn open(&self, folder: &Path) -> std::io::Result<RcgenSigner> {
        std::fs::create_dir_all(folder)?;
        let file = folder.join(AUTHORITY_FILE);
        let kept = match std::fs::read_to_string(&file) {
            Ok(kept) => kept,
            Err(fault) if fault.kind() == ErrorKind::NotFound => make_authority(folder, &file)?,
            Err(fault) => return Err(fault),
        };
        let (root, key) = split_authority(&kept)?;
        let key = KeyPair::from_pem(key).map_err(std::io::Error::other)?;
        let issuer = Issuer::from_ca_cert_pem(root, key).map_err(std::io::Error::other)?;
        let host_key = KeyPair::generate().map_err(std::io::Error::other)?;
        let revocation_list = serve_revocation_list(&issuer)?;
        Ok(RcgenSigner { root: root.to_owned(), issuer, host_key, revocation_list, issued: Mutex::default() })
    }
}

impl Signer for RcgenSigner {
    fn root_certificate(&self) -> String {
        self.root.clone()
    }

    fn issue_certificate(&self, host: &str) -> std::io::Result<Issued> {
        let mut issued = self.issued.lock().map_err(|_| std::io::Error::other("a poisoned certificate cache"))?;
        if let Some(kept) = issued.get(host) {
            return Ok(kept.clone());
        }
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(std::io::Error::other)?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = OffsetDateTime::now_utc() - Duration::DAY;
        params.not_after = params.not_before + Duration::days(HOST_CERTIFICATE_DAYS);
        if let Some(url) = &self.revocation_list {
            params.crl_distribution_points = vec![CrlDistributionPoint { uris: vec![url.clone()] }];
        }
        let certificate = params.signed_by(&self.host_key, &self.issuer).map_err(std::io::Error::other)?;
        let made = Issued {
            chain: vec![certificate.der().to_vec(), pem_contents(&self.root)?],
            private_key: self.host_key.serialize_der(),
        };
        issued.insert(host.to_owned(), made.clone());
        Ok(made)
    }
}

/// The file in the folder that holds the root certificate and then its private key, both in PEM.
const AUTHORITY_FILE: &str = "authority.pem";
/// The loopback URL whose port and path the revocation list is served at.
const LOOPBACK_URL: &str = "http://127.0.0.1/";
/// The path of the root's empty revocation list.
const REVOCATION_LIST_PATH: &str = "/revoked.crl";
/// The response head before the list's length.
const RESPONSE_HEAD_START: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nConnection: close\r\nContent-Length: ";
/// The response head after the list's length.
const RESPONSE_HEAD_END: &str = "\r\n\r\n";
/// The name the root certificate gives itself, which is what the trust store shows.
const AUTHORITY_NAME: &str = "simple-httptap";
/// The longest validity Apple's systems accept for a TLS server certificate, which every host certificate gets.
///
/// https://support.apple.com/en-us/103769
const HOST_CERTIFICATE_DAYS: i64 = 825;
/// The line that starts a PEM private key.
const PRIVATE_KEY_START: &str = "-----BEGIN PRIVATE KEY-----";

/// Makes a new authority and writes it to the file, unless another process wrote one first; returns the file's text.
fn make_authority(folder: &Path, file: &Path) -> std::io::Result<String> {
    let key = KeyPair::generate().map_err(std::io::Error::other)?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(std::io::Error::other)?;
    params.distinguished_name.push(DnType::CommonName, AUTHORITY_NAME);
    params.distinguished_name.push(DnType::OrganizationName, AUTHORITY_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let certificate = params.self_signed(&key).map_err(std::io::Error::other)?;
    let text = format!("{}{}", certificate.pem(), key.serialize_pem());
    let mut temporary = tempfile::NamedTempFile::new_in(folder)?;
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(file) {
        Ok(_) => Ok(text),
        Err(fault) if fault.error.kind() == ErrorKind::AlreadyExists => std::fs::read_to_string(file),
        Err(fault) => Err(fault.error),
    }
}

/// Serves an empty revocation list the root signs over HTTP on a loopback port and returns its URL, on Windows only.
///
/// Windows clients such as curl.exe refuse a host certificate whose revocation they cannot check, and
/// fetch revocation lists only over HTTP or LDAP. The list lives as long as the process, as its
/// host certificates do.
fn serve_revocation_list(issuer: &Issuer<'static, KeyPair>) -> std::io::Result<Option<String>> {
    if !cfg!(windows) {
        return Ok(None);
    }
    let now = OffsetDateTime::now_utc();
    let params = CertificateRevocationListParams {
        this_update: now - Duration::DAY,
        next_update: now + Duration::days(HOST_CERTIFICATE_DAYS),
        crl_number: SerialNumber::from(u64::try_from(now.unix_timestamp()).unwrap_or(u64::MIN)),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let list = params.signed_by(issuer).map_err(std::io::Error::other)?.der().to_vec();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, u16::MIN))?;
    let mut url = url::Url::parse(LOOPBACK_URL).map_err(std::io::Error::other)?;
    url.set_port(Some(listener.local_addr()?.port())).map_err(|()| std::io::Error::other(LOOPBACK_URL))?;
    url.set_path(REVOCATION_LIST_PATH);
    let length = list.len();
    let mut response = format!("{RESPONSE_HEAD_START}{length}{RESPONSE_HEAD_END}").into_bytes();
    response.extend(list);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = answer_with(stream, &response);
        }
    });
    Ok(Some(url.to_string()))
}

/// Reads a request's head off the stream and writes the response, whatever the request asked for.
fn answer_with(stream: std::net::TcpStream, response: &[u8]) -> std::io::Result<()> {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    while reader.read_line(&mut line)? != usize::MIN && !line.trim().is_empty() {
        line.clear();
    }
    let mut stream = stream;
    stream.write_all(response)
}

/// Splits the file's text into the root certificate's PEM and the private key's PEM.
fn split_authority(text: &str) -> std::io::Result<(&str, &str)> {
    let start = text
        .find(PRIVATE_KEY_START)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "the authority file has no private key"))?;
    Ok(text.split_at(start))
}

/// Returns the DER inside one PEM block.
fn pem_contents(pem: &str) -> std::io::Result<Vec<u8>> {
    pem::parse(pem).map(pem::Pem::into_contents).map_err(|fault| std::io::Error::new(ErrorKind::InvalidData, fault))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;

    #[test]
    fn issues_chains_a_tls_client_accepts_with_the_root_trusted() {
        let folder = tempfile::tempdir().expect("a temporary folder");
        let authority = RcgenAuthority.open(folder.path()).expect("the authority opens");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(pem_contents(&authority.root_certificate()).expect("the root's DER"))).expect("the root is a trust anchor");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().expect("a verifier");
        for host in ["localhost", "127.0.0.1", "::1"] {
            let issued = authority.issue_certificate(host).expect("a certificate");
            let (leaf, rest) = issued.chain.split_first().expect("a host certificate");
            let rest: Vec<CertificateDer> = rest.iter().map(|der| CertificateDer::from(der.as_slice())).collect();
            let name = ServerName::try_from(host).expect("a server name");
            verifier
                .verify_server_cert(&CertificateDer::from(leaf.as_slice()), &rest, &name, &[], UnixTime::now())
                .expect("the host certificate verifies");
        }
    }
}
