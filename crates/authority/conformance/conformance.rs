//! The tests every implementation of simple-httptap-authority runs, written against its traits alone.

use simple_httptap_authority::{Authority, Signer};

/// The armor line RFC 7468 puts before a certificate's base64.
///
/// https://www.rfc-editor.org/rfc/rfc7468#section-5.1
const PEM_CERTIFICATE_START: &str = "-----BEGIN CERTIFICATE-----";
/// One DNS name, one IPv4 address and one IPv6 address.
const HOSTS: &[&str] = &["example.com", "127.0.0.1", "::1"];

/// Opens the authority in a new temporary folder, which it keeps.
fn open_in_new_folder<T: Authority>(authority: &T) -> T::Signer {
    let folder = tempfile::tempdir().expect("a temporary folder").keep();
    authority.open(&folder).expect("the authority opens")
}

/// Checks that the root certificate is a PEM certificate.
pub fn gives_its_root_in_pem<T: Authority>(authority: T) {
    assert!(open_in_new_folder(&authority).root_certificate().starts_with(PEM_CERTIFICATE_START));
}

/// Checks that DNS names and IP addresses each get a chain longer than one certificate, and a key.
pub fn issues_certificates_for_names_and_addresses<T: Authority>(authority: T) {
    let signer = open_in_new_folder(&authority);
    for host in HOSTS.iter().copied() {
        let issued = signer.issue_certificate(host).expect("the authority issues for the host");
        assert!(issued.chain.len() > 1, "the chain has the host's certificate and the root");
        assert!(!issued.private_key.is_empty());
    }
}

/// Checks that opening a folder a second time gives the root the first opening made.
pub fn opens_the_same_authority_from_one_folder<T: Authority>(authority: T) {
    let folder = tempfile::tempdir().expect("a temporary folder");
    let first = authority.open(folder.path()).expect("the authority is made");
    let second = authority.open(folder.path()).expect("the authority is opened again");
    assert_eq!(first.root_certificate(), second.root_certificate());
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn gives_its_root_in_pem() {
            $crate::gives_its_root_in_pem($value);
        }

        #[test]
        fn issues_certificates_for_names_and_addresses() {
            $crate::issues_certificates_for_names_and_addresses($value);
        }

        #[test]
        fn opens_the_same_authority_from_one_folder() {
            $crate::opens_the_same_authority_from_one_folder($value);
        }
    };
}
