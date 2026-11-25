//! The tests every implementation of simple-httptap-trust runs, written against its traits alone.
//!
//! None of them changes the store: a test that trusted a certificate would change the machine it runs on.

use simple_httptap_trust::Trust;

/// Text that is no PEM certificate.
const NOT_A_CERTIFICATE: &str = "not a certificate";

/// Checks that text that is no certificate is refused before the store is touched.
pub fn refuses_what_is_no_certificate<T: Trust>(store: T) {
    assert!(store.add_trusted_root(NOT_A_CERTIFICATE).is_err());
}

/// Runs each suite function above as its own test on a value made anew for every test.
///
/// List every suite function here, in the order above, and nothing else.
#[macro_export]
macro_rules! tests {
    ($value:expr) => {
        #[test]
        fn refuses_what_is_no_certificate() {
            $crate::refuses_what_is_no_certificate($value);
        }
    };
}
