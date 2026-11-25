//! Embeds the notarized httptap.app, zipped, when `HTTPTAP_REDIRECTOR_APP_ZIP` names one, so httptap can install it.

/// The variable naming the zipped app to embed.
const APP_ZIP_VARIABLE: &str = "HTTPTAP_REDIRECTOR_APP_ZIP";
/// The configuration flag that says the app is embedded.
const EMBEDDED_FLAG: &str = "httptap_embedded_app";

fn main() {
    println!("cargo::rustc-check-cfg=cfg({EMBEDDED_FLAG})");
    println!("cargo::rerun-if-env-changed={APP_ZIP_VARIABLE}");
    let Some(zip) = std::env::var_os(APP_ZIP_VARIABLE).filter(|value| !value.is_empty()) else { return };
    println!("cargo::rerun-if-changed={}", std::path::Path::new(&zip).display());
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::copy(&zip, out.join("httptap-app.zip")).expect("the zipped app can be copied");
    println!("cargo::rustc-cfg={EMBEDDED_FLAG}");
}
