//! Embeds the notarized httptap.app, zipped, when `HTTPTAP_REDIRECTOR_APP_ZIP` names one, so httptap can install it.

/// The variable naming the zipped app to embed.
const APP_ZIP_VARIABLE: &str = "HTTPTAP_REDIRECTOR_APP_ZIP";
/// The instruction declaring the embedded-app cfg, so an unset one raises no warning.
///
/// https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-check-cfg
const DECLARE_EMBEDDED_FLAG: &str = "cargo::rustc-check-cfg=cfg(httptap_embedded_app)";
/// The instruction that lets the crate include the copied app.
///
/// https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-cfg
const SET_EMBEDDED_FLAG: &str = "cargo::rustc-cfg=httptap_embedded_app";
/// The instruction prefix that reruns this script when a variable changes.
///
/// https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-env-changed
const RERUN_IF_ENV_CHANGED: &str = "cargo::rerun-if-env-changed=";
/// The instruction prefix that reruns this script when a file changes.
///
/// https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed
const RERUN_IF_CHANGED: &str = "cargo::rerun-if-changed=";
/// The variable naming the folder this script copies the app into.
///
/// https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
const OUT_DIR_VARIABLE: &str = "OUT_DIR";
/// The copied app's name there, which the crate includes.
const COPIED_ZIP: &str = "httptap-app.zip";
/// The tool and flag that print one file of a zip archive to standard output.
///
/// https://linux.die.net/man/1/unzip
const UNZIP_TO_STDOUT: [&str; 2] = ["unzip", "-p"];
/// The zipped app's information property list, which the crate compares with the installed app's.
const ZIPPED_INFO_PLIST: &str = "httptap.app/Contents/Info.plist";
/// The name the property list is unpacked to, beside the copied app.
const UNPACKED_INFO_PLIST: &str = "Info.plist";

fn main() {
    println!("{DECLARE_EMBEDDED_FLAG}");
    println!("{RERUN_IF_ENV_CHANGED}{APP_ZIP_VARIABLE}");
    let Some(zip) = std::env::var_os(APP_ZIP_VARIABLE).filter(|value| !value.is_empty()) else {
        return;
    };
    println!("{RERUN_IF_CHANGED}{}", std::path::Path::new(&zip).display());
    let out = std::path::PathBuf::from(std::env::var_os(OUT_DIR_VARIABLE).expect("cargo sets the output folder"));
    std::fs::copy(&zip, out.join(COPIED_ZIP)).expect("the zipped app can be copied");
    let [unzip, to_stdout] = UNZIP_TO_STDOUT;
    let plist = std::process::Command::new(unzip).arg(to_stdout).arg(&zip).arg(ZIPPED_INFO_PLIST).output().expect("unzip runs");
    assert!(plist.status.success() && !plist.stdout.is_empty(), "the zipped app has an information property list");
    std::fs::write(out.join(UNPACKED_INFO_PLIST), plist.stdout).expect("the property list can be written");
    println!("{SET_EMBEDDED_FLAG}");
}
