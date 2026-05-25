use semver::Version;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn current_version() -> Version {
    Version::parse(CURRENT_VERSION).expect("CARGO_PKG_VERSION is not valid semver")
}

pub const DEFAULT_OWNER: &str = "TrulyNimz";
pub const DEFAULT_REPO: &str = "Rust-Fingerprint-Library";

pub fn asset_zip_name(version: &str) -> String {
    format!("fingerprint-sdk-v{version}-win32-x64.zip")
}

pub fn asset_checksum_name(version: &str) -> String {
    format!("fingerprint-sdk-v{version}-win32-x64.sha256")
}
