use semver::Version;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn current_version() -> Version {
    Version::parse(CURRENT_VERSION).expect("CARGO_PKG_VERSION is not valid semver")
}

pub const DEFAULT_OWNER: &str = "TrulyNimz";
pub const DEFAULT_REPO: &str = "Rust-Fingerprint-Library";

/// Hex-encoded Ed25519 verifying key (32 bytes → 64 hex chars), embedded at
/// build time via the FINGERPRINT_UPDATE_PUBKEY env var. When unset, the
/// updater refuses to apply updates unless `--allow-unsigned` is passed.
pub const UPDATE_PUBKEY_HEX: Option<&str> = option_env!("FINGERPRINT_UPDATE_PUBKEY");

pub fn asset_zip_name(version: &str) -> String {
    format!("fingerprint-sdk-v{version}-win32-x64.zip")
}

pub fn asset_checksum_name(version: &str) -> String {
    format!("fingerprint-sdk-v{version}-win32-x64.sha256")
}

pub fn asset_signature_name(version: &str) -> String {
    format!("fingerprint-sdk-v{version}-win32-x64.sig")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_names_follow_release_convention() {
        assert_eq!(asset_zip_name("0.1.0"), "fingerprint-sdk-v0.1.0-win32-x64.zip");
        assert_eq!(
            asset_checksum_name("0.1.0"),
            "fingerprint-sdk-v0.1.0-win32-x64.sha256"
        );
        assert_eq!(
            asset_signature_name("0.1.0"),
            "fingerprint-sdk-v0.1.0-win32-x64.sig"
        );
    }

    #[test]
    fn asset_names_handle_prerelease_versions() {
        assert_eq!(
            asset_zip_name("1.2.3-beta.4"),
            "fingerprint-sdk-v1.2.3-beta.4-win32-x64.zip"
        );
        assert_eq!(
            asset_signature_name("1.2.3-beta.4"),
            "fingerprint-sdk-v1.2.3-beta.4-win32-x64.sig"
        );
    }

    #[test]
    fn current_version_parses_as_semver() {
        // CARGO_PKG_VERSION should always be valid semver; this guards against
        // accidentally setting it to something like "0.1" or a non-numeric tag.
        let _v = current_version();
    }
}
