//! Cross-platform discovery of the SecuGen shared library.
//!
//! Resolution order (first match wins):
//!   1. SECUGEN_LIB_PATH env var  — exact path to the library
//!   2. SECUGEN_DLL_PATH env var  — exact path (legacy alias, works everywhere)
//!   3. SECUGEN_SDK_PATH env var  — directory containing the library
//!   4. Sibling of the Node process executable (parity step; rarely matches)
//!   5. Platform default paths (system installs)
//!   6. Bare filename — handed to dlopen so the OS loader's own rules apply

use std::path::{Path, PathBuf};

use crate::fp_core::errors::FingerprintError;

/// Filename of the SecuGen shared library on this platform.
pub fn default_lib_filename() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "sgfplib.dll"
    }
    #[cfg(target_os = "macos")]
    {
        "libsgfplib.dylib"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "libsgfplib.so"
    }
}

fn platform_default_dirs() -> &'static [&'static str] {
    #[cfg(target_os = "windows")]
    {
        &[
            r"C:\SecuGen\SDK\FDx SDK Pro for Windows v4.3.1_J1.12\FDx SDK Pro for Java v1.12\jnisgfplib\win32",
            r"C:\Program Files\SecuGen\FDx SDK Pro for Windows\lib",
            r"C:\Program Files (x86)\SecuGen\FDx SDK Pro for Windows\lib",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &["/usr/local/lib", "/opt/homebrew/lib", "/opt/SecuGen/lib"]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        &["/usr/local/lib", "/usr/lib", "/opt/SecuGen/lib"]
    }
}

/// Lookup the library path. Returns the first candidate that exists on disk,
/// or — if none of the explicit candidates match — the bare filename so the
/// caller can hand it to `dlopen`/`LoadLibrary` and let the OS loader search.
pub fn find_library_path() -> Result<PathBuf, FingerprintError> {
    find_library_path_with_defaults(platform_default_dirs())
}

/// Internal seam taking the platform default dirs explicitly. Lets tests
/// bypass step 5 by passing an empty slice, so a real SecuGen SDK install
/// on the test host doesn't make assertions about the bare-filename
/// fallback impossible.
fn find_library_path_with_defaults(
    default_dirs: &[&str],
) -> Result<PathBuf, FingerprintError> {
    let filename = default_lib_filename();

    // 1. SECUGEN_LIB_PATH (preferred cross-platform)
    if let Some(p) = env_path("SECUGEN_LIB_PATH") {
        if p.exists() {
            return Ok(p);
        }
    }
    // 2. SECUGEN_DLL_PATH (legacy alias, honoured on all OSes)
    if let Some(p) = env_path("SECUGEN_DLL_PATH") {
        if p.exists() {
            return Ok(p);
        }
    }
    // 3. SECUGEN_SDK_PATH directory
    if let Some(dir) = env_path("SECUGEN_SDK_PATH") {
        let p = dir.join(filename);
        if p.exists() {
            return Ok(p);
        }
    }
    // 4. Sibling of Node executable (parity step)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(filename);
            if p.exists() {
                return Ok(p);
            }
        }
    }
    // 5. Platform default install paths
    for dir in default_dirs {
        let p = Path::new(dir).join(filename);
        if p.exists() {
            return Ok(p);
        }
    }
    // 6. Bare filename — let the OS loader search
    Ok(PathBuf::from(filename))
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Env var manipulation must be single-threaded inside the test binary.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_all() {
        for k in [
            "SECUGEN_LIB_PATH",
            "SECUGEN_DLL_PATH",
            "SECUGEN_SDK_PATH",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn lib_path_env_takes_precedence() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("SECUGEN_LIB_PATH", tmp.path());
        let resolved = find_library_path().unwrap();
        assert_eq!(resolved, tmp.path());
        clear_all();
    }

    #[test]
    fn dll_path_used_when_lib_path_missing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("SECUGEN_DLL_PATH", tmp.path());
        let resolved = find_library_path().unwrap();
        assert_eq!(resolved, tmp.path());
        clear_all();
    }

    #[test]
    fn sdk_path_appends_default_filename() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all();
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join(default_lib_filename());
        std::fs::write(&lib, b"").unwrap();
        std::env::set_var("SECUGEN_SDK_PATH", dir.path());
        let resolved = find_library_path().unwrap();
        assert_eq!(resolved, lib);
        clear_all();
    }

    #[test]
    fn falls_back_to_bare_filename_when_nothing_matches() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all();
        // Empty default-dirs list bypasses step 5 so the host's real SecuGen
        // install (if any) doesn't pre-empt the bare-filename fallback.
        let empty = tempfile::tempdir().unwrap();
        std::env::set_var("SECUGEN_SDK_PATH", empty.path());
        let resolved = find_library_path_with_defaults(&[]).unwrap();
        assert_eq!(resolved, PathBuf::from(default_lib_filename()));
        clear_all();
    }

    #[test]
    fn nonexistent_lib_path_does_not_short_circuit() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_all();
        std::env::set_var("SECUGEN_LIB_PATH", "/no/such/path/nope.so");
        let resolved = find_library_path_with_defaults(&[]).unwrap();
        assert_eq!(resolved, PathBuf::from(default_lib_filename()));
        clear_all();
    }
}
