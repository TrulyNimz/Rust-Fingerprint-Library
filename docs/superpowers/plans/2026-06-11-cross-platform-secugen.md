# Cross-platform SecuGen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `initScanner('secugen')` work on Linux and macOS by adding a direct-FFI backend that dlopens `libsgfplib.so` / `libsgfplib.dylib`, while preserving the unchanged Windows IPC bridge and the zero-runtime-npm-deps guarantee.

**Architecture:** Split `sdk/src/vendors/secugen/` into two backends behind one `SecuGenScanner` facade — `bridge.rs` (Windows IPC client, extracted from today's `mod.rs`) and `native.rs` (new, dlopens the 64-bit vendor library directly via `libc::dlopen`). Three new helper files (`ffi_types.rs`, `error_map.rs`, `library_path.rs`) hold the platform-agnostic types, SDK→`FingerprintError` mapping, and discovery logic. Drive-by fixes: cross-platform `SECUGEN_LIB_PATH` env var and a `JoinError`-aware panic handler at the napi async boundary.

**Tech Stack:** Rust 2021, napi-rs 2.x, `libc 0.2` (gated to `cfg(not(windows))`), existing `thiserror`/`serde`/`tokio` toolchain. No new vendor crates. No `libloading`.

**Spec:** [`docs/superpowers/specs/2026-06-11-cross-platform-secugen-design.md`](../specs/2026-06-11-cross-platform-secugen-design.md)

---

## File Structure

**Create:**
- `sdk/src/vendors/secugen/ffi_types.rs` — C struct layouts, function-pointer aliases, SDK error code constants. Platform-agnostic (C ABI is identical across OSes for SecuGen).
- `sdk/src/vendors/secugen/error_map.rs` — `map_sdk_code(code: c_long) -> FingerprintError`. Table-driven, unit-testable, shared by `bridge.rs` and `native.rs`.
- `sdk/src/vendors/secugen/library_path.rs` — `find_library_path() -> Result<PathBuf, FingerprintError>` with the env-var + system-paths search order. Unit-testable in isolation.
- `sdk/src/vendors/secugen/bridge.rs` (`#[cfg(windows)]`) — IPC client extracted from current `mod.rs`. Same behaviour.
- `sdk/src/vendors/secugen/native.rs` (`#[cfg(not(windows))]`) — `NativeClient`: dlopens the library, resolves symbols, implements the operations the bridge does today.

**Modify:**
- `sdk/Cargo.toml` — add `[target.'cfg(not(windows))'.dependencies] libc = "0.2"`.
- `sdk/src/vendors/secugen/mod.rs` — slim to a `SecuGenScanner` facade that owns `Mutex<Option<Backend>>` (a cfg-gated enum) and dispatches `FingerprintScanner` calls.
- `sdk/src/vendors/mod.rs` — `auto` resolves to `SecuGenScanner::new()` on non-Windows.
- `sdk/src/lib.rs` — replace `.await.unwrap()` on `JoinHandle`s with `.await.map_err(|e| join_err_to_fingerprint(e))?` for clean panic surfacing.
- `bridge/src/main.rs` — `find_dll_path()` honours `SECUGEN_LIB_PATH` first, then `SECUGEN_DLL_PATH`, then `SECUGEN_SDK_PATH`, then the existing fallback chain.
- `README.md` — Linux/macOS rows in the support table, new setup subsections, build steps for both platforms, env var documentation.

---

## Task 1: Scaffold shared FFI types

**Files:**
- Create: `sdk/src/vendors/secugen/ffi_types.rs`
- Modify: `sdk/Cargo.toml`
- Modify: `sdk/src/vendors/secugen/mod.rs:1` (add `pub mod ffi_types;` at top)

- [ ] **Step 1: Add libc dep gated to non-Windows targets**

Append to `sdk/Cargo.toml` (after the closing `]` of `[build-dependencies]`):

```toml

[target.'cfg(not(windows))'.dependencies]
libc = "0.2"
```

- [ ] **Step 2: Create the shared FFI types file**

Create `sdk/src/vendors/secugen/ffi_types.rs`:

```rust
//! Cross-platform C ABI definitions for SecuGen SGFPLIB.
//!
//! These struct layouts and function-pointer aliases mirror the vendor's
//! header file and are identical across Windows (64-bit), Linux, and macOS.
//! `extern "system"` collapses to `extern "C"` everywhere except 32-bit Windows,
//! so the same type aliases work for the 32-bit bridge AND the 64-bit
//! Linux/macOS direct-FFI client.

#![allow(dead_code)] // bridge.rs / native.rs each use a subset

use std::os::raw::{c_int, c_long, c_uchar, c_void};

pub type HSGFPM = *mut c_void;

// ─── SDK error codes (subset we map explicitly) ───────────────────────────

pub const SGFDX_ERROR_NONE: c_long = 0;
pub const SGFDX_ERROR_DLLLOAD_FAILED_DRV: c_long = 6;
pub const SGFDX_ERROR_TIME_OUT: c_long = 54;
pub const SGFDX_ERROR_DEVICE_NOT_FOUND: c_long = 55;

// ─── Device constants ─────────────────────────────────────────────────────

pub const SG_DEV_AUTO: c_long = 0xFF;
pub const SG_SECURITY_NORMAL: c_long = 5;

// ─── C struct layouts (must match SDK headers exactly) ────────────────────

#[repr(C)]
#[derive(Debug, Default)]
pub struct SGDeviceInfoParam {
    pub device_id: c_long,
    pub device_sn: [c_uchar; 16],
    pub com_port: c_long,
    pub com_speed: c_long,
    pub image_width: c_long,
    pub image_height: c_long,
    pub contrast: c_long,
    pub brightness: c_long,
    pub gain: c_long,
    pub image_dpi: c_long,
    pub fw_version: c_long,
}

#[repr(C)]
#[derive(Debug)]
pub struct SGFingerInfo {
    pub finger_number: c_long,
    pub view_number: c_long,
    pub impression_type: c_long,
    pub image_quality: c_long,
}

impl Default for SGFingerInfo {
    fn default() -> Self {
        Self {
            finger_number: 0,
            view_number: 0,
            impression_type: 0,
            image_quality: 0,
        }
    }
}

// ─── Function-pointer aliases ─────────────────────────────────────────────

pub type FnCreate = unsafe extern "system" fn(*mut HSGFPM) -> c_long;
pub type FnTerminate = unsafe extern "system" fn(HSGFPM) -> c_long;
pub type FnInit = unsafe extern "system" fn(HSGFPM, c_long) -> c_long;
pub type FnOpenDevice = unsafe extern "system" fn(HSGFPM, c_int) -> c_long;
pub type FnCloseDevice = unsafe extern "system" fn(HSGFPM) -> c_long;
pub type FnGetDeviceInfo = unsafe extern "system" fn(HSGFPM, *mut SGDeviceInfoParam) -> c_long;
pub type FnGetImageEx =
    unsafe extern "system" fn(HSGFPM, *mut c_uchar, c_long, *mut c_void, c_long) -> c_long;
pub type FnGetImageQuality =
    unsafe extern "system" fn(HSGFPM, c_long, c_long, *const c_uchar, *mut c_long) -> c_long;
pub type FnCreateTemplate =
    unsafe extern "system" fn(HSGFPM, *const SGFingerInfo, *const c_uchar, *mut c_uchar) -> c_long;
pub type FnGetMaxTemplateSize = unsafe extern "system" fn(HSGFPM, *mut c_long) -> c_long;
pub type FnMatchTemplate = unsafe extern "system" fn(
    HSGFPM,
    *const c_uchar,
    *const c_uchar,
    c_long,
    *mut c_int,
) -> c_long;
pub type FnGetMatchingScore =
    unsafe extern "system" fn(HSGFPM, *const c_uchar, *const c_uchar, *mut c_long) -> c_long;
```

- [ ] **Step 3: Register the module in mod.rs**

Edit `sdk/src/vendors/secugen/mod.rs`. Replace the first non-blank line (`pub mod constants;`) with:

```rust
pub mod constants;
mod ffi_types;
```

(Leave the rest of the file alone for now.)

- [ ] **Step 4: Verify it compiles on Windows**

Run: `cargo check -p fingerprint-sdk`
Expected: `Finished` with zero errors/warnings beyond pre-existing ones.

- [ ] **Step 5: Commit**

```bash
git add sdk/Cargo.toml sdk/src/vendors/secugen/ffi_types.rs sdk/src/vendors/secugen/mod.rs
git commit -m "secugen: scaffold cross-platform FFI types module"
```

---

## Task 2: Table-driven SDK error mapping

**Files:**
- Create: `sdk/src/vendors/secugen/error_map.rs`
- Modify: `sdk/src/vendors/secugen/mod.rs:2` (add `mod error_map;`)

- [ ] **Step 1: Write the failing test**

Create `sdk/src/vendors/secugen/error_map.rs`:

```rust
//! Maps SecuGen SGFPLIB return codes to the public `FingerprintError`.
//! Shared by the Windows bridge wrapper and the Linux/macOS native client.

use std::os::raw::c_long;

use crate::fp_core::errors::FingerprintError;

use super::ffi_types::{
    SGFDX_ERROR_DEVICE_NOT_FOUND, SGFDX_ERROR_DLLLOAD_FAILED_DRV, SGFDX_ERROR_TIME_OUT,
};

/// Convert a raw SGFPLIB error code (returned by SGFPM_* calls) into a
/// `FingerprintError`. Returns `None` if the code is success (0).
pub fn map_sdk_code(code: c_long, default_timeout_ms: u32) -> FingerprintError {
    match code {
        SGFDX_ERROR_DEVICE_NOT_FOUND => FingerprintError::DeviceNotFound,
        SGFDX_ERROR_TIME_OUT => FingerprintError::CaptureTimeout(default_timeout_ms),
        SGFDX_ERROR_DLLLOAD_FAILED_DRV => FingerprintError::SdkError(
            "Driver library load failed (sgfdu*.dll / sgfdu*.so missing or wrong directory)"
                .to_string(),
        ),
        other => FingerprintError::SdkError(format!("SGFPLIB error code: {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_not_found_maps_correctly() {
        match map_sdk_code(SGFDX_ERROR_DEVICE_NOT_FOUND, 10_000) {
            FingerprintError::DeviceNotFound => {}
            other => panic!("expected DeviceNotFound, got {:?}", other),
        }
    }

    #[test]
    fn timeout_includes_requested_ms() {
        match map_sdk_code(SGFDX_ERROR_TIME_OUT, 7500) {
            FingerprintError::CaptureTimeout(ms) => assert_eq!(ms, 7500),
            other => panic!("expected CaptureTimeout(7500), got {:?}", other),
        }
    }

    #[test]
    fn dll_load_failure_is_sdk_error_with_hint() {
        match map_sdk_code(SGFDX_ERROR_DLLLOAD_FAILED_DRV, 10_000) {
            FingerprintError::SdkError(msg) => {
                assert!(msg.contains("Driver library load failed"));
            }
            other => panic!("expected SdkError, got {:?}", other),
        }
    }

    #[test]
    fn unknown_code_is_sdk_error_with_numeric_code() {
        match map_sdk_code(999, 10_000) {
            FingerprintError::SdkError(msg) => assert!(msg.contains("999")),
            other => panic!("expected SdkError(999), got {:?}", other),
        }
    }
}
```

- [ ] **Step 2: Register the module**

Edit `sdk/src/vendors/secugen/mod.rs`. The top should now look like:

```rust
pub mod constants;
mod error_map;
mod ffi_types;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p fingerprint-sdk --lib vendors::secugen::error_map`
Expected: `running 4 tests` → all pass. (If you hit OS error 740/4551 on Windows due to the napi-rs cdylib UAC issue, see `memory/windows_test_binary_uac.md` — run from an elevated shell or use `cargo test -p fingerprint-protocol` patterns. The error-map tests have no FFI so they should compile and run fine; the UAC issue is at .node load time, not unit test time.)

- [ ] **Step 4: Verify the SDK as a whole still compiles**

Run: `cargo check -p fingerprint-sdk`
Expected: `Finished` clean.

- [ ] **Step 5: Commit**

```bash
git add sdk/src/vendors/secugen/error_map.rs sdk/src/vendors/secugen/mod.rs
git commit -m "secugen: table-driven SDK error code mapping with unit tests"
```

---

## Task 3: Cross-platform library path discovery

**Files:**
- Create: `sdk/src/vendors/secugen/library_path.rs`
- Modify: `sdk/src/vendors/secugen/mod.rs:2` (add `mod library_path;`)

- [ ] **Step 1: Write the file with tests**

Create `sdk/src/vendors/secugen/library_path.rs`:

```rust
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
        &["/usr/local/lib", "/opt/SecuGen/lib"]
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
    for dir in platform_default_dirs() {
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
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("SECUGEN_LIB_PATH", tmp.path());
        let resolved = find_library_path().unwrap();
        assert_eq!(resolved, tmp.path());
        clear_all();
    }

    #[test]
    fn dll_path_used_when_lib_path_missing() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("SECUGEN_DLL_PATH", tmp.path());
        let resolved = find_library_path().unwrap();
        assert_eq!(resolved, tmp.path());
        clear_all();
    }

    #[test]
    fn sdk_path_appends_default_filename() {
        let _g = ENV_LOCK.lock().unwrap();
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
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        // Point SDK_PATH at a directory with no library so step 3 misses.
        let empty = tempfile::tempdir().unwrap();
        std::env::set_var("SECUGEN_SDK_PATH", empty.path());
        let resolved = find_library_path().unwrap();
        // Final fallback is the bare filename (caller hands it to dlopen).
        assert_eq!(resolved, PathBuf::from(default_lib_filename()));
        clear_all();
    }

    #[test]
    fn nonexistent_lib_path_does_not_short_circuit() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_all();
        std::env::set_var("SECUGEN_LIB_PATH", "/no/such/path/nope.so");
        // Should fall through past step 1 since the file doesn't exist.
        let resolved = find_library_path().unwrap();
        assert_eq!(resolved, PathBuf::from(default_lib_filename()));
        clear_all();
    }
}
```

- [ ] **Step 2: Add tempfile as a dev-dependency**

Append to `sdk/Cargo.toml` (after the `[target.'cfg(not(windows))'.dependencies]` block):

```toml

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Register the module**

`sdk/src/vendors/secugen/mod.rs` top should now read:

```rust
pub mod constants;
mod error_map;
mod ffi_types;
mod library_path;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p fingerprint-sdk --lib vendors::secugen::library_path`
Expected: `running 5 tests` → all pass.

- [ ] **Step 5: Commit**

```bash
git add sdk/Cargo.toml sdk/src/vendors/secugen/library_path.rs sdk/src/vendors/secugen/mod.rs
git commit -m "secugen: cross-platform library path discovery with unit tests"
```

---

## Task 4: Extract Windows IPC client into bridge.rs

**Files:**
- Create: `sdk/src/vendors/secugen/bridge.rs`
- Modify: `sdk/src/vendors/secugen/mod.rs` (replace IPC client code with `mod bridge;` + delegation)

This is a pure refactor — behaviour must remain identical. The existing `SecuGenScanner` becomes the public facade in `mod.rs`; the IPC plumbing moves to `bridge.rs` as a `BridgeBackend` struct that owns the child process and exposes `init`/`capture`/`enroll`/etc. methods returning `Result<T, FingerprintError>`.

- [ ] **Step 1: Create `bridge.rs` with the extracted IPC client**

Create `sdk/src/vendors/secugen/bridge.rs`:

```rust
//! Windows backend for SecuGen: spawns the 32-bit `secugen-bridge.exe` child
//! process and speaks the JSON line protocol over stdin/stdout. This is the
//! existing behaviour, refactored out of `mod.rs` so it can sit beside the
//! Linux/macOS direct-FFI backend without cfg-spaghetti in the facade.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};

use fingerprint_protocol::{BridgeCommand, BridgeResponse, ResponseData, TemplateEntry};
use zeroize::Zeroize;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

use super::constants::DEFAULT_ENROLL_SAMPLES;

/// Mirror of bridge/src/main.rs::MAX_IPC_LINE. Caps inbound payloads so a
/// corrupted/runaway bridge response can't OOM the host process.
const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

pub struct BridgeBackend {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

impl BridgeBackend {
    pub fn spawn() -> Result<Self, FingerprintError> {
        let exe_path = find_bridge_exe()?;
        let mut child = Command::new(&exe_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                FingerprintError::SdkError(format!("Failed to start bridge process: {}", e))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            FingerprintError::SdkError("Failed to capture bridge stdout".to_string())
        })?;

        Ok(Self {
            child,
            reader: BufReader::new(stdout),
        })
    }

    pub fn init(&mut self) -> Result<DeviceInfo, FingerprintError> {
        match self.send(&mut BridgeCommand::Init)? {
            ResponseData::DeviceInfo {
                vendor,
                model,
                serial,
                firmware,
                image_width,
                image_height,
                dpi,
            } => Ok(DeviceInfo {
                vendor,
                model,
                serial,
                firmware,
                image_width,
                image_height,
                dpi,
            }),
            _ => Err(unexpected()),
        }
    }

    pub fn capture(
        &mut self,
        timeout_ms: u32,
        min_quality: u8,
    ) -> Result<ScanResult, FingerprintError> {
        match self.send(&mut BridgeCommand::Capture {
            timeout_ms,
            min_quality,
        })? {
            ResponseData::ScanResult {
                image,
                quality,
                template,
                timestamp,
            } => Ok(ScanResult {
                image,
                quality,
                template,
                timestamp,
            }),
            _ => Err(unexpected()),
        }
    }

    pub fn enroll(&mut self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        let samples = if samples == 0 {
            DEFAULT_ENROLL_SAMPLES
        } else {
            samples
        };
        match self.send(&mut BridgeCommand::Enroll {
            user_id: user_id.to_string(),
            samples,
        })? {
            ResponseData::Template {
                user_id,
                data,
                created_at,
            } => Ok(Template {
                user_id,
                data,
                created_at,
            }),
            _ => Err(unexpected()),
        }
    }

    pub fn verify(
        &mut self,
        user_id: &str,
        template: &Template,
    ) -> Result<MatchResult, FingerprintError> {
        match self.send(&mut BridgeCommand::Verify {
            user_id: user_id.to_string(),
            template_data: template.data.clone(),
        })? {
            ResponseData::MatchResult {
                matched,
                score,
                user_id,
            } => Ok(MatchResult {
                matched,
                score,
                user_id,
            }),
            _ => Err(unexpected()),
        }
    }

    pub fn identify(&mut self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        let entries: Vec<TemplateEntry> = templates
            .iter()
            .map(|t| TemplateEntry {
                user_id: t.user_id.clone(),
                data: t.data.clone(),
            })
            .collect();

        match self.send(&mut BridgeCommand::Identify { templates: entries })? {
            ResponseData::MatchResult {
                matched,
                score,
                user_id,
            } => Ok(MatchResult {
                matched,
                score,
                user_id,
            }),
            _ => Err(unexpected()),
        }
    }

    pub fn get_quality(&mut self, image: &[u8]) -> Result<u8, FingerprintError> {
        match self.send(&mut BridgeCommand::GetQuality {
            image: image.to_vec(),
        })? {
            ResponseData::Quality { score } => Ok(score),
            _ => Err(unexpected()),
        }
    }

    pub fn shutdown(mut self) {
        let _ = self.send(&mut BridgeCommand::Disconnect);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn send(&mut self, cmd: &mut BridgeCommand) -> Result<ResponseData, FingerprintError> {
        let result = self.send_inner(cmd);
        // Wipe biometric bytes carried by the command after send completes,
        // covering every early-return path inside send_inner.
        match cmd {
            BridgeCommand::Verify { template_data, .. } => template_data.zeroize(),
            BridgeCommand::Identify { templates } => {
                for t in templates.iter_mut() {
                    t.data.zeroize();
                }
            }
            BridgeCommand::GetQuality { image } => image.zeroize(),
            _ => {}
        }
        result
    }

    fn send_inner(&mut self, cmd: &BridgeCommand) -> Result<ResponseData, FingerprintError> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| FingerprintError::SdkError("Bridge stdin not available".to_string()))?;

        let mut json = serde_json::to_string(cmd).map_err(|e| {
            FingerprintError::SdkError(format!("Failed to serialize command: {}", e))
        })?;

        let write_res = writeln!(stdin, "{}", json);
        json.zeroize();
        write_res.map_err(|e| {
            FingerprintError::SdkError(format!("Failed to write to bridge: {}", e))
        })?;

        stdin.flush().map_err(|e| {
            FingerprintError::SdkError(format!("Failed to flush bridge stdin: {}", e))
        })?;

        let mut line = String::new();
        let n = self
            .reader
            .by_ref()
            .take(MAX_IPC_LINE as u64)
            .read_line(&mut line)
            .map_err(|e| {
                FingerprintError::SdkError(format!("Failed to read bridge response: {}", e))
            })?;
        if n == MAX_IPC_LINE && !line.ends_with('\n') {
            line.zeroize();
            return Err(FingerprintError::SdkError(format!(
                "Bridge response exceeds {} bytes (framing error)",
                MAX_IPC_LINE
            )));
        }

        if line.trim().is_empty() {
            line.zeroize();
            return Err(FingerprintError::SdkError(
                "Bridge process returned empty response (may have crashed)".to_string(),
            ));
        }

        let parse_res = serde_json::from_str::<BridgeResponse>(line.trim());
        line.zeroize();
        let response = parse_res.map_err(|e| {
            FingerprintError::SdkError(format!("Failed to parse bridge response: {}", e))
        })?;

        match response {
            BridgeResponse::Ok { data } => Ok(data),
            BridgeResponse::Error { code, message } => Err(match code.as_str() {
                "DEVICE_NOT_FOUND" => FingerprintError::DeviceNotFound,
                "CAPTURE_TIMEOUT" => {
                    FingerprintError::SdkError(format!("[CAPTURE_TIMEOUT] {}", message))
                }
                "LOW_QUALITY" => FingerprintError::SdkError(format!("[LOW_QUALITY] {}", message)),
                "MATCH_FAILED" => FingerprintError::MatchFailed,
                "NOT_INITIALIZED" => FingerprintError::NotInitialized,
                "UNSUPPORTED_VENDOR" => FingerprintError::UnsupportedVendor(message),
                _ => FingerprintError::SdkError(format!("[{}] {}", code, message)),
            }),
        }
    }
}

fn unexpected() -> FingerprintError {
    FingerprintError::SdkError("Unexpected response from bridge".to_string())
}

fn find_bridge_exe() -> Result<String, FingerprintError> {
    const BRIDGE_NAME: &str = "secugen-bridge.exe";

    if let Ok(path) = std::env::var("SECUGEN_BRIDGE_PATH") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }
    if let Some(dir) = module_dir() {
        let bridge = dir.join(BRIDGE_NAME);
        if bridge.exists() {
            return Ok(bridge.to_string_lossy().to_string());
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let bridge = dir.join(BRIDGE_NAME);
            if bridge.exists() {
                return Ok(bridge.to_string_lossy().to_string());
            }
        }
    }

    Err(FingerprintError::SdkError(
        "secugen-bridge.exe not found. Set SECUGEN_BRIDGE_PATH or place it next to the .node file.".to_string(),
    ))
}

/// Returns the directory containing this .node DLL (Windows-only helper).
fn module_dir() -> Option<std::path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x00000004;
    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x00000002;

    extern "system" {
        fn GetModuleHandleExW(
            dwFlags: u32,
            lpModuleName: *const u16,
            phModule: *mut isize,
        ) -> i32;
        fn GetModuleFileNameW(hModule: isize, lpFilename: *mut u16, nSize: u32) -> u32;
    }

    unsafe {
        let mut h_module: isize = 0;
        let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        let ret = GetModuleHandleExW(flags, module_dir as *const () as *const u16, &mut h_module);
        if ret == 0 {
            return None;
        }

        let mut buf = vec![0u16; 512];
        let len = GetModuleFileNameW(h_module, buf.as_mut_ptr(), buf.len() as u32);
        if len == 0 || len >= buf.len() as u32 {
            return None;
        }

        let path = std::path::PathBuf::from(OsString::from_wide(&buf[..len as usize]));
        path.parent().map(|p| p.to_path_buf())
    }
}
```

- [ ] **Step 2: Replace `sdk/src/vendors/secugen/mod.rs` with the new facade**

Overwrite `sdk/src/vendors/secugen/mod.rs` with:

```rust
pub mod constants;
mod error_map;
mod ffi_types;
mod library_path;

#[cfg(windows)]
mod bridge;

use std::sync::Mutex;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

#[cfg(windows)]
use self::bridge::BridgeBackend;

pub struct SecuGenScanner {
    backend: Mutex<Option<Backend>>,
}

enum Backend {
    #[cfg(windows)]
    Bridge(BridgeBackend),
}

impl SecuGenScanner {
    pub fn new() -> Self {
        Self {
            backend: Mutex::new(None),
        }
    }

    fn with_backend<F, T>(&self, f: F) -> Result<T, FingerprintError>
    where
        F: FnOnce(&mut Backend) -> Result<T, FingerprintError>,
    {
        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = guard.as_mut().ok_or(FingerprintError::NotInitialized)?;
        f(backend)
    }
}

impl FingerprintScanner for SecuGenScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        #[cfg(windows)]
        {
            let mut backend = BridgeBackend::spawn()?;
            let info = backend.init()?;
            *self.backend.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Backend::Bridge(backend));
            Ok(info)
        }
        #[cfg(not(windows))]
        {
            Err(FingerprintError::SdkError(
                "SecuGen native backend not yet wired up (see Task 6)".to_string(),
            ))
        }
    }

    fn capture(&self, timeout_ms: u32, min_quality: u8) -> Result<ScanResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.capture(timeout_ms, min_quality),
        })
    }

    fn enroll(&self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.enroll(user_id, samples),
        })
    }

    fn verify(&self, user_id: &str, template: &Template) -> Result<MatchResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.verify(user_id, template),
        })
    }

    fn identify(&self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.identify(templates),
        })
    }

    fn get_quality(&self, image: &[u8]) -> Result<u8, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.get_quality(image),
        })
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(backend) = guard.take() {
            match backend {
                #[cfg(windows)]
                Backend::Bridge(br) => br.shutdown(),
            }
        }
        Ok(())
    }
}

impl Drop for SecuGenScanner {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
```

Note: on non-Windows the `match b` arms have no variants today; this is a deliberate compile-time check that we wire the native backend in Task 6 before the code is shippable on Linux/macOS. The non-Windows arm currently returns a clear `SdkError` at `init()` time so anyone running on those platforms gets a useful message until Task 6 lands.

- [ ] **Step 3: Verify the Windows build still compiles**

Run: `cargo check -p fingerprint-sdk`
Expected: `Finished` clean.

- [ ] **Step 4: Verify runtime parity (Windows, hardware required)**

Rebuild the bridge (no source changes but it picks up the env-var change later; for now nothing changed):

Run: `cargo build --target i686-pc-windows-msvc --release -p secugen-bridge`
Then init test:
`SECUGEN_DLL_PATH="C:\SecuGen\SDK\FDx SDK Pro for Windows v4.3.1_J1.12\FDx SDK Pro for Java v1.12\jnisgfplib\win32\sgfplib.dll" echo '{"action":"init"}' | target/i686-pc-windows-msvc/release/secugen-bridge.exe`
Expected: JSON `{"status":"ok","data":{"type":"device_info","vendor":"SecuGen",...}}` — bridge binary unchanged so this should match prior run.

(SDK-side functional test requires rebuilding the napi addon and running `npx ts-node examples/quick_test.ts`. Defer to Task 9 verification block.)

- [ ] **Step 5: Commit**

```bash
git add sdk/src/vendors/secugen/bridge.rs sdk/src/vendors/secugen/mod.rs
git commit -m "secugen: extract Windows IPC client into bridge.rs backend"
```

---

## Task 5: Direct-FFI client for Linux/macOS

**Files:**
- Create: `sdk/src/vendors/secugen/native.rs`
- Modify: `sdk/src/vendors/secugen/mod.rs` (add `#[cfg(not(windows))] mod native;`)

The native client mirrors the bridge's logic flow but runs in-process. It owns a `LoadedLib` (raw `dlopen` handle plus resolved function pointers) and an `SGFPM` handle. `disconnect()` closes the device, terminates the handle, and `dlclose`s the library.

- [ ] **Step 1: Create the native backend file**

Create `sdk/src/vendors/secugen/native.rs`:

```rust
//! Linux/macOS backend for SecuGen: dlopens libsgfplib.{so,dylib} directly,
//! resolves the SGFPM_* symbol surface, and implements the same operations
//! the Windows bridge performs.
//!
//! No bridge process — SecuGen ships 64-bit shared libraries on these platforms
//! so a 64-bit Node process can load them in-process.

use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_long, c_uchar, c_void};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{dlclose, dlerror, dlopen, dlsym, RTLD_NOW};

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

use super::constants::DEFAULT_ENROLL_SAMPLES;
use super::error_map::map_sdk_code;
use super::ffi_types::{
    FnCloseDevice, FnCreate, FnCreateTemplate, FnGetDeviceInfo, FnGetImageEx, FnGetImageQuality,
    FnGetMatchingScore, FnGetMaxTemplateSize, FnInit, FnMatchTemplate, FnOpenDevice, FnTerminate,
    HSGFPM, SGDeviceInfoParam, SGFingerInfo, SG_DEV_AUTO, SG_SECURITY_NORMAL,
};
use super::library_path::find_library_path;

pub struct NativeBackend {
    lib: LoadedLib,
    handle: HSGFPM,
    image_width: c_long,
    image_height: c_long,
    max_template_size: c_long,
    image_dpi: c_long,
    fw_version: c_long,
    serial: String,
    closed: bool,
}

struct LoadedLib {
    handle: *mut c_void,
    fn_create: FnCreate,
    fn_terminate: FnTerminate,
    fn_init: FnInit,
    fn_open_device: FnOpenDevice,
    fn_close_device: FnCloseDevice,
    fn_get_device_info: FnGetDeviceInfo,
    fn_get_image_ex: FnGetImageEx,
    fn_get_image_quality: FnGetImageQuality,
    fn_create_template: FnCreateTemplate,
    fn_get_max_template_size: FnGetMaxTemplateSize,
    fn_match_template: FnMatchTemplate,
    fn_get_matching_score: FnGetMatchingScore,
}

// LoadedLib only contains raw pointers and `unsafe extern fn` items; the
// data they reference (SGFPM handle, vendor library code) is single-owner.
// Send/Sync are safe because the surrounding Mutex serialises all access.
unsafe impl Send for LoadedLib {}
unsafe impl Sync for LoadedLib {}

impl Drop for LoadedLib {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                dlclose(self.handle);
            }
        }
    }
}

impl NativeBackend {
    /// Discover, load, and initialise the SecuGen library + device.
    pub fn init() -> Result<(Self, DeviceInfo), FingerprintError> {
        let lib_path = find_library_path()?;
        let lib = LoadedLib::load(&lib_path)?;

        let mut handle: HSGFPM = std::ptr::null_mut();
        let code = unsafe { (lib.fn_create)(&mut handle) };
        if code != 0 {
            return Err(map_sdk_code(code, 0));
        }

        let code = unsafe { (lib.fn_init)(handle, SG_DEV_AUTO) };
        if code != 0 {
            // Best-effort terminate; ignore any secondary error.
            unsafe {
                let _ = (lib.fn_terminate)(handle);
            }
            return Err(map_sdk_code(code, 0));
        }

        let code = unsafe { (lib.fn_open_device)(handle, 0) };
        if code != 0 {
            unsafe {
                let _ = (lib.fn_terminate)(handle);
            }
            return Err(map_sdk_code(code, 0));
        }

        let mut info = SGDeviceInfoParam::default();
        let code = unsafe { (lib.fn_get_device_info)(handle, &mut info) };
        if code != 0 {
            unsafe {
                let _ = (lib.fn_close_device)(handle);
                let _ = (lib.fn_terminate)(handle);
            }
            return Err(map_sdk_code(code, 0));
        }

        let mut template_size: c_long = 0;
        let code = unsafe { (lib.fn_get_max_template_size)(handle, &mut template_size) };
        if code != 0 {
            unsafe {
                let _ = (lib.fn_close_device)(handle);
                let _ = (lib.fn_terminate)(handle);
            }
            return Err(map_sdk_code(code, 0));
        }

        let serial: String = info
            .device_sn
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();

        let device_info = DeviceInfo {
            vendor: "SecuGen".to_string(),
            model: "Hamster Plus".to_string(),
            serial: serial.clone(),
            firmware: format!("{}", info.fw_version),
            image_width: info.image_width as u32,
            image_height: info.image_height as u32,
            dpi: info.image_dpi as u32,
        };

        Ok((
            Self {
                lib,
                handle,
                image_width: info.image_width,
                image_height: info.image_height,
                max_template_size: template_size,
                image_dpi: info.image_dpi,
                fw_version: info.fw_version,
                serial,
                closed: false,
            },
            device_info,
        ))
    }

    pub fn capture(
        &mut self,
        timeout_ms: u32,
        min_quality: u8,
    ) -> Result<ScanResult, FingerprintError> {
        let (image, quality) = self.capture_image(timeout_ms, min_quality)?;
        let template = self.create_template_from_image(&image)?;
        Ok(ScanResult {
            image,
            quality,
            template,
            timestamp: now_ms(),
        })
    }

    pub fn enroll(&mut self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        let sample_count = if samples == 0 {
            DEFAULT_ENROLL_SAMPLES
        } else {
            samples
        };

        let mut best_template: Option<Vec<u8>> = None;
        let mut best_quality: i32 = -1;

        for _ in 0..sample_count {
            let (image, quality) = self.capture_image(10_000, 60)?;
            let template = self.create_template_from_image(&image)?;
            if (quality as i32) > best_quality {
                best_quality = quality as i32;
                best_template = Some(template);
            }
        }

        match best_template {
            Some(data) => Ok(Template {
                user_id: user_id.to_string(),
                data,
                created_at: now_ms(),
            }),
            None => Err(FingerprintError::SdkError(
                "No valid samples captured".to_string(),
            )),
        }
    }

    pub fn verify(
        &mut self,
        user_id: &str,
        template: &Template,
    ) -> Result<MatchResult, FingerprintError> {
        let (image, _) = self.capture_image(10_000, 60)?;
        let live_template = self.create_template_from_image(&image)?;

        let mut score: c_long = 0;
        let code = unsafe {
            (self.lib.fn_get_matching_score)(
                self.handle,
                live_template.as_ptr(),
                template.data.as_ptr(),
                &mut score,
            )
        };
        if code != 0 {
            return Err(map_sdk_code(code, 0));
        }

        let mut matched: c_int = 0;
        let code = unsafe {
            (self.lib.fn_match_template)(
                self.handle,
                live_template.as_ptr(),
                template.data.as_ptr(),
                SG_SECURITY_NORMAL,
                &mut matched,
            )
        };
        if code != 0 {
            return Err(map_sdk_code(code, 0));
        }

        Ok(MatchResult {
            matched: matched != 0,
            score: score as u32,
            user_id: if matched != 0 {
                Some(user_id.to_string())
            } else {
                None
            },
        })
    }

    pub fn identify(&mut self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        if templates.is_empty() {
            return Err(FingerprintError::MatchFailed);
        }

        let (image, _) = self.capture_image(10_000, 60)?;
        let live_template = self.create_template_from_image(&image)?;

        let mut best_score: c_long = 0;
        let mut best_user_id: Option<String> = None;
        let mut best_data: Option<&[u8]> = None;

        for tmpl in templates {
            let mut score: c_long = 0;
            let code = unsafe {
                (self.lib.fn_get_matching_score)(
                    self.handle,
                    live_template.as_ptr(),
                    tmpl.data.as_ptr(),
                    &mut score,
                )
            };
            if code != 0 {
                return Err(map_sdk_code(code, 0));
            }
            if score > best_score {
                best_score = score;
                best_user_id = Some(tmpl.user_id.clone());
                best_data = Some(&tmpl.data);
            }
        }

        if let Some(data) = best_data {
            let mut matched: c_int = 0;
            let code = unsafe {
                (self.lib.fn_match_template)(
                    self.handle,
                    live_template.as_ptr(),
                    data.as_ptr(),
                    SG_SECURITY_NORMAL,
                    &mut matched,
                )
            };
            if code != 0 {
                return Err(map_sdk_code(code, 0));
            }
            Ok(MatchResult {
                matched: matched != 0,
                score: best_score as u32,
                user_id: if matched != 0 { best_user_id } else { None },
            })
        } else {
            Ok(MatchResult {
                matched: false,
                score: 0,
                user_id: None,
            })
        }
    }

    pub fn get_quality(&mut self, image: &[u8]) -> Result<u8, FingerprintError> {
        let mut quality: c_long = 0;
        let code = unsafe {
            (self.lib.fn_get_image_quality)(
                self.handle,
                self.image_width,
                self.image_height,
                image.as_ptr(),
                &mut quality,
            )
        };
        if code != 0 {
            return Err(map_sdk_code(code, 0));
        }
        Ok(quality as u8)
    }

    pub fn shutdown(mut self) {
        self.cleanup();
        // dlclose runs in LoadedLib::drop after `self` goes out of scope.
        // `closed` flag prevents `Drop` from running cleanup a second time.
    }

    fn cleanup(&mut self) {
        if !self.closed {
            unsafe {
                let _ = (self.lib.fn_close_device)(self.handle);
                let _ = (self.lib.fn_terminate)(self.handle);
            }
            self.closed = true;
        }
    }

    fn capture_image(
        &mut self,
        timeout_ms: u32,
        min_quality: u8,
    ) -> Result<(Vec<u8>, u8), FingerprintError> {
        let buf_size = (self.image_width * self.image_height) as usize;
        let mut image = vec![0u8; buf_size];

        let code = unsafe {
            (self.lib.fn_get_image_ex)(
                self.handle,
                image.as_mut_ptr(),
                timeout_ms as c_long,
                std::ptr::null_mut(),
                min_quality as c_long,
            )
        };
        if code != 0 {
            return Err(map_sdk_code(code, timeout_ms));
        }

        let mut quality: c_long = 0;
        let code = unsafe {
            (self.lib.fn_get_image_quality)(
                self.handle,
                self.image_width,
                self.image_height,
                image.as_ptr(),
                &mut quality,
            )
        };
        if code != 0 {
            return Err(map_sdk_code(code, timeout_ms));
        }

        if (quality as u8) < min_quality {
            return Err(FingerprintError::LowQuality {
                got: quality as u8,
                min: min_quality,
            });
        }

        Ok((image, quality as u8))
    }

    fn create_template_from_image(&self, image: &[u8]) -> Result<Vec<u8>, FingerprintError> {
        let mut template_buf = vec![0u8; self.max_template_size as usize];
        let finger_info = SGFingerInfo::default();
        let code = unsafe {
            (self.lib.fn_create_template)(
                self.handle,
                &finger_info as *const SGFingerInfo,
                image.as_ptr(),
                template_buf.as_mut_ptr(),
            )
        };
        if code != 0 {
            return Err(map_sdk_code(code, 0));
        }
        Ok(template_buf)
    }
}

impl Drop for NativeBackend {
    fn drop(&mut self) {
        // Best-effort cleanup if shutdown() wasn't called. `cleanup` is
        // idempotent (no-op when `closed` is set), so the explicit-shutdown
        // path doesn't double-close.
        self.cleanup();
    }
}

impl LoadedLib {
    fn load(path: &Path) -> Result<Self, FingerprintError> {
        // dlopen with RTLD_NOW forces all symbols to resolve at load time.
        let c_path = path_to_cstring(path)?;
        let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_NOW) };
        if handle.is_null() {
            return Err(FingerprintError::SdkError(format!(
                "Failed to load {}: {}",
                path.display(),
                last_dlerror().unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        let resolve = |name: &str| -> Result<*mut c_void, FingerprintError> {
            let cname = CString::new(name)
                .expect("SecuGen symbol names are static and null-byte-free");
            // Clear stale errors before dlsym (per the POSIX dlsym(3) idiom).
            unsafe {
                dlerror();
            }
            let sym = unsafe { dlsym(handle, cname.as_ptr()) };
            if sym.is_null() {
                let err = last_dlerror().unwrap_or_else(|| "symbol not found".to_string());
                return Err(FingerprintError::SdkError(format!(
                    "Symbol '{}' missing in {}: {}",
                    name,
                    path.display(),
                    err
                )));
            }
            Ok(sym)
        };

        // Resolve every symbol up-front. If any is missing the whole load fails.
        let fn_create = unsafe { std::mem::transmute_copy(&resolve("SGFPM_Create")?) };
        let fn_terminate = unsafe { std::mem::transmute_copy(&resolve("SGFPM_Terminate")?) };
        let fn_init = unsafe { std::mem::transmute_copy(&resolve("SGFPM_Init")?) };
        let fn_open_device =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_OpenDevice")?) };
        let fn_close_device =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_CloseDevice")?) };
        let fn_get_device_info =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_GetDeviceInfo")?) };
        let fn_get_image_ex =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_GetImageEx")?) };
        let fn_get_image_quality =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_GetImageQuality")?) };
        let fn_create_template =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_CreateTemplate")?) };
        let fn_get_max_template_size =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_GetMaxTemplateSize")?) };
        let fn_match_template =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_MatchTemplate")?) };
        let fn_get_matching_score =
            unsafe { std::mem::transmute_copy(&resolve("SGFPM_GetMatchingScore")?) };

        Ok(Self {
            handle,
            fn_create,
            fn_terminate,
            fn_init,
            fn_open_device,
            fn_close_device,
            fn_get_device_info,
            fn_get_image_ex,
            fn_get_image_quality,
            fn_create_template,
            fn_get_max_template_size,
            fn_match_template,
            fn_get_matching_score,
        })
    }
}

fn path_to_cstring(path: &Path) -> Result<CString, FingerprintError> {
    let s = path.to_str().ok_or_else(|| {
        FingerprintError::SdkError(format!("Library path is not valid UTF-8: {:?}", path))
    })?;
    CString::new(s).map_err(|e| {
        FingerprintError::SdkError(format!("Library path contains NUL byte: {}", e))
    })
}

fn last_dlerror() -> Option<String> {
    unsafe {
        let p = dlerror();
        if p.is_null() {
            None
        } else {
            Some(CStr::from_ptr(p).to_string_lossy().into_owned())
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
```

- [ ] **Step 2: Register the module (gated)**

Edit `sdk/src/vendors/secugen/mod.rs`. After the existing `#[cfg(windows)] mod bridge;` line add:

```rust
#[cfg(not(windows))]
mod native;
```

- [ ] **Step 3: Verify the Windows build still compiles**

Run: `cargo check -p fingerprint-sdk`
Expected: `Finished` clean. (The native module is gated out on Windows so this only checks that the cfg attribute is syntactically correct.)

- [ ] **Step 4: Static cross-check for the Linux build (if cross toolchain present)**

If you have the Linux GNU cross target installed:

Run: `cargo check -p fingerprint-sdk --target x86_64-unknown-linux-gnu`
Expected: `Finished` clean.

If you don't have the cross toolchain handy, install it via `rustup target add x86_64-unknown-linux-gnu` — for type checking only, the linker isn't invoked. If installation isn't possible right now, skip this step and rely on the build-time check that happens once a Linux host runs `cargo build`.

- [ ] **Step 5: Commit**

```bash
git add sdk/src/vendors/secugen/native.rs sdk/src/vendors/secugen/mod.rs
git commit -m "secugen: native dlopen backend for Linux and macOS"
```

---

## Task 6: Wire the native backend through the facade

**Files:**
- Modify: `sdk/src/vendors/secugen/mod.rs`
- Modify: `sdk/src/vendors/mod.rs`

- [ ] **Step 1: Extend `Backend` enum and wire the native variant**

Edit `sdk/src/vendors/secugen/mod.rs`. Replace the existing module body (everything from `use std::sync::Mutex;` down) with:

```rust
use std::sync::Mutex;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

#[cfg(windows)]
use self::bridge::BridgeBackend;
#[cfg(not(windows))]
use self::native::NativeBackend;

pub struct SecuGenScanner {
    backend: Mutex<Option<Backend>>,
}

enum Backend {
    #[cfg(windows)]
    Bridge(BridgeBackend),
    #[cfg(not(windows))]
    Native(NativeBackend),
}

impl SecuGenScanner {
    pub fn new() -> Self {
        Self {
            backend: Mutex::new(None),
        }
    }

    fn with_backend<F, T>(&self, f: F) -> Result<T, FingerprintError>
    where
        F: FnOnce(&mut Backend) -> Result<T, FingerprintError>,
    {
        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = guard.as_mut().ok_or(FingerprintError::NotInitialized)?;
        f(backend)
    }
}

impl FingerprintScanner for SecuGenScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        #[cfg(windows)]
        {
            let mut backend = BridgeBackend::spawn()?;
            let info = backend.init()?;
            *self.backend.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Backend::Bridge(backend));
            Ok(info)
        }
        #[cfg(not(windows))]
        {
            let (backend, info) = NativeBackend::init()?;
            *self.backend.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Backend::Native(backend));
            Ok(info)
        }
    }

    fn capture(&self, timeout_ms: u32, min_quality: u8) -> Result<ScanResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.capture(timeout_ms, min_quality),
            #[cfg(not(windows))]
            Backend::Native(n) => n.capture(timeout_ms, min_quality),
        })
    }

    fn enroll(&self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.enroll(user_id, samples),
            #[cfg(not(windows))]
            Backend::Native(n) => n.enroll(user_id, samples),
        })
    }

    fn verify(&self, user_id: &str, template: &Template) -> Result<MatchResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.verify(user_id, template),
            #[cfg(not(windows))]
            Backend::Native(n) => n.verify(user_id, template),
        })
    }

    fn identify(&self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.identify(templates),
            #[cfg(not(windows))]
            Backend::Native(n) => n.identify(templates),
        })
    }

    fn get_quality(&self, image: &[u8]) -> Result<u8, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.get_quality(image),
            #[cfg(not(windows))]
            Backend::Native(n) => n.get_quality(image),
        })
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(backend) = guard.take() {
            match backend {
                #[cfg(windows)]
                Backend::Bridge(br) => br.shutdown(),
                #[cfg(not(windows))]
                Backend::Native(n) => n.shutdown(),
            }
        }
        Ok(())
    }
}

impl Drop for SecuGenScanner {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
```

(The module-list lines at the top — `pub mod constants;` etc. plus the cfg-gated `bridge` and `native` declarations — stay as they were.)

- [ ] **Step 2: Make `auto` dispatch SecuGen on non-Windows**

Replace `sdk/src/vendors/mod.rs` with:

```rust
pub mod secugen;
pub mod template;
#[cfg(windows)]
pub mod wbf;
#[cfg(windows)]
pub mod neurotec;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;

use self::secugen::SecuGenScanner;

pub fn get_scanner(vendor: Option<&str>) -> Result<Box<dyn FingerprintScanner>, FingerprintError> {
    match vendor.unwrap_or("auto") {
        "secugen" => Ok(Box::new(SecuGenScanner::new())),
        #[cfg(windows)]
        "wbf" | "windows" => Ok(Box::new(wbf::WbfScanner::new())),
        #[cfg(windows)]
        "neurotec" | "neurotechnology" => Ok(Box::new(neurotec::NeurotecScanner::new())),
        "auto" => {
            #[cfg(windows)]
            {
                // Windows: try WBF first (any biometric device), fall back to SecuGen.
                Ok(Box::new(wbf::WbfScanner::new()))
            }
            #[cfg(not(windows))]
            {
                // Linux / macOS: SecuGen is the only implemented vendor today.
                Ok(Box::new(SecuGenScanner::new()))
            }
        }
        other => Err(FingerprintError::UnsupportedVendor(other.to_string())),
    }
}
```

- [ ] **Step 3: Verify Windows build is unaffected**

Run: `cargo check -p fingerprint-sdk`
Expected: `Finished` clean.

- [ ] **Step 4: Static check for Linux build (if cross toolchain present)**

Run: `cargo check -p fingerprint-sdk --target x86_64-unknown-linux-gnu`
Expected: `Finished` clean. The non-Windows path now references a real `NativeBackend`, not a stub.

- [ ] **Step 5: Commit**

```bash
git add sdk/src/vendors/secugen/mod.rs sdk/src/vendors/mod.rs
git commit -m "secugen: dispatch through native backend on Linux + macOS"
```

---

## Task 7: Panic firewall at the napi async boundary

**Files:**
- Modify: `sdk/src/lib.rs`

The current `.await.unwrap()` re-raises panics into the napi runtime. Replace each one with handling that converts `JoinError` (panic or cancellation) into a clean `napi::Error`.

- [ ] **Step 1: Add a JoinError → napi::Error helper**

Edit `sdk/src/lib.rs`. After the existing imports and `static SCANNER` (around line 21, before `fn with_scanner`), insert:

```rust
fn join_err_to_napi(e: tokio::task::JoinError) -> napi::Error {
    let reason = if e.is_panic() {
        "Vendor library panicked during operation"
    } else if e.is_cancelled() {
        "Operation cancelled"
    } else {
        "Operation aborted"
    };
    napi::Error::new(napi::Status::GenericFailure, format!("[SDK_ERROR] {}", reason))
}
```

- [ ] **Step 2: Replace each `.await.unwrap()` site**

Find every `tokio::task::spawn_blocking(...).await.unwrap()` in `sdk/src/lib.rs` and convert to `.await.map_err(join_err_to_napi)?`. Concretely, the file currently has six such sites — `init_scanner`, `capture_fingerprint`, `enroll_user`, `verify_user`, `identify_user`, `disconnect_scanner`. The shape of each rewrite is the same. Here is the pattern (replace the analogous block in each function):

Before:
```rust
    tokio::task::spawn_blocking(move || {
        ...
    })
    .await
    .unwrap()
    .map_err(|e: FingerprintError| e.into())
```

After:
```rust
    tokio::task::spawn_blocking(move || {
        ...
    })
    .await
    .map_err(join_err_to_napi)?
    .map_err(|e: FingerprintError| e.into())
```

For functions whose closure returns `napi::Result<T>` directly (rather than `Result<T, FingerprintError>`) the pattern is:

Before:
```rust
    tokio::task::spawn_blocking(move || {
        ...
    })
    .await
    .unwrap()
```

After:
```rust
    tokio::task::spawn_blocking(move || {
        ...
    })
    .await
    .map_err(join_err_to_napi)?
```

Apply consistently across all six functions. Do not change anything else in the file.

- [ ] **Step 3: Verify the file compiles**

Run: `cargo check -p fingerprint-sdk`
Expected: `Finished` clean. No new warnings.

- [ ] **Step 4: Commit**

```bash
git add sdk/src/lib.rs
git commit -m "sdk: convert JoinError to SDK_ERROR instead of re-raising panics"
```

---

## Task 8: Bridge env-var precedence honours SECUGEN_LIB_PATH

**Files:**
- Modify: `bridge/src/main.rs:120-163` (the `find_dll_path` function)

- [ ] **Step 1: Update the lookup order**

In `bridge/src/main.rs`, replace the `find_dll_path` function (the block currently spanning roughly lines 120–163) with:

```rust
fn find_dll_path() -> PathBuf {
    // 1. SECUGEN_LIB_PATH env var (preferred cross-platform name)
    if let Ok(path) = env::var("SECUGEN_LIB_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return p;
        }
    }

    // 2. SECUGEN_DLL_PATH env var (legacy alias, kept for back-compat)
    if let Ok(path) = env::var("SECUGEN_DLL_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return p;
        }
    }

    // 3. SECUGEN_SDK_PATH env var (directory containing DLL)
    if let Ok(path) = env::var("SECUGEN_SDK_PATH") {
        let p = PathBuf::from(&path).join("sgfplib.dll");
        if p.exists() {
            return p;
        }
    }

    // 4. Same directory as the bridge executable
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("sgfplib.dll");
            if p.exists() {
                return p;
            }
        }
    }

    // 5. Known SDK paths
    let candidates = [
        r"C:\SecuGen\SDK\FDx SDK Pro for Windows v4.3.1_J1.12\FDx SDK Pro for Java v1.12\jnisgfplib\win32\sgfplib.dll",
        r"C:\Program Files\SecuGen\FDx SDK Pro for Windows\lib\sgfplib.dll",
        r"C:\Program Files (x86)\SecuGen\FDx SDK Pro for Windows\lib\sgfplib.dll",
    ];
    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    // 6. Bare filename — let the Windows loader's own rules apply
    PathBuf::from("sgfplib.dll")
}
```

- [ ] **Step 2: Rebuild the 32-bit bridge**

Run: `cargo build --target i686-pc-windows-msvc --release -p secugen-bridge`
Expected: `Finished` clean.

- [ ] **Step 3: Confirm runtime parity (Windows, hardware required)**

Re-run the init smoke with the legacy env var to confirm back-compat:
```bash
SECUGEN_DLL_PATH="C:\SecuGen\SDK\FDx SDK Pro for Windows v4.3.1_J1.12\FDx SDK Pro for Java v1.12\jnisgfplib\win32\sgfplib.dll" \
echo '{"action":"init"}' | target/i686-pc-windows-msvc/release/secugen-bridge.exe
```
Expected: same `device_info` JSON as before.

Then re-run with the new env var:
```bash
SECUGEN_LIB_PATH="C:\SecuGen\SDK\FDx SDK Pro for Windows v4.3.1_J1.12\FDx SDK Pro for Java v1.12\jnisgfplib\win32\sgfplib.dll" \
echo '{"action":"init"}' | target/i686-pc-windows-msvc/release/secugen-bridge.exe
```
Expected: same `device_info` JSON.

- [ ] **Step 4: Commit**

```bash
git add bridge/src/main.rs
git commit -m "bridge: honour SECUGEN_LIB_PATH and SECUGEN_DLL_PATH on Windows"
```

---

## Task 9: README updates for Linux + macOS

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the Platform & Vendor Support table**

In `README.md`, replace the existing support table (the `| Platform | Vendor  | Model         | Strategy | Status |` block plus its rows) with:

```markdown
| Platform | Vendor  | Model         | Strategy | Status |
|----------|---------|---------------|----------|--------|
| Windows  | SecuGen | Hamster Plus  | Out-of-process bridge (32-bit DLL) | Verified (full) |
| Windows  | WBF (any) | Goodix, Synaptics, etc. | Native WinBio API (64-bit) | Init only (see note) |
| Linux (x86_64) | SecuGen | Hamster Plus | Direct FFI to `libsgfplib.so` (64-bit) | Build supported, verify on host |
| macOS (x86_64 / arm64) | SecuGen | Hamster Plus | Direct FFI to `libsgfplib.dylib` (64-bit) | Build supported, verify on host |
```

- [ ] **Step 2: Add Linux/macOS prerequisites and setup**

After the existing `### macOS / Linux` paragraph under *Prerequisites* (which currently says "No additional prerequisites..."), replace that paragraph with:

```markdown
### Linux

- **SecuGen FDx SDK Pro for Linux** — install `libsgfplib.so` (and companion driver `.so` files) from SecuGen. Not redistributable; obtain from the vendor.
- Standard glibc-based distros are expected to work; the library only depends on POSIX `dlopen` semantics.

### macOS

- **SecuGen FDx SDK Pro for macOS** — install `libsgfplib.dylib` from SecuGen. macOS Touch ID is **not** supported; Apple's `LocalAuthentication` API hides the sensor and exposes only an authenticate prompt.
```

- [ ] **Step 3: Document Linux/macOS library discovery**

In the existing *Setup* section, after the SecuGen DLL Resolution (Windows) subsection, insert a new subsection:

```markdown
### SecuGen Library Resolution (Linux / macOS)

The native client finds `libsgfplib.so` (Linux) or `libsgfplib.dylib` (macOS) in this order:

1. `SECUGEN_LIB_PATH` env var — exact path to the library (preferred name).
2. `SECUGEN_DLL_PATH` env var — exact path; honoured cross-platform for ops convenience.
3. `SECUGEN_SDK_PATH` env var — directory containing the library.
4. Same directory as the Node executable (parity step).
5. Platform default paths:
   - Linux: `/usr/local/lib`, `/usr/lib`, `/opt/SecuGen/lib`
   - macOS: `/usr/local/lib`, `/opt/SecuGen/lib`
6. Bare filename — handed to `dlopen`, falling back to `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` and the system cache.

All vendor companion libraries (`libsgfpamx.*`, the device driver `.so`/`.dylib`) must be discoverable through the same OS loader rules — typically placed in the same directory as the main library.
```

- [ ] **Step 4: Add the Linux/macOS build commands**

In the *Build* section, replace the `### macOS / Linux` subsection's content (currently a single shell block) with:

```markdown
### Linux

```bash
cd sdk && npx napi build --platform --release
```

This produces `fingerprint-sdk.linux-x64-gnu.node` (or `linux-arm64-gnu.node` on ARM). No bridge process is needed — the 64-bit Node process loads `libsgfplib.so` directly. Set `SECUGEN_LIB_PATH` or place the library in a standard location (see Setup).

### macOS

```bash
cd sdk && npx napi build --platform --release
```

Produces `fingerprint-sdk.darwin-x64.node` (Intel) or `darwin-arm64.node` (Apple silicon). Install `libsgfplib.dylib` from the SecuGen macOS SDK; Apple-silicon support depends on the vendor shipping an arm64 build.
```

- [ ] **Step 5: Update Known Limitations**

In the *Known Limitations* section, replace the existing "Verified vendor" / "Windows-only" lines with:

```markdown
- **Verified vendor**: SecuGen is the only vendor exercised end-to-end on real hardware so far. WBF and Neurotec modules compile on Windows; capture/match behaviour depends on the underlying sensor.
- **macOS Touch ID is not supported**: Apple's `LocalAuthentication` framework hides the sensor and exposes only "authenticate this user", never raw image or template data. macOS support means USB sensors with vendor SDKs (e.g. SecuGen Hamster Plus over USB).
- **No automatic reconnect mid-capture**: If a scanner is unplugged mid-operation, calls return `DEVICE_NOT_FOUND`. Call `disconnectScanner()` then `initScanner()` to recover — the library reload and device re-init happen cleanly.
```

(Leave the "Single scanner" and "Binary data as `number[]`" bullets in place.)

- [ ] **Step 6: Verify the markdown renders cleanly**

Run: `git diff README.md | head -200`
Skim the diff; check that no malformed table rows, broken code fences, or stray backticks were introduced.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs: Linux + macOS setup, build, library discovery, limitations"
```

---

## Task 10: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Re-run the full SDK test suite**

Run: `cargo test -p fingerprint-sdk --lib`
Expected: all unit tests (error_map ×4, library_path ×5) pass. No new failures.

- [ ] **Step 2: Verify the full Windows build**

Run, in order:
```bash
cargo build --target i686-pc-windows-msvc --release -p secugen-bridge
cargo build -p fingerprint-sdk --release
```
Expected: both `Finished` clean.

- [ ] **Step 3: Static-check the Linux build (if cross toolchain installed)**

Run: `cargo check -p fingerprint-sdk --target x86_64-unknown-linux-gnu`
Expected: `Finished` clean. If the cross toolchain isn't installed and you can't install it here, document the gap and proceed — a Linux host run is the authoritative check anyway.

- [ ] **Step 4: Runtime smoke against real hardware (Windows)**

With the Hamster Plus plugged in:
```bash
SECUGEN_LIB_PATH="C:\SecuGen\SDK\FDx SDK Pro for Windows v4.3.1_J1.12\FDx SDK Pro for Java v1.12\jnisgfplib\win32\sgfplib.dll" \
echo '{"action":"init"}' | target/i686-pc-windows-msvc/release/secugen-bridge.exe
```
Expected: `{"status":"ok","data":{"type":"device_info","vendor":"SecuGen",...}}` returns within ~2 s. Same shape as the pre-change baseline.

- [ ] **Step 5: Confirm `git status` is clean**

Run: `git status`
Expected: `nothing to commit, working tree clean`.

- [ ] **Step 6: Confirm commit history**

Run: `git log --oneline -15`
Expected to see (in reverse chronological order) the 9 task commits plus the prior spec/initial commits. No fixup squashing needed.

---

## Out-of-scope verifications (need Linux/macOS hardware host)

These cannot be performed from the current Windows session. The operator (or CI) runs them once the work lands on a Linux/macOS host:

- `npx ts-node examples/quick_test.ts` on Linux with the Hamster Plus plugged in: should reach `Capture OK!`.
- Same on macOS.
- Hot unplug test: unplug mid-`captureFingerprint` → expect `DEVICE_NOT_FOUND`; replug → `initScanner()` again succeeds without restarting Node.
- Missing-library test: unset `SECUGEN_LIB_PATH` and remove `/usr/local/lib/libsgfplib.so`; `initScanner('secugen')` returns `[SDK_ERROR] Failed to load libsgfplib.so: ...` with the dlerror message inline. Node process stays up.
- Cross-platform template interop: enroll on Linux, save template, verify the same template on Windows — same byte format, same match result.
