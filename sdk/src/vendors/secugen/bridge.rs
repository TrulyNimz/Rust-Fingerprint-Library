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
        // Wipe biometric bytes AND identity-linkage strings carried by the
        // command after send completes, covering every early-return path
        // inside send_inner. `user_id` ties a person to their biometric
        // template, so leaving it in freed heap is the same leak as the
        // template itself.
        match cmd {
            BridgeCommand::Enroll { user_id, .. } => user_id.zeroize(),
            BridgeCommand::Verify { template_data, user_id } => {
                template_data.zeroize();
                user_id.zeroize();
            }
            BridgeCommand::Identify { templates } => {
                for t in templates.iter_mut() {
                    t.data.zeroize();
                    t.user_id.zeroize();
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

impl Drop for BridgeBackend {
    fn drop(&mut self) {
        // Best-effort cleanup if shutdown() wasn't called (e.g. failed init,
        // panic between spawn and first send). Without this, the 32-bit bridge
        // exe keeps running and holds the SecuGen USB driver handle, blocking
        // hot-replug recovery.
        let _ = self.child.kill();
        let _ = self.child.wait();
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

    // NOTE: CWD lookup is intentionally NOT in the chain above. A process
    // whose working directory is attacker-writable would otherwise spawn a
    // planted secugen-bridge.exe — classic binary-planting hijack.
    Err(FingerprintError::SdkError(
        "secugen-bridge.exe not found. Set SECUGEN_BRIDGE_PATH or place it next to the .node file.".to_string(),
    ))
}

/// Returns the directory containing this .node DLL (Windows-only helper).
fn module_dir() -> Option<std::path::PathBuf> {
    use std::ffi::c_void;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x00000004;
    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x00000002;

    extern "system" {
        fn GetModuleHandleExW(
            dwFlags: u32,
            lpModuleName: *const c_void,
            phModule: *mut isize,
        ) -> i32;
        fn GetModuleFileNameW(hModule: isize, lpFilename: *mut u16, nSize: u32) -> u32;
    }

    unsafe {
        let mut h_module: isize = 0;
        let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        let ret = GetModuleHandleExW(flags, module_dir as *const c_void, &mut h_module);
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
