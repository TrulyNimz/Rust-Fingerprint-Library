pub mod constants;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use fingerprint_protocol::{BridgeCommand, BridgeResponse, ResponseData, TemplateEntry};

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

use self::constants::DEFAULT_ENROLL_SAMPLES;

pub struct SecuGenScanner {
    bridge: Mutex<Option<BridgeProcess>>,
}

struct BridgeProcess {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

impl SecuGenScanner {
    pub fn new() -> Self {
        Self {
            bridge: Mutex::new(None),
        }
    }

    fn find_bridge_exe() -> Result<String, FingerprintError> {
        let bridge_name = "secugen-bridge.exe";

        // 1. SECUGEN_BRIDGE_PATH env var (exact path)
        if let Ok(path) = std::env::var("SECUGEN_BRIDGE_PATH") {
            if std::path::Path::new(&path).exists() {
                return Ok(path);
            }
        }

        // 2. Next to the .node DLL itself (primary deployment location)
        if let Some(dir) = Self::get_module_dir() {
            let bridge = dir.join(bridge_name);
            if bridge.exists() {
                return Ok(bridge.to_string_lossy().to_string());
            }
        }

        // 3. Current working directory
        let cwd_bridge = std::path::Path::new(bridge_name);
        if cwd_bridge.exists() {
            return Ok(bridge_name.to_string());
        }

        // 4. Next to node.exe (fallback)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let bridge = dir.join(bridge_name);
                if bridge.exists() {
                    return Ok(bridge.to_string_lossy().to_string());
                }
            }
        }

        Err(FingerprintError::SdkError(
            "secugen-bridge.exe not found. Set SECUGEN_BRIDGE_PATH or place it next to the .node file.".to_string(),
        ))
    }

    /// Get the directory containing this .node DLL using Windows GetModuleHandleExW.
    fn get_module_dir() -> Option<std::path::PathBuf> {
        #[cfg(target_os = "windows")]
        {
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
                fn GetModuleFileNameW(
                    hModule: isize,
                    lpFilename: *mut u16,
                    nSize: u32,
                ) -> u32;
            }

            unsafe {
                let mut h_module: isize = 0;
                // Use the address of this function to find which DLL it lives in
                let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
                let ret = GetModuleHandleExW(
                    flags,
                    Self::get_module_dir as *const () as *const u16,
                    &mut h_module,
                );
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

        #[cfg(not(target_os = "windows"))]
        {
            None
        }
    }

    fn spawn_bridge() -> Result<BridgeProcess, FingerprintError> {
        let exe_path = Self::find_bridge_exe()?;

        let mut child = Command::new(&exe_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                FingerprintError::SdkError(format!("Failed to start bridge process: {}", e))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            FingerprintError::SdkError("Failed to capture bridge stdout".to_string())
        })?;

        Ok(BridgeProcess {
            child,
            reader: BufReader::new(stdout),
        })
    }

    fn send_command(
        bridge: &mut BridgeProcess,
        cmd: &BridgeCommand,
    ) -> Result<ResponseData, FingerprintError> {
        let stdin = bridge.child.stdin.as_mut().ok_or_else(|| {
            FingerprintError::SdkError("Bridge stdin not available".to_string())
        })?;

        let json = serde_json::to_string(cmd).map_err(|e| {
            FingerprintError::SdkError(format!("Failed to serialize command: {}", e))
        })?;

        writeln!(stdin, "{}", json).map_err(|e| {
            FingerprintError::SdkError(format!("Failed to write to bridge: {}", e))
        })?;

        stdin.flush().map_err(|e| {
            FingerprintError::SdkError(format!("Failed to flush bridge stdin: {}", e))
        })?;

        let mut line = String::new();
        bridge.reader.read_line(&mut line).map_err(|e| {
            FingerprintError::SdkError(format!("Failed to read bridge response: {}", e))
        })?;

        if line.trim().is_empty() {
            return Err(FingerprintError::SdkError(
                "Bridge process returned empty response (may have crashed)".to_string(),
            ));
        }

        let response: BridgeResponse = serde_json::from_str(line.trim()).map_err(|e| {
            FingerprintError::SdkError(format!("Failed to parse bridge response: {}", e))
        })?;

        match response {
            BridgeResponse::Ok { data } => Ok(data),
            BridgeResponse::Error { code, message } => {
                Err(match code.as_str() {
                    "DEVICE_NOT_FOUND" => FingerprintError::DeviceNotFound,
                    "CAPTURE_TIMEOUT" => FingerprintError::SdkError(format!("[CAPTURE_TIMEOUT] {}", message)),
                    "LOW_QUALITY" => FingerprintError::SdkError(format!("[LOW_QUALITY] {}", message)),
                    "MATCH_FAILED" => FingerprintError::MatchFailed,
                    "NOT_INITIALIZED" => FingerprintError::NotInitialized,
                    "UNSUPPORTED_VENDOR" => FingerprintError::UnsupportedVendor(message),
                    _ => FingerprintError::SdkError(format!("[{}] {}", code, message)),
                })
            }
        }
    }

    fn with_bridge<F, T>(&self, f: F) -> Result<T, FingerprintError>
    where
        F: FnOnce(&mut BridgeProcess) -> Result<T, FingerprintError>,
    {
        let mut guard = self.bridge.lock().unwrap();
        let bridge = guard.as_mut().ok_or(FingerprintError::NotInitialized)?;
        f(bridge)
    }
}

impl FingerprintScanner for SecuGenScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        let mut bridge = Self::spawn_bridge()?;
        let data = Self::send_command(&mut bridge, &BridgeCommand::Init)?;

        *self.bridge.lock().unwrap() = Some(bridge);

        match data {
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
            _ => Err(FingerprintError::SdkError(
                "Unexpected response from bridge".to_string(),
            )),
        }
    }

    fn capture(&self, timeout_ms: u32, min_quality: u8) -> Result<ScanResult, FingerprintError> {
        self.with_bridge(|bridge| {
            let data = Self::send_command(
                bridge,
                &BridgeCommand::Capture {
                    timeout_ms,
                    min_quality,
                },
            )?;

            match data {
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
                _ => Err(FingerprintError::SdkError(
                    "Unexpected response from bridge".to_string(),
                )),
            }
        })
    }

    fn enroll(&self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        let samples = if samples == 0 {
            DEFAULT_ENROLL_SAMPLES
        } else {
            samples
        };

        self.with_bridge(|bridge| {
            let data = Self::send_command(
                bridge,
                &BridgeCommand::Enroll {
                    user_id: user_id.to_string(),
                    samples,
                },
            )?;

            match data {
                ResponseData::Template {
                    user_id,
                    data,
                    created_at,
                } => Ok(Template {
                    user_id,
                    data,
                    created_at,
                }),
                _ => Err(FingerprintError::SdkError(
                    "Unexpected response from bridge".to_string(),
                )),
            }
        })
    }

    fn verify(&self, user_id: &str, template: &Template) -> Result<MatchResult, FingerprintError> {
        self.with_bridge(|bridge| {
            let data = Self::send_command(
                bridge,
                &BridgeCommand::Verify {
                    user_id: user_id.to_string(),
                    template_data: template.data.clone(),
                },
            )?;

            match data {
                ResponseData::MatchResult {
                    matched,
                    score,
                    user_id,
                } => Ok(MatchResult {
                    matched,
                    score,
                    user_id,
                }),
                _ => Err(FingerprintError::SdkError(
                    "Unexpected response from bridge".to_string(),
                )),
            }
        })
    }

    fn identify(&self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        let entries: Vec<TemplateEntry> = templates
            .iter()
            .map(|t| TemplateEntry {
                user_id: t.user_id.clone(),
                data: t.data.clone(),
            })
            .collect();

        self.with_bridge(|bridge| {
            let data = Self::send_command(
                bridge,
                &BridgeCommand::Identify {
                    templates: entries,
                },
            )?;

            match data {
                ResponseData::MatchResult {
                    matched,
                    score,
                    user_id,
                } => Ok(MatchResult {
                    matched,
                    score,
                    user_id,
                }),
                _ => Err(FingerprintError::SdkError(
                    "Unexpected response from bridge".to_string(),
                )),
            }
        })
    }

    fn get_quality(&self, image: &[u8]) -> Result<u8, FingerprintError> {
        self.with_bridge(|bridge| {
            let data = Self::send_command(
                bridge,
                &BridgeCommand::GetQuality {
                    image: image.to_vec(),
                },
            )?;

            match data {
                ResponseData::Quality { score } => Ok(score),
                _ => Err(FingerprintError::SdkError(
                    "Unexpected response from bridge".to_string(),
                )),
            }
        })
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        let mut guard = self.bridge.lock().unwrap();
        if let Some(mut bridge) = guard.take() {
            let _ = Self::send_command(&mut bridge, &BridgeCommand::Disconnect);
            let _ = bridge.child.kill();
            let _ = bridge.child.wait();
        }
        Ok(())
    }
}

impl Drop for SecuGenScanner {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
