mod ffi;

use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fingerprint_protocol::{BridgeCommand, BridgeResponse, ResponseData, TemplateEntry};
use libc::c_long;

use ffi::{SGFingerInfo, SgfpLib, HSGFPM};

// SecuGen constants
const SG_DEV_AUTO: c_long = 0xFF;
const SG_SECURITY_NORMAL: c_long = 5;

const SGFDX_ERROR_TIME_OUT: c_long = 54;
const SGFDX_ERROR_DEVICE_NOT_FOUND: c_long = 55;
const SGFDX_ERROR_DLLLOAD_FAILED_DRV: c_long = 6;

struct ScannerState {
    lib: SgfpLib,
    handle: HSGFPM,
    image_width: c_long,
    image_height: c_long,
    max_template_size: c_long,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn map_sdk_error(code: c_long) -> BridgeResponse {
    let (error_code, message) = match code {
        SGFDX_ERROR_DEVICE_NOT_FOUND => ("DEVICE_NOT_FOUND", "Device not found".to_string()),
        SGFDX_ERROR_TIME_OUT => ("CAPTURE_TIMEOUT", "Capture timed out".to_string()),
        SGFDX_ERROR_DLLLOAD_FAILED_DRV => {
            ("SDK_ERROR", "Driver DLL load failed (sgfdu*.dll missing or wrong directory)".to_string())
        }
        _ => ("SDK_ERROR", format!("SGFPLIB error code: {}", code)),
    };
    BridgeResponse::Error {
        code: error_code.to_string(),
        message,
    }
}

fn err_response(code: &str, message: &str) -> BridgeResponse {
    BridgeResponse::Error {
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn find_dll_path() -> PathBuf {
    // 1. SECUGEN_DLL_PATH env var (exact path to DLL)
    if let Ok(path) = env::var("SECUGEN_DLL_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return p;
        }
    }

    // 2. SECUGEN_SDK_PATH env var (directory containing DLL)
    if let Ok(path) = env::var("SECUGEN_SDK_PATH") {
        let p = PathBuf::from(&path).join("sgfplib.dll");
        if p.exists() {
            return p;
        }
    }

    // 3. Same directory as the bridge executable
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("sgfplib.dll");
            if p.exists() {
                return p;
            }
        }
    }

    // 4. Known SDK paths
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

    // Fallback — let libloading search PATH
    PathBuf::from("sgfplib.dll")
}

fn handle_init(state: &mut Option<ScannerState>) -> BridgeResponse {
    let dll_path = find_dll_path();
    let lib = match SgfpLib::load(&dll_path) {
        Ok(lib) => lib,
        Err(e) => return err_response("SDK_ERROR", &format!("Failed to load DLL: {}", e)),
    };

    let handle = match lib.create_handle() {
        Ok(h) => h,
        Err(code) => return map_sdk_error(code),
    };

    if let Err(code) = lib.init_device(handle, SG_DEV_AUTO) {
        return map_sdk_error(code);
    }

    if let Err(code) = lib.open_device(handle, 0) {
        return map_sdk_error(code);
    }

    let info = match lib.get_device_info(handle) {
        Ok(info) => info,
        Err(code) => return map_sdk_error(code),
    };

    let template_size = match lib.get_max_template_size(handle) {
        Ok(s) => s,
        Err(code) => return map_sdk_error(code),
    };

    let serial = info
        .device_sn
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect::<String>();

    *state = Some(ScannerState {
        lib,
        handle,
        image_width: info.image_width,
        image_height: info.image_height,
        max_template_size: template_size,
    });

    BridgeResponse::Ok {
        data: ResponseData::DeviceInfo {
            vendor: "SecuGen".into(),
            model: "Hamster Plus".into(),
            serial,
            firmware: format!("{}", info.fw_version),
            image_width: info.image_width as u32,
            image_height: info.image_height as u32,
            dpi: info.image_dpi as u32,
        },
    }
}

fn capture_image(
    s: &ScannerState,
    timeout_ms: u32,
    min_quality: u8,
) -> Result<(Vec<u8>, u8), BridgeResponse> {
    let buf_size = (s.image_width * s.image_height) as usize;
    let mut image = vec![0u8; buf_size];

    s.lib
        .get_image_ex(s.handle, &mut image, timeout_ms as c_long, min_quality as c_long)
        .map_err(map_sdk_error)?;

    let quality = s
        .lib
        .get_image_quality(s.handle, s.image_width, s.image_height, &image)
        .map_err(map_sdk_error)?;

    if (quality as u8) < min_quality {
        return Err(err_response(
            "LOW_QUALITY",
            &format!(
                "Image quality too low: {} (minimum: {})",
                quality, min_quality
            ),
        ));
    }

    Ok((image, quality as u8))
}

fn create_template_from_image(s: &ScannerState, image: &[u8]) -> Result<Vec<u8>, BridgeResponse> {
    let mut template_buf = vec![0u8; s.max_template_size as usize];
    let finger_info = SGFingerInfo::default();
    s.lib
        .create_template(s.handle, &finger_info, image, &mut template_buf)
        .map_err(map_sdk_error)?;
    Ok(template_buf)
}

fn handle_capture(
    state: &Option<ScannerState>,
    timeout_ms: u32,
    min_quality: u8,
) -> BridgeResponse {
    let s = match state.as_ref() {
        Some(s) => s,
        None => return err_response("NOT_INITIALIZED", "Scanner not initialized"),
    };

    let (image, quality) = match capture_image(s, timeout_ms, min_quality) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let template = match create_template_from_image(s, &image) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    BridgeResponse::Ok {
        data: ResponseData::ScanResult {
            image,
            quality,
            template,
            timestamp: now_ms(),
        },
    }
}

fn handle_enroll(state: &Option<ScannerState>, user_id: &str, samples: u8) -> BridgeResponse {
    let s = match state.as_ref() {
        Some(s) => s,
        None => return err_response("NOT_INITIALIZED", "Scanner not initialized"),
    };

    let sample_count = if samples == 0 { 3u8 } else { samples };
    let mut best_template: Option<Vec<u8>> = None;
    let mut best_quality: i32 = -1;

    for _ in 0..sample_count {
        let (image, quality) = match capture_image(s, 10_000, 60) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

        let template = match create_template_from_image(s, &image) {
            Ok(t) => t,
            Err(resp) => return resp,
        };

        if (quality as i32) > best_quality {
            best_quality = quality as i32;
            best_template = Some(template);
        }
    }

    match best_template {
        Some(data) => BridgeResponse::Ok {
            data: ResponseData::Template {
                user_id: user_id.to_string(),
                data,
                created_at: now_ms(),
            },
        },
        None => err_response("SDK_ERROR", "No valid samples captured"),
    }
}

fn handle_verify(
    state: &Option<ScannerState>,
    user_id: &str,
    template_data: &[u8],
) -> BridgeResponse {
    let s = match state.as_ref() {
        Some(s) => s,
        None => return err_response("NOT_INITIALIZED", "Scanner not initialized"),
    };

    let (image, _) = match capture_image(s, 10_000, 60) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let live_template = match create_template_from_image(s, &image) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let score = match s
        .lib
        .get_matching_score(s.handle, &live_template, template_data)
    {
        Ok(score) => score,
        Err(code) => return map_sdk_error(code),
    };

    let matched = match s
        .lib
        .match_template(s.handle, &live_template, template_data, SG_SECURITY_NORMAL)
    {
        Ok(m) => m,
        Err(code) => return map_sdk_error(code),
    };

    BridgeResponse::Ok {
        data: ResponseData::MatchResult {
            matched,
            score: score as u32,
            user_id: if matched {
                Some(user_id.to_string())
            } else {
                None
            },
        },
    }
}

fn handle_identify(
    state: &Option<ScannerState>,
    templates: &[TemplateEntry],
) -> BridgeResponse {
    let s = match state.as_ref() {
        Some(s) => s,
        None => return err_response("NOT_INITIALIZED", "Scanner not initialized"),
    };

    if templates.is_empty() {
        return err_response("MATCH_FAILED", "No templates provided");
    }

    let (image, _) = match capture_image(s, 10_000, 60) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let live_template = match create_template_from_image(s, &image) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let mut best_score: c_long = 0;
    let mut best_user_id: Option<&str> = None;
    let mut best_data: Option<&[u8]> = None;

    for tmpl in templates {
        let score = match s
            .lib
            .get_matching_score(s.handle, &live_template, &tmpl.data)
        {
            Ok(score) => score,
            Err(code) => return map_sdk_error(code),
        };

        if score > best_score {
            best_score = score;
            best_user_id = Some(&tmpl.user_id);
            best_data = Some(&tmpl.data);
        }
    }

    if let Some(data) = best_data {
        let matched = match s
            .lib
            .match_template(s.handle, &live_template, data, SG_SECURITY_NORMAL)
        {
            Ok(m) => m,
            Err(code) => return map_sdk_error(code),
        };

        BridgeResponse::Ok {
            data: ResponseData::MatchResult {
                matched,
                score: best_score as u32,
                user_id: if matched {
                    best_user_id.map(|s| s.to_string())
                } else {
                    None
                },
            },
        }
    } else {
        BridgeResponse::Ok {
            data: ResponseData::MatchResult {
                matched: false,
                score: 0,
                user_id: None,
            },
        }
    }
}

fn handle_get_quality(state: &Option<ScannerState>, image: &[u8]) -> BridgeResponse {
    let s = match state.as_ref() {
        Some(s) => s,
        None => return err_response("NOT_INITIALIZED", "Scanner not initialized"),
    };

    let quality = match s
        .lib
        .get_image_quality(s.handle, s.image_width, s.image_height, image)
    {
        Ok(q) => q,
        Err(code) => return map_sdk_error(code),
    };

    BridgeResponse::Ok {
        data: ResponseData::Quality {
            score: quality as u8,
        },
    }
}

fn handle_disconnect(state: &mut Option<ScannerState>) -> BridgeResponse {
    if let Some(s) = state.take() {
        let _ = s.lib.close_device(s.handle);
        let _ = s.lib.terminate(s.handle);
    }
    BridgeResponse::Ok {
        data: ResponseData::Void,
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut state: Option<ScannerState> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // stdin closed
        };

        if line.trim().is_empty() {
            continue;
        }

        let cmd: BridgeCommand = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                let resp = err_response("SDK_ERROR", &format!("Invalid command: {}", e));
                let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
                let _ = stdout.flush();
                continue;
            }
        };

        let response = match cmd {
            BridgeCommand::Init => handle_init(&mut state),
            BridgeCommand::Capture {
                timeout_ms,
                min_quality,
            } => handle_capture(&state, timeout_ms, min_quality),
            BridgeCommand::Enroll { ref user_id, samples } => {
                handle_enroll(&state, user_id, samples)
            }
            BridgeCommand::Verify {
                ref user_id,
                ref template_data,
            } => handle_verify(&state, user_id, template_data),
            BridgeCommand::Identify { ref templates } => handle_identify(&state, templates),
            BridgeCommand::GetQuality { ref image } => handle_get_quality(&state, image),
            BridgeCommand::Disconnect => handle_disconnect(&mut state),
        };

        let _ = writeln!(stdout, "{}", serde_json::to_string(&response).unwrap());
        let _ = stdout.flush();
    }

    // Cleanup on exit
    handle_disconnect(&mut state);
}
