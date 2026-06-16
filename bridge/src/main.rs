mod ffi;

use std::env;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fingerprint_protocol::{BridgeCommand, BridgeResponse, ResponseData, TemplateEntry};
use libc::c_long;
use zeroize::Zeroize;

/// Maximum size of a single JSON IPC line, in bytes. Large enough to carry a
/// JSON-encoded high-res fingerprint image with headroom; small enough to
/// reject runaway/corrupted state before it OOMs the process.
const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

/// Read one '\n'-terminated line from `reader`, capped at `MAX_IPC_LINE`.
fn read_ipc_line<R: BufRead>(reader: &mut R, buf: &mut String) -> io::Result<usize> {
    read_ipc_line_with_limit(reader, buf, MAX_IPC_LINE)
}

/// Bounded `read_line` with explicit limit. Errors with `InvalidData` if the
/// limit is hit before a newline. Factored out so tests can hit boundary
/// conditions without allocating 64 MB of input.
fn read_ipc_line_with_limit<R: BufRead>(
    reader: &mut R,
    buf: &mut String,
    limit: usize,
) -> io::Result<usize> {
    let n = reader.by_ref().take(limit as u64).read_line(buf)?;
    if n == limit && !buf.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IPC line exceeds {} bytes", limit),
        ));
    }
    Ok(n)
}

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

/// Wipe biometric byte buffers carried in a response so they don't linger in
/// the allocator after this command finishes. Called after the response has
/// already been serialized and written to stdout.
fn zeroize_response(resp: &mut BridgeResponse) {
    if let BridgeResponse::Ok { data } = resp {
        match data {
            ResponseData::ScanResult { image, template, .. } => {
                image.zeroize();
                template.zeroize();
            }
            ResponseData::Template { data, .. } => {
                data.zeroize();
            }
            _ => {}
        }
    }
}

/// Wipe biometric byte buffers carried in an incoming command before the
/// command struct is dropped.
fn zeroize_command(cmd: &mut BridgeCommand) {
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
}

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
        let (mut image, quality) = match capture_image(s, 10_000, 60) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

        let template = match create_template_from_image(s, &image) {
            Ok(t) => t,
            Err(resp) => {
                image.zeroize();
                return resp;
            }
        };
        image.zeroize();

        if (quality as i32) > best_quality {
            best_quality = quality as i32;
            if let Some(mut old) = best_template.replace(template) {
                old.zeroize();
            }
        } else {
            let mut discarded = template;
            discarded.zeroize();
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

    let (mut image, _) = match capture_image(s, 10_000, 60) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let mut live_template = match create_template_from_image(s, &image) {
        Ok(t) => t,
        Err(resp) => {
            image.zeroize();
            return resp;
        }
    };

    let score_res = s
        .lib
        .get_matching_score(s.handle, &live_template, template_data);
    let score = match score_res {
        Ok(score) => score,
        Err(code) => {
            image.zeroize();
            live_template.zeroize();
            return map_sdk_error(code);
        }
    };

    let match_res = s
        .lib
        .match_template(s.handle, &live_template, template_data, SG_SECURITY_NORMAL);
    image.zeroize();
    live_template.zeroize();
    let matched = match match_res {
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

    let (mut image, _) = match capture_image(s, 10_000, 60) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let mut live_template = match create_template_from_image(s, &image) {
        Ok(t) => t,
        Err(resp) => {
            image.zeroize();
            return resp;
        }
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
            Err(code) => {
                image.zeroize();
                live_template.zeroize();
                return map_sdk_error(code);
            }
        };

        if score > best_score {
            best_score = score;
            best_user_id = Some(&tmpl.user_id);
            best_data = Some(&tmpl.data);
        }
    }

    if let Some(data) = best_data {
        let match_res = s
            .lib
            .match_template(s.handle, &live_template, data, SG_SECURITY_NORMAL);
        image.zeroize();
        live_template.zeroize();
        let matched = match match_res {
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
        image.zeroize();
        live_template.zeroize();
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
    let mut reader = stdin.lock();

    loop {
        let mut line = String::new();
        let n = match read_ipc_line(&mut reader, &mut line) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                // Oversized or non-UTF8 line — reply with an error and exit.
                // We can't safely resync the stream after a framing violation.
                let resp = err_response("SDK_ERROR", &format!("IPC framing error: {}", e));
                let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).expect("BridgeResponse serialization is infallible"));
                let _ = stdout.flush();
                break;
            }
            Err(_) => break, // unrecoverable IO error
        };
        let _ = n;

        if line.trim().is_empty() {
            continue;
        }

        let mut cmd: BridgeCommand = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                line.zeroize();
                let resp = err_response("SDK_ERROR", &format!("Invalid command: {}", e));
                let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).expect("BridgeResponse serialization is infallible"));
                let _ = stdout.flush();
                continue;
            }
        };
        line.zeroize();

        let mut response = match cmd {
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

        let mut json = serde_json::to_string(&response)
            .expect("BridgeResponse serialization is infallible");
        let _ = writeln!(stdout, "{}", json);
        let _ = stdout.flush();

        // Wipe biometric bytes from the serialized payload and the in-memory
        // command/response structs before they drop.
        json.zeroize();
        zeroize_response(&mut response);
        zeroize_command(&mut cmd);
    }

    // Cleanup on exit
    handle_disconnect(&mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ─── read_ipc_line_with_limit ────────────────────────────────────────────

    #[test]
    fn read_ipc_line_reads_normal_line() {
        let input: &[u8] = b"hello\nworld\n";
        let mut reader = Cursor::new(input);
        let mut buf = String::new();
        let n = read_ipc_line_with_limit(&mut reader, &mut buf, 1024).unwrap();
        assert_eq!(n, 6);
        assert_eq!(buf, "hello\n");
    }

    #[test]
    fn read_ipc_line_returns_zero_at_eof() {
        let input: &[u8] = b"";
        let mut reader = Cursor::new(input);
        let mut buf = String::new();
        let n = read_ipc_line_with_limit(&mut reader, &mut buf, 1024).unwrap();
        assert_eq!(n, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn read_ipc_line_rejects_oversized() {
        // Limit = 10, line = 20 bytes without newline → must error.
        let input: &[u8] = b"xxxxxxxxxxxxxxxxxxxx";
        let mut reader = Cursor::new(input);
        let mut buf = String::new();
        match read_ipc_line_with_limit(&mut reader, &mut buf, 10) {
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                assert!(e.to_string().contains("exceeds 10"));
            }
            other => panic!("expected InvalidData, got {:?}", other),
        }
    }

    #[test]
    fn read_ipc_line_accepts_line_exactly_at_limit_with_newline() {
        // 9 chars + '\n' = 10 bytes; limit = 10. Should succeed cleanly.
        let input: &[u8] = b"abcdefghi\n";
        let mut reader = Cursor::new(input);
        let mut buf = String::new();
        let n = read_ipc_line_with_limit(&mut reader, &mut buf, 10).unwrap();
        assert_eq!(n, 10);
        assert_eq!(buf, "abcdefghi\n");
    }

    #[test]
    fn read_ipc_line_handles_short_line_without_trailing_newline() {
        // EOF before newline: legitimate "last line", not an overflow.
        let input: &[u8] = b"abc";
        let mut reader = Cursor::new(input);
        let mut buf = String::new();
        let n = read_ipc_line_with_limit(&mut reader, &mut buf, 1024).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, "abc");
    }

    // ─── zeroize_response ────────────────────────────────────────────────────

    #[test]
    fn zeroize_response_wipes_scan_result() {
        let mut resp = BridgeResponse::Ok {
            data: ResponseData::ScanResult {
                image: vec![1, 2, 3, 4, 5],
                quality: 80,
                template: vec![9, 8, 7, 6],
                timestamp: 12345,
            },
        };
        zeroize_response(&mut resp);
        match resp {
            BridgeResponse::Ok {
                data:
                    ResponseData::ScanResult {
                        image,
                        template,
                        quality,
                        timestamp,
                    },
            } => {
                // zeroize::Zeroize on Vec<u8> writes zeros then truncates.
                assert!(image.is_empty(), "image bytes not wiped");
                assert!(template.is_empty(), "template bytes not wiped");
                // Scalars untouched (no biometric content).
                assert_eq!(quality, 80);
                assert_eq!(timestamp, 12345);
            }
            _ => panic!("unexpected response shape after zeroize"),
        }
    }

    #[test]
    fn zeroize_response_wipes_template_data() {
        let mut resp = BridgeResponse::Ok {
            data: ResponseData::Template {
                user_id: "alice".into(),
                data: vec![0xAB; 32],
                created_at: 0,
            },
        };
        zeroize_response(&mut resp);
        match resp {
            BridgeResponse::Ok {
                data: ResponseData::Template { user_id, data, .. },
            } => {
                assert_eq!(user_id, "alice"); // user_id is not biometric
                assert!(data.is_empty(), "template data not wiped");
            }
            _ => panic!("unexpected response shape"),
        }
    }

    #[test]
    fn zeroize_response_noop_on_non_biometric_variants() {
        let mut resp = BridgeResponse::Ok {
            data: ResponseData::MatchResult {
                matched: true,
                score: 42,
                user_id: Some("bob".into()),
            },
        };
        zeroize_response(&mut resp); // must not panic
        if let BridgeResponse::Ok {
            data: ResponseData::MatchResult { matched, score, user_id },
        } = resp
        {
            assert!(matched);
            assert_eq!(score, 42);
            assert_eq!(user_id.as_deref(), Some("bob"));
        } else {
            panic!("response shape changed");
        }
    }

    #[test]
    fn zeroize_response_noop_on_error() {
        let mut resp = BridgeResponse::Error {
            code: "X".into(),
            message: "y".into(),
        };
        zeroize_response(&mut resp); // must not panic on Error variant
    }

    // ─── zeroize_command ─────────────────────────────────────────────────────

    #[test]
    fn zeroize_command_wipes_verify_template() {
        let mut cmd = BridgeCommand::Verify {
            user_id: "alice".into(),
            template_data: vec![0xCD; 128],
        };
        zeroize_command(&mut cmd);
        match cmd {
            BridgeCommand::Verify {
                user_id,
                template_data,
            } => {
                assert_eq!(user_id, "alice");
                assert!(template_data.is_empty(), "verify template_data not wiped");
            }
            _ => panic!("command shape changed"),
        }
    }

    #[test]
    fn zeroize_command_wipes_identify_templates() {
        let mut cmd = BridgeCommand::Identify {
            templates: vec![
                TemplateEntry {
                    user_id: "a".into(),
                    data: vec![1, 2, 3],
                },
                TemplateEntry {
                    user_id: "b".into(),
                    data: vec![4, 5, 6],
                },
            ],
        };
        zeroize_command(&mut cmd);
        if let BridgeCommand::Identify { templates } = cmd {
            assert_eq!(templates.len(), 2);
            assert_eq!(templates[0].user_id, "a");
            assert_eq!(templates[1].user_id, "b");
            for t in &templates {
                assert!(t.data.is_empty(), "identify template bytes not wiped");
            }
        } else {
            panic!("command shape changed");
        }
    }

    #[test]
    fn zeroize_command_wipes_get_quality_image() {
        let mut cmd = BridgeCommand::GetQuality {
            image: vec![7u8; 256],
        };
        zeroize_command(&mut cmd);
        if let BridgeCommand::GetQuality { image } = cmd {
            assert!(image.is_empty());
        } else {
            panic!("command shape changed");
        }
    }

    #[test]
    fn zeroize_command_noop_on_non_biometric_variants() {
        // Variants without biometric byte buffers: must not panic.
        let mut init = BridgeCommand::Init;
        zeroize_command(&mut init);
        let mut disconnect = BridgeCommand::Disconnect;
        zeroize_command(&mut disconnect);
        let mut capture = BridgeCommand::Capture {
            timeout_ms: 1000,
            min_quality: 60,
        };
        zeroize_command(&mut capture);
        let mut enroll = BridgeCommand::Enroll {
            user_id: "x".into(),
            samples: 3,
        };
        zeroize_command(&mut enroll);
    }
}
