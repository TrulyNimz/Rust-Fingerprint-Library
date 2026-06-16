//! Linux/macOS backend for SecuGen: dlopens libsgfplib.{so,dylib} directly,
//! resolves the SGFPM_* symbol surface, and implements the same operations
//! the Windows bridge performs.
//!
//! No bridge process — SecuGen ships 64-bit shared libraries on these platforms
//! so a 64-bit Node process can load them in-process.

use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_long, c_void};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{dlclose, dlerror, dlopen, dlsym, RTLD_NOW};

use zeroize::Zeroize;

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

/// Linux/macOS in-process backend for SecuGen.
///
/// Drop order invariant: `cleanup` (called from `Drop for NativeBackend`)
/// dispatches through `self.lib.fn_*`, so `self.lib` MUST still be live
/// when cleanup runs. Rust drops `Drop::drop()` first, then fields in
/// declaration order — so as long as the `Drop for NativeBackend` impl
/// stays present and calls cleanup before returning, ordering is safe.
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

// NativeBackend holds an HSGFPM (raw *mut c_void) plus a LoadedLib. The SDK
// handle is owned exclusively by this struct and must not be used concurrently
// (the SGFPLIB API is not thread-safe). Send is sound because ownership
// transfers; Sync is intentionally NOT implemented — concurrent access via
// `&NativeBackend` would race the handle.
unsafe impl Send for NativeBackend {}

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
            let (mut image, quality) = self.capture_image(10_000, 60)?;
            let template = self.create_template_from_image(&image)?;
            // Raw image is no longer needed once the template is extracted.
            image.zeroize();
            if (quality as i32) > best_quality {
                best_quality = quality as i32;
                // Wipe the previously-best template before replacing it; otherwise
                // a worse-quality sample's bytes linger in freed heap.
                if let Some(mut prior) = best_template.replace(template) {
                    prior.zeroize();
                }
            } else {
                // This sample didn't win — wipe its template before drop.
                let mut t = template;
                t.zeroize();
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
        let (mut image, _) = self.capture_image(10_000, 60)?;
        let live_template = self.create_template_from_image(&image)?;
        image.zeroize();
        let mut live_template = live_template;

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
            live_template.zeroize();
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
            live_template.zeroize();
            return Err(map_sdk_code(code, 0));
        }

        let result = MatchResult {
            matched: matched != 0,
            score: score as u32,
            user_id: if matched != 0 {
                Some(user_id.to_string())
            } else {
                None
            },
        };
        live_template.zeroize();
        Ok(result)
    }

    pub fn identify(&mut self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        if templates.is_empty() {
            return Err(FingerprintError::MatchFailed);
        }

        let (mut image, _) = self.capture_image(10_000, 60)?;
        let live_template = self.create_template_from_image(&image)?;
        image.zeroize();
        let mut live_template = live_template;

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
                live_template.zeroize();
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
                live_template.zeroize();
                return Err(map_sdk_code(code, 0));
            }
            let result = MatchResult {
                matched: matched != 0,
                score: best_score as u32,
                user_id: if matched != 0 { best_user_id } else { None },
            };
            live_template.zeroize();
            Ok(result)
        } else {
            live_template.zeroize();
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
        if self.image_width <= 0 || self.image_height <= 0 {
            return Err(FingerprintError::SdkError(
                "Device returned invalid image dimensions".to_string(),
            ));
        }
        let buf_size: usize = (self.image_width as u64)
            .checked_mul(self.image_height as u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| {
                FingerprintError::SdkError("Image buffer size overflows usize".to_string())
            })?;
        let mut image = vec![0u8; buf_size];

        let code = unsafe {
            (self.lib.fn_get_image_ex)(
                self.handle,
                image.as_mut_ptr(),
                timeout_ms as c_long,
                std::ptr::null_mut(), // reserved ImageEx extra params — pass NULL per SDK docs
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
        if self.max_template_size <= 0 {
            return Err(FingerprintError::SdkError(
                "Device returned invalid template size".to_string(),
            ));
        }
        let template_size: usize = usize::try_from(self.max_template_size).map_err(|_| {
            FingerprintError::SdkError("Template size overflows usize".to_string())
        })?;
        let mut template_buf = vec![0u8; template_size];
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
