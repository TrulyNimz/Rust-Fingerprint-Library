use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

// Neurotec FFV SDK types
type NResult = i32;
type NInt = i32;
type NUInt = u32;
type NByte = u8;
type NFloat = f32;
type NSizeType = u64; // 64-bit build

// Opaque handle
type HNffvUser = *mut std::ffi::c_void;

// NffvStatus enum
#[allow(dead_code)]
const NFES_NONE: i32 = 0;
const NFES_TEMPLATE_CREATED: i32 = 1;
const NFES_NO_SCANNER: i32 = 2;
const NFES_SCANNER_TIMEOUT: i32 = 3;
#[allow(dead_code)]
const NFES_USER_CANCELED: i32 = 4;
const NFES_QUALITY_CHECK_FAILED: i32 = 100;

// Error codes
const N_OK: i32 = 0;

// Function pointer types (N_API = __stdcall on Windows)
type FnNffvInitializeW = unsafe extern "system" fn(
    sz_db_name: *const u16,
    sz_password: *const u16,
    sz_scanner_modules: *const u16,
) -> NResult;
type FnNffvUninitialize = unsafe extern "system" fn();
type FnNffvEnroll = unsafe extern "system" fn(
    timeout: NUInt,
    p_status: *mut NInt,
    ph_user: *mut HNffvUser,
) -> NResult;
type FnNffvVerify = unsafe extern "system" fn(
    h_user: HNffvUser,
    timeout: NUInt,
    p_status: *mut NInt,
    p_score: *mut NInt,
) -> NResult;
type FnNffvCancel = unsafe extern "system" fn() -> NResult;
type FnNffvGetUserCount = unsafe extern "system" fn(p_value: *mut NInt) -> NResult;
type FnNffvGetUser = unsafe extern "system" fn(index: NInt, p_value: *mut HNffvUser) -> NResult;
type FnNffvRemoveUser = unsafe extern "system" fn(index: NInt) -> NResult;
type FnNffvGetQualityThreshold = unsafe extern "system" fn(p_value: *mut NByte) -> NResult;
type FnNffvSetQualityThreshold = unsafe extern "system" fn(value: NByte) -> NResult;
type FnNffvUserGetImage = unsafe extern "system" fn(
    h_user: HNffvUser,
    p_width: *mut NUInt,
    p_height: *mut NUInt,
    p_horz_resolution: *mut NFloat,
    p_vert_resolution: *mut NFloat,
    p_stride: *mut NSizeType,
    p_pixels: *mut u8,
) -> NResult;
type FnNffvUserGetId = unsafe extern "system" fn(h_user: HNffvUser, p_value: *mut NInt) -> NResult;
type FnNffvGetAvailableScannerModulesW =
    unsafe extern "system" fn(pp_value: *mut *mut u16) -> NResult;
type FnNffvFreeMemory = unsafe extern "system" fn(p_block: *mut std::ffi::c_void);
type FnNffvGetErrorMessageW =
    unsafe extern "system" fn(code: NResult, sz_value: *mut u16) -> NInt;

struct NffvLib {
    _handle: *mut std::ffi::c_void,
    initialize_w: FnNffvInitializeW,
    uninitialize: FnNffvUninitialize,
    enroll: FnNffvEnroll,
    verify: FnNffvVerify,
    cancel: FnNffvCancel,
    get_user_count: FnNffvGetUserCount,
    get_user: FnNffvGetUser,
    remove_user: FnNffvRemoveUser,
    get_quality_threshold: FnNffvGetQualityThreshold,
    set_quality_threshold: FnNffvSetQualityThreshold,
    user_get_image: FnNffvUserGetImage,
    user_get_id: FnNffvUserGetId,
    get_available_scanner_modules_w: FnNffvGetAvailableScannerModulesW,
    free_memory: FnNffvFreeMemory,
    get_error_message_w: FnNffvGetErrorMessageW,
}

// Safety: The DLL functions are thread-safe per Neurotec documentation
unsafe impl Send for NffvLib {}
unsafe impl Sync for NffvLib {}

pub struct NeurotecScanner {
    lib: Mutex<Option<NffvLib>>,
}

impl NeurotecScanner {
    pub fn new() -> Self {
        Self {
            lib: Mutex::new(None),
        }
    }

    fn find_sdk_dir() -> Result<String, FingerprintError> {
        // 1. NEUROTEC_SDK_PATH env var
        if let Ok(path) = std::env::var("NEUROTEC_SDK_PATH") {
            let dll = std::path::Path::new(&path).join("Nffv.dll");
            if dll.exists() {
                return Ok(path);
            }
        }

        // 2. Known install path from our download
        let known_paths = [
            "D:/Projects/API/Fingerprint-Rust/neurotechnology-sdk/FreeFingerprintVerification_3_0_SDK/Bin/Win64_x64",
            "C:/Neurotechnology/FFV SDK/Bin/Win64_x64",
        ];
        for p in &known_paths {
            let dll = std::path::Path::new(p).join("Nffv.dll");
            if dll.exists() {
                return Ok(p.to_string());
            }
        }

        // 3. Same directory as node.exe
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let dll = dir.join("Nffv.dll");
                if dll.exists() {
                    return Ok(dir.to_string_lossy().to_string());
                }
            }
        }

        // 4. Current working directory
        if std::path::Path::new("Nffv.dll").exists() {
            return Ok(".".to_string());
        }

        Err(FingerprintError::SdkError(
            "Neurotechnology FFV SDK not found. Set NEUROTEC_SDK_PATH to the Bin/Win64_x64 directory.".to_string(),
        ))
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn from_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    fn load_dll(sdk_dir: &str) -> Result<NffvLib, FingerprintError> {
        use std::ffi::c_void;

        // Windows API imports
        extern "system" {
            fn LoadLibraryW(name: *const u16) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn SetDllDirectoryW(path: *const u16) -> i32;
        }

        // Set DLL search directory so Nffv.dll can find its scanner modules
        let sdk_dir_wide = Self::to_wide(sdk_dir);
        unsafe {
            SetDllDirectoryW(sdk_dir_wide.as_ptr());
        }

        let dll_path = format!("{}\\Nffv.dll", sdk_dir.replace('/', "\\"));
        let dll_path_wide = Self::to_wide(&dll_path);

        let handle = unsafe { LoadLibraryW(dll_path_wide.as_ptr()) };
        if handle.is_null() {
            return Err(FingerprintError::SdkError(format!(
                "Failed to load Nffv.dll from {}",
                dll_path
            )));
        }

        macro_rules! load_fn {
            ($name:expr) => {{
                let name_bytes = concat!($name, "\0").as_bytes();
                let ptr = unsafe { GetProcAddress(handle, name_bytes.as_ptr()) };
                if ptr.is_null() {
                    return Err(FingerprintError::SdkError(format!(
                        "Failed to find {} in Nffv.dll",
                        $name
                    )));
                }
                unsafe { std::mem::transmute(ptr) }
            }};
        }

        Ok(NffvLib {
            _handle: handle,
            initialize_w: load_fn!("NffvInitializeW"),
            uninitialize: load_fn!("NffvUninitialize"),
            enroll: load_fn!("NffvEnroll"),
            verify: load_fn!("NffvVerify"),
            cancel: load_fn!("NffvCancel"),
            get_user_count: load_fn!("NffvGetUserCount"),
            get_user: load_fn!("NffvGetUser"),
            remove_user: load_fn!("NffvRemoveUser"),
            get_quality_threshold: load_fn!("NffvGetQualityThreshold"),
            set_quality_threshold: load_fn!("NffvSetQualityThreshold"),
            user_get_image: load_fn!("NffvUserGetImage"),
            user_get_id: load_fn!("NffvUserGetId"),
            get_available_scanner_modules_w: load_fn!("NffvGetAvailableScannerModulesW"),
            free_memory: load_fn!("NffvFreeMemory"),
            get_error_message_w: load_fn!("NffvGetErrorMessageW"),
        })
    }

    fn nffv_error(lib: &NffvLib, code: NResult) -> FingerprintError {
        let mut buf = [0u16; 256];
        unsafe {
            (lib.get_error_message_w)(code, buf.as_mut_ptr());
        }
        let msg = Self::from_wide(buf.as_ptr());
        FingerprintError::SdkError(format!("Neurotec error {}: {}", code, msg))
    }

    fn check_status(status: NInt) -> Result<(), FingerprintError> {
        match status {
            NFES_TEMPLATE_CREATED => Ok(()),
            NFES_NO_SCANNER => Err(FingerprintError::DeviceNotFound),
            NFES_SCANNER_TIMEOUT => Err(FingerprintError::SdkError(
                "[CAPTURE_TIMEOUT] Scanner timed out waiting for finger".to_string(),
            )),
            NFES_QUALITY_CHECK_FAILED => Err(FingerprintError::SdkError(
                "[LOW_QUALITY] Fingerprint quality check failed".to_string(),
            )),
            _ => Err(FingerprintError::SdkError(format!(
                "Unexpected Nffv status: {}",
                status
            ))),
        }
    }

    fn with_lib<F, T>(&self, f: F) -> Result<T, FingerprintError>
    where
        F: FnOnce(&NffvLib) -> Result<T, FingerprintError>,
    {
        let guard = self.lib.lock().unwrap();
        let lib = guard.as_ref().ok_or(FingerprintError::NotInitialized)?;
        f(lib)
    }
}

impl FingerprintScanner for NeurotecScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        let sdk_dir = Self::find_sdk_dir()?;
        let lib = Self::load_dll(&sdk_dir)?;

        // Discover available scanner modules
        let mut modules_ptr: *mut u16 = std::ptr::null_mut();
        let result =
            unsafe { (lib.get_available_scanner_modules_w)(&mut modules_ptr) };
        let modules_str = if result >= N_OK && !modules_ptr.is_null() {
            let s = Self::from_wide(modules_ptr);
            unsafe {
                (lib.free_memory)(modules_ptr as *mut std::ffi::c_void);
            }
            s
        } else {
            format!("(discovery failed: {})", result)
        };

        eprintln!("[neurotec] SDK dir: {}", sdk_dir);
        eprintln!("[neurotec] Available modules: {}", modules_str);

        // Pick the best scanner module: prefer SupremaBioMini, fall back to SecuGen
        let scanner_module = if modules_str.contains("SupremaBioMini") {
            "SupremaBioMini"
        } else if modules_str.contains("SecuGen") {
            "SecuGen"
        } else {
            // Pass empty string to let SDK try all available modules
            ""
        };

        eprintln!("[neurotec] Using module: '{}'", scanner_module);

        // Initialize with a temp database in the SDK directory
        let db_file = format!("{}\\nffv_temp.db", sdk_dir.replace('/', "\\"));
        eprintln!("[neurotec] DB path: {}", db_file);
        let db_path = Self::to_wide(&db_file);
        let password = Self::to_wide("");
        let module_wide = Self::to_wide(scanner_module);

        let result = unsafe {
            (lib.initialize_w)(db_path.as_ptr(), password.as_ptr(), module_wide.as_ptr())
        };
        eprintln!("[neurotec] Initialize result: {}", result);
        if result < N_OK {
            return Err(Self::nffv_error(&lib, result));
        }

        let vendor = if scanner_module.contains("Suprema") || scanner_module.contains("BioMini") {
            "Suprema/Xperix (via Neurotec)"
        } else if scanner_module.contains("SecuGen") {
            "SecuGen (via Neurotec)"
        } else {
            "Neurotec FFV"
        };

        *self.lib.lock().unwrap() = Some(lib);

        Ok(DeviceInfo {
            vendor: vendor.to_string(),
            model: scanner_module.to_string(),
            serial: String::new(),
            firmware: format!("Neurotec FFV 3.0 | Modules: {}", modules_str),
            image_width: 0,
            image_height: 0,
            dpi: 500,
        })
    }

    fn capture(&self, timeout_ms: u32, min_quality: u8) -> Result<ScanResult, FingerprintError> {
        self.with_lib(|lib| {
            // Set quality threshold
            let result = unsafe { (lib.set_quality_threshold)(min_quality) };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }

            // Enroll to capture (this is the only way to capture in the free SDK)
            let mut status: NInt = 0;
            let mut h_user: HNffvUser = std::ptr::null_mut();

            let result = unsafe { (lib.enroll)(timeout_ms, &mut status, &mut h_user) };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }
            Self::check_status(status)?;

            // Get image data - first call with null to get dimensions
            let mut width: NUInt = 0;
            let mut height: NUInt = 0;
            let mut horz_res: NFloat = 0.0;
            let mut vert_res: NFloat = 0.0;
            let mut stride: NSizeType = 0;

            let result = unsafe {
                (lib.user_get_image)(
                    h_user,
                    &mut width,
                    &mut height,
                    &mut horz_res,
                    &mut vert_res,
                    &mut stride,
                    std::ptr::null_mut(),
                )
            };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }

            // Allocate and get pixels
            let pixel_count = (stride as usize) * (height as usize);
            let mut pixels = vec![0u8; pixel_count];

            let result = unsafe {
                (lib.user_get_image)(
                    h_user,
                    &mut width,
                    &mut height,
                    &mut horz_res,
                    &mut vert_res,
                    &mut stride,
                    pixels.as_mut_ptr(),
                )
            };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }

            // Get quality threshold (as a proxy for quality score)
            let mut quality: NByte = 0;
            let _ = unsafe { (lib.get_quality_threshold)(&mut quality) };

            // Get user ID
            let mut user_id: NInt = 0;
            let _ = unsafe { (lib.user_get_id)(h_user, &mut user_id) };

            // Remove the temp user to not consume the 10-slot limit
            let mut user_count: NInt = 0;
            let _ = unsafe { (lib.get_user_count)(&mut user_count) };
            if user_count > 0 {
                let _ = unsafe { (lib.remove_user)(user_count - 1) };
            }

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;

            Ok(ScanResult {
                image: pixels,
                quality: quality.max(1), // quality threshold used, at minimum 1
                template: Vec::new(), // free SDK doesn't expose raw templates
                timestamp,
            })
        })
    }

    fn enroll(&self, user_id: &str, _samples: u8) -> Result<Template, FingerprintError> {
        self.with_lib(|lib| {
            // The free SDK captures once per enroll call
            let mut status: NInt = 0;
            let mut h_user: HNffvUser = std::ptr::null_mut();

            let result = unsafe { (lib.enroll)(10000, &mut status, &mut h_user) };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }
            Self::check_status(status)?;

            // Get internal user ID
            let mut internal_id: NInt = 0;
            let _ = unsafe { (lib.user_get_id)(h_user, &mut internal_id) };

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;

            // Store the internal ID as the "template" data
            Ok(Template {
                user_id: user_id.to_string(),
                data: internal_id.to_le_bytes().to_vec(),
                created_at: timestamp,
            })
        })
    }

    fn verify(&self, _user_id: &str, template: &Template) -> Result<MatchResult, FingerprintError> {
        self.with_lib(|lib| {
            // Recover internal index from template data
            if template.data.len() < 4 {
                return Err(FingerprintError::SdkError(
                    "Invalid Neurotec template: missing internal ID".to_string(),
                ));
            }
            let internal_id = i32::from_le_bytes([
                template.data[0],
                template.data[1],
                template.data[2],
                template.data[3],
            ]);

            // Find the user by ID
            let mut h_user: HNffvUser = std::ptr::null_mut();
            let mut user_count: NInt = 0;
            let _ = unsafe { (lib.get_user_count)(&mut user_count) };

            // Search for user with matching internal ID
            let mut found = false;
            for i in 0..user_count {
                let mut h: HNffvUser = std::ptr::null_mut();
                let r = unsafe { (lib.get_user)(i, &mut h) };
                if r >= N_OK {
                    let mut uid: NInt = 0;
                    let _ = unsafe { (lib.user_get_id)(h, &mut uid) };
                    if uid == internal_id {
                        h_user = h;
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return Err(FingerprintError::SdkError(
                    "Enrolled user not found in Neurotec database. Re-enroll required.".to_string(),
                ));
            }

            let mut status: NInt = 0;
            let mut score: NInt = 0;

            let result = unsafe { (lib.verify)(h_user, 10000, &mut status, &mut score) };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }
            Self::check_status(status)?;

            Ok(MatchResult {
                matched: score > 0,
                score: score.max(0) as u32,
                user_id: if score > 0 {
                    Some(template.user_id.clone())
                } else {
                    None
                },
            })
        })
    }

    fn identify(&self, _templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        Err(FingerprintError::SdkError(
            "1:N identification is not supported by the Neurotechnology Free FFV SDK. Use verifyUser() for 1:1 matching, or upgrade to VeriFinger SDK.".to_string(),
        ))
    }

    fn get_quality(&self, _image: &[u8]) -> Result<u8, FingerprintError> {
        self.with_lib(|lib| {
            let mut quality: NByte = 0;
            let result = unsafe { (lib.get_quality_threshold)(&mut quality) };
            if result < N_OK {
                return Err(Self::nffv_error(lib, result));
            }
            Ok(quality)
        })
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        let mut guard = self.lib.lock().unwrap();
        if let Some(lib) = guard.as_ref() {
            unsafe {
                (lib.uninitialize)();
            }
        }
        *guard = None;
        Ok(())
    }
}

impl Drop for NeurotecScanner {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
