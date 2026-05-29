//! Runtime DLL loading for SecuGen SGFPLIB using Windows API directly.
//! This runs in the 32-bit bridge process, so architecture matches the 32-bit DLL.
//!
//! Loader hardening: restricts the process-wide DLL search to System32 + the
//! specific vendor directory we add via AddDllDirectory, blocking the legacy
//! "search PATH and CWD" behaviour that allows DLL hijacking. Requires
//! Windows 7 SP1 + KB2533623 or Windows 8+.

use libc::{c_int, c_long, c_uchar, c_void};
use std::ffi::CString;
use std::path::Path;
use std::sync::Once;

pub type HSGFPM = *mut c_void;
type HMODULE = *mut c_void;

// Flags for SetDefaultDllDirectories / LoadLibraryExW.
const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x0000_0400;

extern "system" {
    fn LoadLibraryExW(path: *const u16, h_file: HMODULE, flags: u32) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const i8) -> *mut c_void;
    fn AddDllDirectory(new_directory: *const u16) -> *mut c_void;
    fn SetDefaultDllDirectories(flags: u32) -> i32;
    fn GetLastError() -> u32;
}

/// Restrict the process-wide DLL search to System32 + explicitly added dirs.
/// Idempotent; safe to call from every loader.
fn ensure_safe_dll_search() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS);
    });
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_proc<T>(module: HMODULE, name: &str) -> Result<T, String> {
    let cname = CString::new(name).expect("DLL export names are static and null-byte-free");
    let addr = unsafe { GetProcAddress(module, cname.as_ptr()) };
    if addr.is_null() {
        return Err(format!("{} not found in DLL (error {})", name, unsafe {
            GetLastError()
        }));
    }
    Ok(unsafe { std::mem::transmute_copy(&addr) })
}

// C struct layouts — must match the SDK headers exactly
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

// Type aliases for function pointers loaded from the DLL
type FnCreate = unsafe extern "system" fn(*mut HSGFPM) -> c_long;
type FnTerminate = unsafe extern "system" fn(HSGFPM) -> c_long;
type FnInit = unsafe extern "system" fn(HSGFPM, c_long) -> c_long;
type FnOpenDevice = unsafe extern "system" fn(HSGFPM, c_int) -> c_long;
type FnCloseDevice = unsafe extern "system" fn(HSGFPM) -> c_long;
type FnGetDeviceInfo = unsafe extern "system" fn(HSGFPM, *mut SGDeviceInfoParam) -> c_long;
type FnGetImageEx =
    unsafe extern "system" fn(HSGFPM, *mut c_uchar, c_long, *mut c_void, c_long) -> c_long;
type FnGetImageQuality =
    unsafe extern "system" fn(HSGFPM, c_long, c_long, *const c_uchar, *mut c_long) -> c_long;
type FnCreateTemplate =
    unsafe extern "system" fn(HSGFPM, *const SGFingerInfo, *const c_uchar, *mut c_uchar) -> c_long;
type FnGetMaxTemplateSize = unsafe extern "system" fn(HSGFPM, *mut c_long) -> c_long;
type FnMatchTemplate =
    unsafe extern "system" fn(HSGFPM, *const c_uchar, *const c_uchar, c_long, *mut c_int) -> c_long;
type FnGetMatchingScore =
    unsafe extern "system" fn(HSGFPM, *const c_uchar, *const c_uchar, *mut c_long) -> c_long;

/// Holds the loaded DLL module handle and resolved function pointers.
pub struct SgfpLib {
    _module: HMODULE,
    pub fn_create: FnCreate,
    pub fn_terminate: FnTerminate,
    pub fn_init: FnInit,
    pub fn_open_device: FnOpenDevice,
    pub fn_close_device: FnCloseDevice,
    pub fn_get_device_info: FnGetDeviceInfo,
    pub fn_get_image_ex: FnGetImageEx,
    pub fn_get_image_quality: FnGetImageQuality,
    pub fn_create_template: FnCreateTemplate,
    pub fn_get_max_template_size: FnGetMaxTemplateSize,
    pub fn_match_template: FnMatchTemplate,
    pub fn_get_matching_score: FnGetMatchingScore,
}

impl SgfpLib {
    /// Load the SecuGen DLL using a hardened search path.
    /// Adds only the vendor's own directory; system DLLs come from System32.
    /// Dependent DLLs (sgfpamx.dll, sgfdu05m.dll, sgwsqlib.dll) resolve via
    /// the LOAD_LIBRARY_SEARCH_USER_DIRS list and System32 — never PATH or CWD.
    pub fn load(dll_path: &Path) -> Result<Self, String> {
        ensure_safe_dll_search();

        if let Some(parent) = dll_path.parent() {
            let wide_parent = to_wide(&parent.to_string_lossy());
            let cookie = unsafe { AddDllDirectory(wide_parent.as_ptr()) };
            if cookie.is_null() {
                let err = unsafe { GetLastError() };
                return Err(format!(
                    "AddDllDirectory failed for {} (error {})",
                    parent.display(),
                    err
                ));
            }
        }

        let wide_path = to_wide(&dll_path.to_string_lossy());
        let module = unsafe {
            LoadLibraryExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
        };
        if module.is_null() {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "Failed to load {} (LoadLibraryExW error {})",
                dll_path.display(),
                err
            ));
        }

        Ok(Self {
            _module: module,
            fn_create: get_proc(module, "SGFPM_Create")?,
            fn_terminate: get_proc(module, "SGFPM_Terminate")?,
            fn_init: get_proc(module, "SGFPM_Init")?,
            fn_open_device: get_proc(module, "SGFPM_OpenDevice")?,
            fn_close_device: get_proc(module, "SGFPM_CloseDevice")?,
            fn_get_device_info: get_proc(module, "SGFPM_GetDeviceInfo")?,
            fn_get_image_ex: get_proc(module, "SGFPM_GetImageEx")?,
            fn_get_image_quality: get_proc(module, "SGFPM_GetImageQuality")?,
            fn_create_template: get_proc(module, "SGFPM_CreateTemplate")?,
            fn_get_max_template_size: get_proc(module, "SGFPM_GetMaxTemplateSize")?,
            fn_match_template: get_proc(module, "SGFPM_MatchTemplate")?,
            fn_get_matching_score: get_proc(module, "SGFPM_GetMatchingScore")?,
        })
    }

    // --- Safe wrappers ---

    pub fn create_handle(&self) -> Result<HSGFPM, c_long> {
        let mut handle: HSGFPM = std::ptr::null_mut();
        let ret = unsafe { (self.fn_create)(&mut handle) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(handle)
    }

    pub fn init_device(&self, handle: HSGFPM, dev_name: c_long) -> Result<(), c_long> {
        let ret = unsafe { (self.fn_init)(handle, dev_name) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn open_device(&self, handle: HSGFPM, dev_id: c_int) -> Result<(), c_long> {
        let ret = unsafe { (self.fn_open_device)(handle, dev_id) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn close_device(&self, handle: HSGFPM) -> Result<(), c_long> {
        let ret = unsafe { (self.fn_close_device)(handle) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn terminate(&self, handle: HSGFPM) -> Result<(), c_long> {
        let ret = unsafe { (self.fn_terminate)(handle) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn get_device_info(&self, handle: HSGFPM) -> Result<SGDeviceInfoParam, c_long> {
        let mut info = SGDeviceInfoParam::default();
        let ret = unsafe { (self.fn_get_device_info)(handle, &mut info) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(info)
    }

    pub fn get_image_ex(
        &self,
        handle: HSGFPM,
        buffer: &mut [u8],
        timeout: c_long,
        quality: c_long,
    ) -> Result<(), c_long> {
        let ret = unsafe {
            (self.fn_get_image_ex)(
                handle,
                buffer.as_mut_ptr(),
                timeout,
                std::ptr::null_mut(),
                quality,
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn get_image_quality(
        &self,
        handle: HSGFPM,
        width: c_long,
        height: c_long,
        image: &[u8],
    ) -> Result<c_long, c_long> {
        let mut quality: c_long = 0;
        let ret = unsafe {
            (self.fn_get_image_quality)(handle, width, height, image.as_ptr(), &mut quality)
        };
        if ret != 0 {
            return Err(ret);
        }
        Ok(quality)
    }

    pub fn get_max_template_size(&self, handle: HSGFPM) -> Result<c_long, c_long> {
        let mut size: c_long = 0;
        let ret = unsafe { (self.fn_get_max_template_size)(handle, &mut size) };
        if ret != 0 {
            return Err(ret);
        }
        Ok(size)
    }

    pub fn create_template(
        &self,
        handle: HSGFPM,
        finger_info: &SGFingerInfo,
        image: &[u8],
        template_buf: &mut [u8],
    ) -> Result<(), c_long> {
        let ret = unsafe {
            (self.fn_create_template)(
                handle,
                finger_info as *const SGFingerInfo,
                image.as_ptr(),
                template_buf.as_mut_ptr(),
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn match_template(
        &self,
        handle: HSGFPM,
        template1: &[u8],
        template2: &[u8],
        sec_level: c_long,
    ) -> Result<bool, c_long> {
        let mut matched: c_int = 0;
        let ret = unsafe {
            (self.fn_match_template)(
                handle,
                template1.as_ptr(),
                template2.as_ptr(),
                sec_level,
                &mut matched,
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        Ok(matched != 0)
    }

    pub fn get_matching_score(
        &self,
        handle: HSGFPM,
        template1: &[u8],
        template2: &[u8],
    ) -> Result<c_long, c_long> {
        let mut score: c_long = 0;
        let ret = unsafe {
            (self.fn_get_matching_score)(handle, template1.as_ptr(), template2.as_ptr(), &mut score)
        };
        if ret != 0 {
            return Err(ret);
        }
        Ok(score)
    }
}
