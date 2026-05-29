//! Windows Biometric Framework (WBF) vendor implementation.
//! Works with any WBF-enrolled fingerprint scanner (Goodix, Synaptics, Elan, etc.)
//! Uses 64-bit native WinBio API — no bridge process needed.
//!
//! Limitations vs direct vendor SDKs:
//! - MOC (Match-on-Chip) sensors may not return raw image data
//! - Enroll/verify/identify use Windows biometric database, not app-managed templates
//! - Template data returned is the raw BIR (Biometric Information Record) from WBF

use std::ffi::c_void;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

// ─── WBF Constants ───────────────────────────────────────────────────────────

const WINBIO_TYPE_FINGERPRINT: u32 = 0x0000_0008;
const WINBIO_POOL_SYSTEM: u32 = 1;
const WINBIO_FLAG_RAW: u32 = 0x0000_0001;
const WINBIO_FLAG_DEFAULT: u32 = 0x0000_0000;

// BIR purpose flags
const WINBIO_NO_PURPOSE_AVAILABLE: u8 = 0x00;
const WINBIO_PURPOSE_VERIFY: u8 = 0x01;
const WINBIO_PURPOSE_AUDIT: u8 = 0x80;

// BIR data flags
const WINBIO_DATA_FLAG_RAW: u8 = 0x01;
const WINBIO_DATA_FLAG_INTERMEDIATE: u8 = 0x02;
const WINBIO_DATA_FLAG_PROCESSED: u8 = 0x04;

// HRESULT success
const S_OK: i32 = 0;

// Common WinBio errors
const WINBIO_E_ENROLLMENT_IN_PROGRESS: i32 = 0x80098001_u32 as i32;
const WINBIO_E_BAD_CAPTURE: i32 = 0x80098004_u32 as i32;
const WINBIO_E_NO_MATCH: i32 = 0x80098005_u32 as i32;
const WINBIO_E_UNSUPPORTED_PURPOSE: i32 = 0x80098009_u32 as i32;
const WINBIO_I_MORE_DATA: i32 = 0x00090001;

// ─── WBF Types ───────────────────────────────────────────────────────────────

type HRESULT = i32;

#[repr(C)]
struct WinbioVersion {
    major: u32,
    minor: u32,
}

#[repr(C)]
struct WinbioUnitSchema {
    unit_id: u32,
    pool_type: u32,
    biometric_factor: u32,
    sensor_sub_type: u32,
    capabilities: u32,
    device_instance_id: [u16; 256],
    description: [u16; 256],
    manufacturer: [u16; 256],
    model: [u16; 256],
    serial_number: [u16; 256],
    firmware_version: WinbioVersion,
}

#[repr(C)]
struct WinbioRegisteredFormat {
    owner: u16,
    type_: u16,
}

#[repr(C)]
struct WinbioBirHeader {
    valid_fields: u16,
    header_version: u8,
    patron_header_version: u8,
    data_flags: u8,
    _pad1: [u8; 3],
    biometric_type: u32,
    subtype: u8,
    purpose: u8,
    quality: i8,
    _pad2: u8,
    _pad3: u32,
    creation_date: i64,
    validity_begin: i64,
    validity_end: i64,
    data_format: WinbioRegisteredFormat,
    product_id: WinbioRegisteredFormat,
}

#[repr(C)]
struct WinbioBirData {
    size: u32,
    offset: u32,
}

#[repr(C)]
struct WinbioBir {
    header: WinbioBirHeader,
    standard_data: WinbioBirData,
    vendor_data: WinbioBirData,
}

// ─── WBF FFI ─────────────────────────────────────────────────────────────────

#[link(name = "winbio")]
extern "system" {
    fn WinBioEnumBiometricUnits(
        factor: u32,
        unit_schema_array: *mut *mut WinbioUnitSchema,
        unit_count: *mut usize,
    ) -> HRESULT;

    fn WinBioOpenSession(
        factor: u32,
        pool_type: u32,
        flags: u32,
        unit_array: *const u32,
        unit_count: usize,
        database_id: *const c_void,
        session_handle: *mut usize,
    ) -> HRESULT;

    fn WinBioCaptureSample(
        session_handle: usize,
        purpose: u8,
        flags: u8,
        unit_id: *mut u32,
        sample: *mut *mut WinbioBir,
        sample_size: *mut usize,
        reject_detail: *mut u32,
    ) -> HRESULT;

    fn WinBioIdentify(
        session_handle: usize,
        unit_id: *mut u32,
        identity: *mut u8,     // WINBIO_IDENTITY (76 bytes)
        sub_factor: *mut u8,
        reject_detail: *mut u32,
    ) -> HRESULT;

    fn WinBioLocateSensor(
        session_handle: usize,
        unit_id: *mut u32,
    ) -> HRESULT;

    fn WinBioCloseSession(session_handle: usize) -> HRESULT;

    fn WinBioFree(address: *mut c_void) -> HRESULT;
}

// WINBIO_IDENTITY is 76 bytes: type (u32) + union of GUID(16), SID(68), etc.
const WINBIO_IDENTITY_SIZE: usize = 76;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

fn hresult_msg(hr: HRESULT) -> String {
    match hr {
        WINBIO_E_BAD_CAPTURE => "Bad capture (finger not placed correctly)".into(),
        WINBIO_E_NO_MATCH => "No match found".into(),
        WINBIO_E_ENROLLMENT_IN_PROGRESS => "Enrollment already in progress".into(),
        WINBIO_E_UNSUPPORTED_PURPOSE => "Unsupported capture purpose (sensor may not support raw capture)".into(),
        _ => format!("WinBio error 0x{:08X}", hr as u32),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ─── Capture helpers ─────────────────────────────────────────────────────────

/// Try WinBioCaptureSample with various purpose/flag combos.
/// Returns None if all strategies get ACCESS_DENIED (MOC sensor).
/// Returns Some(Ok/Err) if capture worked or had a sensor-level error.
fn try_capture_sample(session: usize) -> Option<Result<ScanResult, FingerprintError>> {
    let strategies: &[(u8, u8)] = &[
        (WINBIO_NO_PURPOSE_AVAILABLE, WINBIO_DATA_FLAG_RAW),
        (WINBIO_PURPOSE_AUDIT, WINBIO_DATA_FLAG_RAW),
        (WINBIO_NO_PURPOSE_AVAILABLE, WINBIO_DATA_FLAG_PROCESSED),
        (WINBIO_PURPOSE_VERIFY, WINBIO_DATA_FLAG_PROCESSED),
    ];

    let mut all_access_denied = true;

    for &(purpose, flags) in strategies {
        let mut unit_id: u32 = 0;
        let mut sample_ptr: *mut WinbioBir = std::ptr::null_mut();
        let mut sample_size: usize = 0;
        let mut reject_detail: u32 = 0;

        let hr = unsafe {
            WinBioCaptureSample(
                session,
                purpose,
                flags,
                &mut unit_id,
                &mut sample_ptr,
                &mut sample_size,
                &mut reject_detail,
            )
        };

        if hr == S_OK {
            let (data, quality) = extract_bir_data(sample_ptr, sample_size);
            return Some(Ok(ScanResult {
                image: data.clone(),
                quality,
                template: data,
                timestamp: now_ms(),
            }));
        }

        if !sample_ptr.is_null() {
            unsafe { WinBioFree(sample_ptr as *mut c_void); }
        }

        // 0x80070005 = E_ACCESSDENIED
        if hr as u32 != 0x80070005 {
            all_access_denied = false;
        }

        if hr == WINBIO_E_BAD_CAPTURE {
            return Some(Err(FingerprintError::SdkError(format!(
                "Bad capture (reject detail: {})",
                reject_detail
            ))));
        }
    }

    if all_access_denied {
        None // Signal caller to try MOC-specific APIs
    } else {
        Some(Err(FingerprintError::SdkError(
            "WinBioCaptureSample failed with all strategies".to_string(),
        )))
    }
}

fn extract_bir_data(sample_ptr: *mut WinbioBir, sample_size: usize) -> (Vec<u8>, u8) {
    if sample_ptr.is_null() || sample_size == 0 {
        return (vec![], 0);
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(sample_ptr as *const u8, sample_size)
    };
    let data = bytes.to_vec();

    let quality = if sample_size >= std::mem::size_of::<WinbioBir>() {
        let bir = unsafe { &*sample_ptr };
        let q = bir.header.quality;
        if q >= 0 { q as u8 } else { 0 }
    } else {
        0
    };

    unsafe { WinBioFree(sample_ptr as *mut c_void); }
    (data, quality)
}

// ─── Scanner Implementation ──────────────────────────────────────────────────

struct WbfState {
    session: usize,
    unit_id: u32,
}

pub struct WbfScanner {
    state: Mutex<Option<WbfState>>,
}

impl WbfScanner {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }
}

impl FingerprintScanner for WbfScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        // Enumerate biometric units
        let mut schema_ptr: *mut WinbioUnitSchema = std::ptr::null_mut();
        let mut count: usize = 0;

        let hr = unsafe {
            WinBioEnumBiometricUnits(WINBIO_TYPE_FINGERPRINT, &mut schema_ptr, &mut count)
        };

        if hr != S_OK || count == 0 {
            if !schema_ptr.is_null() {
                unsafe { WinBioFree(schema_ptr as *mut c_void); }
            }
            return Err(FingerprintError::DeviceNotFound);
        }

        // Read first fingerprint unit info
        let schema = unsafe { &*schema_ptr };
        let unit_id = schema.unit_id;
        let manufacturer = wide_to_string(&schema.manufacturer);
        let model = wide_to_string(&schema.model);
        let serial = wide_to_string(&schema.serial_number);
        let firmware = format!("{}.{}", schema.firmware_version.major, schema.firmware_version.minor);
        let description = wide_to_string(&schema.description);

        unsafe { WinBioFree(schema_ptr as *mut c_void); }

        // Open session targeting this unit
        let mut session: usize = 0;

        // Try session open strategies in order of capability
        let session_configs: &[(u32, *const u32, usize, &str)] = &[
            // RAW flag with specific unit
            (WINBIO_FLAG_RAW, &unit_id, 1, "raw+unit"),
            // DEFAULT with specific unit
            (WINBIO_FLAG_DEFAULT, &unit_id, 1, "default+unit"),
            // RAW flag, all units
            (WINBIO_FLAG_RAW, std::ptr::null(), 0, "raw+all"),
            // DEFAULT, all units
            (WINBIO_FLAG_DEFAULT, std::ptr::null(), 0, "default+all"),
        ];

        let mut hr = S_OK;
        for &(flags, unit_ptr, unit_count, _label) in session_configs {
            hr = unsafe {
                WinBioOpenSession(
                    WINBIO_TYPE_FINGERPRINT,
                    WINBIO_POOL_SYSTEM,
                    flags,
                    unit_ptr,
                    unit_count,
                    std::ptr::null(),
                    &mut session,
                )
            };
            if hr == S_OK {
                break;
            }
        }

        if hr != S_OK {
            return Err(FingerprintError::SdkError(format!(
                "WinBioOpenSession failed: {}",
                hresult_msg(hr)
            )));
        }

        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(WbfState { session, unit_id });

        // Use description as model if model is empty
        let display_model = if model.is_empty() { description } else { model };
        let display_vendor = if manufacturer.is_empty() {
            "Windows Biometric".into()
        } else {
            manufacturer
        };

        Ok(DeviceInfo {
            vendor: display_vendor,
            model: display_model,
            serial,
            firmware,
            image_width: 0,  // WBF doesn't expose raw sensor dimensions
            image_height: 0,
            dpi: 0,
        })
    }

    fn capture(&self, _timeout_ms: u32, _min_quality: u8) -> Result<ScanResult, FingerprintError> {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = guard.as_ref().ok_or(FingerprintError::NotInitialized)?;

        // WinBioIdentify: blocks until a finger is placed and matched
        let mut unit_id: u32 = 0;
        let mut identity = [0u8; WINBIO_IDENTITY_SIZE];
        let mut sub_factor: u8 = 0;
        let mut reject_detail: u32 = 0;

        let hr = unsafe {
            WinBioIdentify(
                state.session,
                &mut unit_id,
                identity.as_mut_ptr(),
                &mut sub_factor,
                &mut reject_detail,
            )
        };

        if hr == S_OK {
            return Ok(ScanResult {
                image: vec![], // MOC sensors don't expose raw images
                quality: 100,  // If identify succeeded, quality is good
                template: identity.to_vec(), // WINBIO_IDENTITY as "template"
                timestamp: now_ms(),
            });
        }

        if hr == WINBIO_E_NO_MATCH {
            return Err(FingerprintError::SdkError(
                "Finger not recognized. Enroll via Windows Hello first (Settings > Accounts > Sign-in options > Fingerprint).".to_string(),
            ));
        }

        if hr == WINBIO_E_BAD_CAPTURE {
            return Err(FingerprintError::SdkError(format!(
                "Bad capture — try again (reject detail: {})",
                reject_detail
            )));
        }

        Err(FingerprintError::SdkError(format!(
            "WinBioIdentify failed: {} (reject: {})",
            hresult_msg(hr),
            reject_detail
        )))
    }

    fn enroll(&self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        // WBF enrolls to Windows biometric database, not app-managed templates.
        // We capture multiple samples and return the best BIR as the "template".
        let count = if samples == 0 { 3 } else { samples };
        let mut best_data: Option<Vec<u8>> = None;
        let mut best_quality: i8 = -1;

        for _ in 0..count {
            let scan = self.capture(10_000, 0)?;
            let q = scan.quality as i8;
            if q > best_quality {
                best_quality = q;
                best_data = Some(scan.template);
            }
        }

        match best_data {
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

    fn verify(
        &self,
        _user_id: &str,
        _template: &Template,
    ) -> Result<MatchResult, FingerprintError> {
        // WBF verify works against Windows biometric DB, not arbitrary templates.
        // For now, capture a sample and return it — cross-template matching
        // would require a software matcher.
        Err(FingerprintError::SdkError(
            "WBF verify requires Windows biometric enrollment. Use a vendor-specific SDK for template-based matching.".to_string(),
        ))
    }

    fn identify(&self, _templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        Err(FingerprintError::SdkError(
            "WBF identify requires Windows biometric enrollment. Use a vendor-specific SDK for template-based matching.".to_string(),
        ))
    }

    fn get_quality(&self, _image: &[u8]) -> Result<u8, FingerprintError> {
        Err(FingerprintError::SdkError(
            "WBF does not expose a standalone quality scoring API.".to_string(),
        ))
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = guard.take() {
            unsafe { WinBioCloseSession(state.session); }
        }
        Ok(())
    }
}

impl Drop for WbfScanner {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
