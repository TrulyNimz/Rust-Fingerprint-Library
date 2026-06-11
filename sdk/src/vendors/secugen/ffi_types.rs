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
