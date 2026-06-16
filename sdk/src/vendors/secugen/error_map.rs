//! Maps SecuGen SGFPLIB return codes to the public `FingerprintError`.
//! Shared by the Windows bridge wrapper and the Linux/macOS native client.

use std::os::raw::c_long;

use crate::fp_core::errors::FingerprintError;

use super::ffi_types::{
    SGFDX_ERROR_DEVICE_NOT_FOUND, SGFDX_ERROR_DLLLOAD_FAILED_DRV, SGFDX_ERROR_TIME_OUT,
};

/// Convert a non-zero SGFPLIB error code (returned by SGFPM_* calls) into a
/// `FingerprintError`. Callers must check for success (code == 0) before
/// calling this — code 0 is not handled here and would fall through to the
/// catch-all `SdkError` arm.
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
