use thiserror::Error;

#[derive(Error, Debug)]
pub enum FingerprintError {
    #[error("Device not found")]
    DeviceNotFound,

    #[error("Capture timed out after {0}ms")]
    CaptureTimeout(u32),

    #[error("Image quality too low: {got} (minimum: {min})")]
    LowQuality { got: u8, min: u8 },

    #[error("Match failed")]
    MatchFailed,

    #[error("SDK error: {0}")]
    SdkError(String),

    #[error("Unsupported vendor: {0}")]
    UnsupportedVendor(String),

    #[error("Scanner not initialized")]
    NotInitialized,
}

impl FingerprintError {
    pub fn code(&self) -> &'static str {
        match self {
            FingerprintError::DeviceNotFound => "DEVICE_NOT_FOUND",
            FingerprintError::CaptureTimeout(_) => "CAPTURE_TIMEOUT",
            FingerprintError::LowQuality { .. } => "LOW_QUALITY",
            FingerprintError::MatchFailed => "MATCH_FAILED",
            FingerprintError::SdkError(_) => "SDK_ERROR",
            FingerprintError::UnsupportedVendor(_) => "UNSUPPORTED_VENDOR",
            FingerprintError::NotInitialized => "NOT_INITIALIZED",
        }
    }
}

impl From<FingerprintError> for napi::Error {
    fn from(err: FingerprintError) -> Self {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("[{}] {}", err.code(), err),
        )
    }
}
