pub mod secugen;
pub mod template;
#[cfg(windows)]
pub mod wbf;
#[cfg(windows)]
pub mod neurotec;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;

use self::secugen::SecuGenScanner;

pub fn get_scanner(vendor: Option<&str>) -> Result<Box<dyn FingerprintScanner>, FingerprintError> {
    match vendor.unwrap_or("auto") {
        "secugen" => Ok(Box::new(SecuGenScanner::new())),
        #[cfg(windows)]
        "wbf" | "windows" => Ok(Box::new(wbf::WbfScanner::new())),
        #[cfg(windows)]
        "neurotec" | "neurotechnology" => Ok(Box::new(neurotec::NeurotecScanner::new())),
        "auto" => {
            #[cfg(windows)]
            {
                // Windows: try WBF first (any biometric device), fall back to SecuGen.
                Ok(Box::new(wbf::WbfScanner::new()))
            }
            #[cfg(not(windows))]
            {
                // Linux / macOS: SecuGen is the only implemented vendor today.
                Ok(Box::new(SecuGenScanner::new()))
            }
        }
        other => Err(FingerprintError::UnsupportedVendor(other.to_string())),
    }
}
