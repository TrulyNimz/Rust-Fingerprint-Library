use super::errors::FingerprintError;
use super::types::{DeviceInfo, MatchResult, ScanResult, Template};

pub trait FingerprintScanner: Send + Sync {
    fn init(&self) -> Result<DeviceInfo, FingerprintError>;
    fn capture(&self, timeout_ms: u32, min_quality: u8) -> Result<ScanResult, FingerprintError>;
    fn enroll(&self, user_id: &str, samples: u8) -> Result<Template, FingerprintError>;
    fn verify(&self, user_id: &str, template: &Template) -> Result<MatchResult, FingerprintError>;
    fn identify(&self, templates: &[Template]) -> Result<MatchResult, FingerprintError>;
    fn get_quality(&self, image: &[u8]) -> Result<u8, FingerprintError>;
    fn disconnect(&self) -> Result<(), FingerprintError>;
}
