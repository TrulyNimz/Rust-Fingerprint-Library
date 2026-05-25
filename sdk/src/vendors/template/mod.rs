// Vendor template — copy this module to implement a new fingerprint scanner vendor.
//
// Steps:
// 1. Copy this directory to vendors/<your_vendor>/
// 2. Add an ffi.rs with your SDK's FFI bindings
// 3. Implement FingerprintScanner for your scanner struct
// 4. Register the vendor in vendors/mod.rs

#![allow(unused)]

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

pub struct TemplateScanner;

impl TemplateScanner {
    pub fn new() -> Self {
        Self
    }
}

impl FingerprintScanner for TemplateScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        todo!("Implement device initialization")
    }

    fn capture(&self, _timeout_ms: u32, _min_quality: u8) -> Result<ScanResult, FingerprintError> {
        todo!("Implement fingerprint capture")
    }

    fn enroll(&self, _user_id: &str, _samples: u8) -> Result<Template, FingerprintError> {
        todo!("Implement user enrollment")
    }

    fn verify(
        &self,
        _user_id: &str,
        _template: &Template,
    ) -> Result<MatchResult, FingerprintError> {
        todo!("Implement 1:1 verification")
    }

    fn identify(&self, _templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        todo!("Implement 1:N identification")
    }

    fn get_quality(&self, _image: &[u8]) -> Result<u8, FingerprintError> {
        todo!("Implement quality scoring")
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        todo!("Implement device disconnect")
    }
}
