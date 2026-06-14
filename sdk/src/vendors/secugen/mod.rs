pub mod constants;
mod error_map;
mod ffi_types;
mod library_path;

#[cfg(windows)]
mod bridge;

use std::sync::Mutex;

use crate::fp_core::errors::FingerprintError;
use crate::fp_core::traits::FingerprintScanner;
use crate::fp_core::types::{DeviceInfo, MatchResult, ScanResult, Template};

#[cfg(windows)]
use self::bridge::BridgeBackend;

pub struct SecuGenScanner {
    backend: Mutex<Option<Backend>>,
}

enum Backend {
    #[cfg(windows)]
    Bridge(BridgeBackend),
}

impl SecuGenScanner {
    pub fn new() -> Self {
        Self {
            backend: Mutex::new(None),
        }
    }

    fn with_backend<F, T>(&self, f: F) -> Result<T, FingerprintError>
    where
        F: FnOnce(&mut Backend) -> Result<T, FingerprintError>,
    {
        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = guard.as_mut().ok_or(FingerprintError::NotInitialized)?;
        f(backend)
    }
}

impl FingerprintScanner for SecuGenScanner {
    fn init(&self) -> Result<DeviceInfo, FingerprintError> {
        #[cfg(windows)]
        {
            let mut backend = BridgeBackend::spawn()?;
            let info = backend.init()?;
            *self.backend.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Backend::Bridge(backend));
            Ok(info)
        }
        #[cfg(not(windows))]
        {
            Err(FingerprintError::SdkError(
                "SecuGen native backend not yet wired up (lands in Task 6)".to_string(),
            ))
        }
    }

    fn capture(&self, timeout_ms: u32, min_quality: u8) -> Result<ScanResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.capture(timeout_ms, min_quality),
        })
    }

    fn enroll(&self, user_id: &str, samples: u8) -> Result<Template, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.enroll(user_id, samples),
        })
    }

    fn verify(&self, user_id: &str, template: &Template) -> Result<MatchResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.verify(user_id, template),
        })
    }

    fn identify(&self, templates: &[Template]) -> Result<MatchResult, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.identify(templates),
        })
    }

    fn get_quality(&self, image: &[u8]) -> Result<u8, FingerprintError> {
        self.with_backend(|b| match b {
            #[cfg(windows)]
            Backend::Bridge(br) => br.get_quality(image),
        })
    }

    fn disconnect(&self) -> Result<(), FingerprintError> {
        let mut guard = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(backend) = guard.take() {
            match backend {
                #[cfg(windows)]
                Backend::Bridge(br) => br.shutdown(),
            }
        }
        Ok(())
    }
}

impl Drop for SecuGenScanner {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
